"""Reusable librarian retrieval and brief-support logic."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, is_dataclass
from typing import Any, Dict, List, Optional

from src.config import get_runtime_config
from src.database.librarian.models import LibrarianDependencyStatus, ResearchEvidence
from src.database.librarian.query_builder import TelemetryProcessor
from src.state.cyber_state import CyberState
from src.state.models import IntelligenceBrief, RetrievalSourceTrace, RetrievalTrace


_DEFAULT_CLIENT = object()
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class LibrarianResearchService:
    """Database-backed retrieval helpers shared by librarian implementations."""

    def __init__(
        self,
        rag_orchestrator: Optional[Any] = None,
        *,
        osint_client: Any = _DEFAULT_CLIENT,
        cve_client: Any = _DEFAULT_CLIENT,
    ):
        cfg = get_runtime_config()
        self._rag_top_k = cfg.rag_kb_top_k
        self._findings_top_k = cfg.rag_findings_top_k
        self._min_docs = cfg.rag_min_docs
        self._min_score = cfg.rag_min_score
        self._telemetry_processor = TelemetryProcessor()
        self._rag = rag_orchestrator
        self._osint_client: Any | None = None if osint_client is _DEFAULT_CLIENT else osint_client
        self._cve_client: Any | None = None if cve_client is _DEFAULT_CLIENT else cve_client
        self._osint_client_explicit = osint_client is not _DEFAULT_CLIENT
        self._cve_client_explicit = cve_client is not _DEFAULT_CLIENT

    def _build_research_query(self, state: CyberState) -> str:
        """Build the compact telemetry query used by all retrieval stages."""

        return self._telemetry_processor.build_research_query(state)

    def _get_rag(self) -> Any:
        """Lazily initialize RAG so startup does not block on DB/embedding setup."""

        if self._rag is not None:
            return self._rag
        try:
            from src.database.rag.rag_engine import RAGOrchestrator

            self._rag = RAGOrchestrator()
        except Exception:
            self._rag = None
        return self._rag

    def _get_osint_client(self) -> Any:
        """Lazily initialize OSINT search only when the retrieval pipeline needs it."""

        if self._osint_client_explicit or self._osint_client is not None:
            return self._osint_client
        try:
            from src.database.librarian.osint_client import OSINTClient

            self._osint_client = OSINTClient()
        except Exception:
            self._osint_client = None
        return self._osint_client

    def _get_cve_client(self) -> Any:
        """Lazily initialize official CVE/KEV lookup only when version clues warrant it."""

        if self._cve_client_explicit or self._cve_client is not None:
            return self._cve_client
        try:
            from src.database.librarian.cve_client import CVEClient

            self._cve_client = CVEClient()
        except Exception:
            self._cve_client = None
        return self._cve_client

    async def _retrieve_from_kb(
        self,
        query: str,
        status: LibrarianDependencyStatus,
    ) -> List[Dict[str, Any]]:
        """Retrieve KB evidence while marking dependency and embedding health."""

        rag = self._get_rag()
        if rag is None:
            status.mark("kb", "unavailable")
            status.mark("embeddings", "unavailable")
            status.add_reason("kb_unavailable")
            return []

        embedding_client = getattr(getattr(rag, "retriever", None), "embedding_client", None)
        if embedding_client is None or not embedding_client.is_available():
            status.mark("embeddings", "degraded")
            status.add_reason("embedding_unavailable_using_lexical_fallback")
        else:
            status.mark("embeddings", "ready")

        try:
            result = await rag.retrieve(query=query, source="kb", top_k=self._rag_top_k)
            rows = result.get("kb_results", []) or []
            status.mark("kb", "ready" if rows else "empty")
            return rows
        except Exception:
            status.mark("kb", "unavailable")
            status.add_reason("kb_retrieval_failed")
            return []

    async def _retrieve_from_findings(
        self,
        query: str,
        status: LibrarianDependencyStatus,
    ) -> List[Dict[str, Any]]:
        """Retrieve historical findings so librarian can use prior workflow context."""

        rag = self._get_rag()
        if rag is None:
            status.mark("findings", "unavailable")
            status.add_reason("findings_unavailable")
            return []

        try:
            result = await rag.retrieve(query=query, source="findings", top_k=self._findings_top_k)
            rows = result.get("findings_results", []) or []
            status.mark("findings", "ready" if rows else "empty")
            return rows
        except Exception:
            status.mark("findings", "unavailable")
            status.add_reason("findings_retrieval_failed")
            return []

    async def _retrieve_cves(
        self,
        query: str,
        query_inputs: Dict[str, Any],
        status: LibrarianDependencyStatus,
        kb_results: List[Dict[str, Any]],
        findings_results: List[Dict[str, Any]],
    ) -> List[ResearchEvidence]:
        """Query NVD and KEV using discovered service/version clues."""

        client = self._get_cve_client()
        if client is None:
            status.mark("cve", "unavailable")
            status.add_reason("cve_client_unavailable")
            return []

        service_clues = []
        for service in query_inputs.get("services", []) or []:
            if not isinstance(service, dict):
                continue
            clue = " ".join(
                part
                for part in [
                    str(service.get("service_name") or "").strip(),
                    str(service.get("version") or "").strip(),
                    str(service.get("banner") or "").strip(),
                ]
                if part
            )
            if clue:
                service_clues.append(clue)

        known_cves = self._known_cves_for_lookup(query_inputs, kb_results, findings_results)

        try:
            results = await client.search(
                query=query,
                service_clues=service_clues,
                known_cves=known_cves,
                max_results=5,
            )
            status.mark("cve", "ready" if results else "empty")
            if results:
                self._clear_degraded_reason(status, "cve_lookup_failed")
            return results
        except Exception:
            status.mark("cve", "unavailable")
            status.add_reason("cve_lookup_failed")
            return []

    async def _retrieve_cves_from_osint(
        self,
        query: str,
        query_inputs: Dict[str, Any],
        status: LibrarianDependencyStatus,
        kb_results: List[Dict[str, Any]],
        findings_results: List[Dict[str, Any]],
        osint_results: List[Dict[str, Any]],
    ) -> List[ResearchEvidence]:
        """Retry official CVE lookup using explicit CVE IDs discovered in OSINT evidence."""

        osint_cves = self._extract_cves_from_evidence(osint_results)
        if not osint_cves:
            return []

        enriched_inputs = dict(query_inputs)
        enriched_inputs["cve_candidates"] = sorted(
            {
                *[
                    str(candidate).strip().upper()
                    for candidate in query_inputs.get("cve_candidates", []) or []
                    if CVE_RE.fullmatch(str(candidate or "").strip())
                ],
                *osint_cves,
            }
        )
        return await self._retrieve_cves(
            query,
            enriched_inputs,
            status,
            kb_results,
            findings_results,
        )

    def _known_cves_for_lookup(
        self,
        query_inputs: Dict[str, Any],
        kb_results: List[Dict[str, Any]],
        findings_results: List[Dict[str, Any]],
    ) -> List[str]:
        """Collect explicit CVE IDs from state, KB snippets, findings, and metadata."""

        found = {
            str(candidate).strip().upper()
            for candidate in query_inputs.get("cve_candidates", []) or []
            if CVE_RE.fullmatch(str(candidate or "").strip())
        }
        found.update(self._extract_cves_from_evidence(kb_results, findings_results))
        return sorted(found)

    def _extract_cves_from_evidence(self, *collections: List[Any]) -> set[str]:
        """Extract explicit CVE IDs from retrieved evidence without product-specific mappings."""

        found: set[str] = set()

        def visit(value: Any) -> None:
            if value is None:
                return
            if isinstance(value, str):
                found.update(match.upper() for match in CVE_RE.findall(value))
                return
            if isinstance(value, dict):
                for nested in value.values():
                    visit(nested)
                return
            if isinstance(value, list):
                for nested in value:
                    visit(nested)
                return
            if is_dataclass(value) or hasattr(value, "model_dump"):
                visit(self._normalize_item(value))

        for collection in collections:
            visit(collection)
        return found

    @staticmethod
    def _clear_degraded_reason(status: LibrarianDependencyStatus, reason: str) -> None:
        """Remove a transient degraded reason after a later retry succeeds."""

        status.degraded_reasons = [item for item in status.degraded_reasons if item != reason]

    async def _retrieve_osint(
        self,
        query: str,
        status: LibrarianDependencyStatus,
    ) -> List[Dict[str, Any]]:
        """Run targeted OSINT search when internal/CVE evidence is insufficient."""

        client = self._get_osint_client()
        if client is None:
            status.mark("osint", "unavailable")
            status.add_reason("osint_client_unavailable")
            return []
        if hasattr(client, "is_configured") and not client.is_configured():
            status.mark("osint", "unavailable")
            status.add_reason("osint_not_configured")
            return []

        try:
            results = await client.search(query)
            status.mark("osint", "ready" if results else "empty")
            return results
        except Exception:
            status.mark("osint", "unavailable")
            status.add_reason("osint_lookup_failed")
            return []

    def _should_lookup_cves(
        self,
        query: str,
        query_inputs: Dict[str, Any],
        kb_results: List[Dict[str, Any]],
        findings_results: List[Dict[str, Any]],
    ) -> bool:
        """Decide whether official CVE lookup is worth the external request."""

        intent_text = " ".join(
            str(part or "")
            for part in (
                query,
                query_inputs.get("specific_goal"),
                query_inputs.get("mission_goal"),
            )
        )
        if self._query_needs_exploit_guidance(intent_text):
            return True
        if self._has_strong_internal_evidence(kb_results, findings_results):
            return False
        if query_inputs.get("cve_candidates"):
            return True
        for service in query_inputs.get("services", []) or []:
            if not isinstance(service, dict):
                continue
            if service.get("version") or service.get("banner"):
                return True
        return False

    def _should_lookup_osint(
        self,
        query: str,
        kb_results: List[Dict[str, Any]],
        findings_results: List[Dict[str, Any]],
        cve_results: List[ResearchEvidence],
    ) -> bool:
        """Decide whether OSINT is needed after internal and CVE retrieval."""

        if self._query_needs_exploit_guidance(query):
            return True
        if self._has_strong_internal_evidence(kb_results, findings_results):
            return False
        if cve_results and self._best_score(cve_results) >= 0.72:
            return False
        return True

    @staticmethod
    def _query_needs_exploit_guidance(query: str) -> bool:
        """Detect supervisor goals that need exploit/tooling context beyond CVE facts."""

        text = str(query or "").lower()
        return any(
            token in text
            for token in (
                "alternate exploit",
                "alternative exploit",
                "attack approach",
                "attack path",
                "exploit failed",
                "exploit path",
                "exploit guidance",
                "exploit module",
                "how to exploit",
                "exploit it",
                "find alternatives",
                "failure recovery",
                "metasploit",
                "module",
                "next striker action",
                "options",
                "payload",
                "poc",
                "prepare striker",
                "proof of concept",
                "procedure",
                "research exploit",
                "tool usage",
                "tooling",
                "steps",
                "validate exploit",
                "validate exploitability",
                "why exploit failed",
                "working exploit",
            )
        )

    def _has_strong_internal_evidence(
        self,
        kb_results: List[Dict[str, Any]],
        findings_results: List[Dict[str, Any]],
    ) -> bool:
        """Treat internal evidence as strong only when enough high-scoring hits exist."""

        combined = list(kb_results or []) + list(findings_results or [])
        if len(combined) < self._min_docs:
            return False
        return self._best_score(combined) >= self._min_score

    def _best_score(self, results: List[Any]) -> float:
        """Return the highest score/similarity from mixed dict/dataclass evidence."""

        scores: List[float] = []
        for result in results or []:
            item = self._normalize_item(result)
            value = item.get("score")
            if value is None:
                value = item.get("similarity")
            try:
                if value is not None:
                    scores.append(float(value))
            except (TypeError, ValueError):
                continue
        return max(scores) if scores else 0.0

    def _fallback_brief(
        self,
        query: str,
        kb_results: List[Dict[str, Any]],
        findings_results: List[Dict[str, Any]],
        cve_results: List[ResearchEvidence],
        osint_results: List[Dict[str, Any]],
        status: LibrarianDependencyStatus,
    ) -> IntelligenceBrief:
        """Build a structured brief when the LLM is unavailable or synthesis fails."""

        source_types = self._source_types(kb_results, findings_results, cve_results, osint_results)
        citations = self._citations_from_results(kb_results, findings_results, cve_results, osint_results)
        technical_params = self._technical_params_from_results(findings_results, cve_results)
        confidence = min(
            0.88,
            max(
                self._best_score(kb_results + findings_results),
                self._best_score(cve_results),
                0.25 if citations else 0.0,
            ),
        )

        evidence_summaries = []
        if kb_results:
            evidence_summaries.append(f"{len(kb_results)} KB matches")
        if findings_results:
            evidence_summaries.append(f"{len(findings_results)} historical findings")
        if cve_results:
            evidence_summaries.append(f"{len(cve_results)} CVE/KEV references")
        if osint_results:
            evidence_summaries.append(f"{len(osint_results)} OSINT references")
        summary_bits = ", ".join(evidence_summaries) if evidence_summaries else "no supporting evidence"

        payload = {
            "summary": f"Fallback intelligence brief for: {query}. Available evidence: {summary_bits}.",
            "technical_params": technical_params,
            "is_osint_derived": bool(osint_results),
            "confidence": round(confidence, 4),
            "citations": citations,
            "conflicting_sources": None,
            "source_types": source_types,
            "source_status": dict(status.statuses),
            "degraded_reasons": list(status.degraded_reasons),
        }
        self._apply_confidence_guard(payload)
        return IntelligenceBrief.model_validate(payload)

    def _technical_params_from_results(
        self,
        findings_results: List[Dict[str, Any]],
        cve_results: List[ResearchEvidence],
    ) -> Dict[str, Any]:
        """Extract actionable parameters from retrieved findings and CVE evidence."""

        params: Dict[str, Any] = {}
        for evidence in cve_results:
            metadata = evidence.metadata or {}
            cve = str(metadata.get("cve") or evidence.identifier or "").strip()
            if cve and "cve" not in params:
                params["cve"] = cve
            if metadata.get("severity") and "severity" not in params:
                params["severity"] = metadata.get("severity")
        for finding in findings_results:
            if not isinstance(finding, dict):
                continue
            data = finding.get("data", {}) or {}
            if not params.get("exploit_module"):
                for key in ("exploit_module", "msf_module", "module"):
                    value = data.get(key)
                    if value:
                        params["exploit_module"] = value
                        break
        return params

    def _source_types(
        self,
        kb_results: List[Dict[str, Any]],
        findings_results: List[Dict[str, Any]],
        cve_results: List[ResearchEvidence],
        osint_results: List[Dict[str, Any]],
    ) -> List[str]:
        """List source classes that materially contributed evidence to the brief."""

        source_types: List[str] = []
        if kb_results:
            source_types.append("kb")
        if findings_results:
            source_types.append("findings")
        if cve_results:
            source_types.append("cve")
        if osint_results:
            source_types.append("osint")
        return source_types

    def _citations_from_results(
        self,
        kb_results: List[Dict[str, Any]],
        findings_results: List[Dict[str, Any]],
        cve_results: List[ResearchEvidence],
        osint_results: List[Dict[str, Any]],
    ) -> List[str]:
        """Create compact citation strings from raw retrieval results."""

        citations: List[str] = []
        for item in kb_results[:3]:
            doc = str(item.get("doc_name") or "").strip()
            if doc:
                citations.append(f"kb:{doc}")
        for item in findings_results[:3]:
            title = str(item.get("title") or "").strip()
            if title:
                citations.append(f"finding:{title}")
        for evidence in cve_results[:3]:
            reference = str(evidence.reference or "").strip()
            if reference:
                citations.append(f"cve:{reference}")
        for item in osint_results[:3]:
            reference = str(item.get("url") or item.get("reference") or "").strip()
            if reference:
                citations.append(f"osint:{reference}")
        return citations

    def _finding_from_brief(self, brief: IntelligenceBrief) -> Dict[str, Any]:
        """Convert a brief into the flat CyberState intelligence finding shape."""

        cve = str(brief.technical_params.get("cve") or "").strip() or None
        return {
            "source": "librarian",
            "cve": cve,
            "description": brief.summary,
            "exploit_available": bool(brief.technical_params.get("exploit_module")),
            "technical_params": brief.technical_params,
            "citations": brief.citations,
            "confidence": brief.confidence,
            "is_osint_derived": brief.is_osint_derived,
            "conflicting_sources": brief.conflicting_sources or [],
            "source_types": brief.source_types,
            "source_status": brief.source_status,
            "degraded_reasons": brief.degraded_reasons,
        }

    def _build_retrieval_trace(
        self,
        kb_results: List[Dict[str, Any]],
        findings_results: List[Dict[str, Any]],
        cve_results: List[ResearchEvidence],
        osint_results: List[Dict[str, Any]],
        status: LibrarianDependencyStatus,
    ) -> RetrievalTrace:
        """Build the structured audit trace stored in the librarian agent log."""

        return RetrievalTrace(
            kb=self._source_trace("kb", kb_results, status, ("doc_name", "source", "path")),
            findings=self._source_trace("findings", findings_results, status, ("title", "identifier", "finding_type")),
            cve=self._source_trace("cve", cve_results, status, ("metadata.cve", "identifier", "reference")),
            osint=self._source_trace("osint", osint_results, status, ("url", "reference", "title")),
            degraded_reasons=list(status.degraded_reasons),
        )

    @staticmethod
    def _trace_from_cached_brief(brief: IntelligenceBrief) -> RetrievalTrace:
        """Reconstruct a minimal trace when a cached brief avoids live retrieval."""

        source_types = set(brief.source_types or [])
        statuses = dict(brief.source_status or {})
        traces = {
            source: RetrievalSourceTrace(status=statuses.get(source, "cached" if source in source_types else "unknown"))
            for source in ("kb", "findings", "cve", "osint")
        }
        return RetrievalTrace(
            **traces,
            degraded_reasons=list(brief.degraded_reasons or []),
        )

    def _source_trace(
        self,
        source: str,
        items: List[Any],
        status: LibrarianDependencyStatus,
        reference_keys: tuple[str, ...],
    ) -> RetrievalSourceTrace:
        """Summarize one retrieval source for audit/debug visibility."""

        return RetrievalSourceTrace(
            status=status.statuses.get(source, "unknown"),
            count=len(items or []),
            references=self._compact_references(items, reference_keys),
        )

    def _compact_references(self, items: List[Any], keys: tuple[str, ...], *, limit: int = 3) -> List[str]:
        """Collect a few human-readable references from retrieval rows."""

        references: List[str] = []
        for item in items or []:
            value = self._first_reference_value(self._normalize_item(item), keys)
            if value:
                references.append(value)
            if len(references) >= limit:
                break
        return references

    @staticmethod
    def _first_reference_value(item: Dict[str, Any], keys: tuple[str, ...]) -> str:
        """Return the first populated field from a normalized retrieval item."""

        for key in keys:
            if "." in key:
                parent, child = key.split(".", 1)
                nested = item.get(parent)
                value = nested.get(child) if isinstance(nested, dict) else None
            else:
                value = item.get(key)
            text = str(value or "").strip()
            if text:
                return text
        return ""

    @staticmethod
    def _apply_confidence_guard(payload: Dict[str, Any]) -> None:
        """Cap unsupported LLM confidence when retrieval found no evidence."""

        source_types = list(payload.get("source_types") or [])
        if source_types:
            return

        try:
            confidence = float(payload.get("confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0

        payload["confidence"] = min(confidence, 0.35)
        reasons = list(payload.get("degraded_reasons") or [])
        if "no_supporting_evidence_confidence_capped" not in reasons:
            reasons.append("no_supporting_evidence_confidence_capped")
        payload["degraded_reasons"] = reasons

    def _cache_key(self, query: str) -> str:
        """Generate a stable research-cache key from the final query string."""

        return f"research_{hashlib.sha1(query.encode()).hexdigest()[:10]}"

    @staticmethod
    def _normalize_citations(raw: Any) -> List[str]:
        """Normalize LLM citation output into simple printable strings."""

        citations: List[str] = []
        for item in list(raw or []):
            if isinstance(item, str):
                if item.strip():
                    citations.append(item.strip())
            elif isinstance(item, dict):
                source = str(item.get("source") or "").strip()
                reference = str(item.get("reference") or item.get("url") or "").strip()
                if source and reference:
                    citations.append(f"{source}:{reference}")
                elif reference:
                    citations.append(reference)
        return citations

    @staticmethod
    def _normalize_item(item: Any) -> Dict[str, Any]:
        """Convert dicts, dataclasses, and Pydantic models to plain dicts."""

        if isinstance(item, dict):
            return dict(item)
        if is_dataclass(item):
            return asdict(item)
        if hasattr(item, "model_dump"):
            return item.model_dump()
        return {}

