from __future__ import annotations

import re
from typing import Any, Dict, List, Sequence

import httpx

from src.database.librarian.models import ResearchEvidence

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class CVEClient:
    def __init__(self, timeout: float = 20.0):
        """Create the official CVE/KEV client without doing network work yet."""

        self._timeout = timeout
        self._kev_cache: Dict[str, Dict[str, Any]] | None = None

    async def search(
        self,
        *,
        query: str,
        service_clues: Sequence[str] | None = None,
        known_cves: Sequence[str] | None = None,
        max_results: int = 5,
    ) -> List[ResearchEvidence]:
        """Search official NVD data and enrich matches with CISA KEV metadata."""

        cve_ids = self._extract_cve_ids(query, service_clues or [], known_cves or [])
        # KEV is enrichment. If CISA is unavailable, continue with NVD-only evidence.
        try:
            kev_entries = await self._load_kev_catalog()
        except Exception:
            kev_entries = {}

        if cve_ids:
            evidences = await self._fetch_by_cve_ids(cve_ids[:max_results], kev_entries)
        else:
            evidences = await self._fetch_by_keywords(
                self._keyword_queries(query, service_clues or []),
                max_results=max_results,
                kev_entries=kev_entries,
            )

        return evidences[:max_results]

    def _extract_cve_ids(
        self,
        query: str,
        service_clues: Sequence[str],
        known_cves: Sequence[str],
    ) -> List[str]:
        """Extract explicit CVE IDs from query text, services, and cached hints."""

        found = {match.upper() for match in CVE_RE.findall(str(query or ""))}
        for clue in service_clues:
            found.update(match.upper() for match in CVE_RE.findall(str(clue or "")))
        for cve in known_cves:
            if CVE_RE.fullmatch(str(cve or "").strip()):
                found.add(str(cve).strip().upper())
        return sorted(found)

    def _keyword_queries(self, query: str, service_clues: Sequence[str]) -> List[str]:
        """Build broad-to-specific NVD keyword queries from service/version clues."""

        queries: List[str] = []

        if service_clues:
            combined = " ".join(str(item).strip() for item in service_clues if str(item).strip())
            if combined:
                queries.append(combined[:160])
            for clue in service_clues:
                queries.extend(self._version_window_queries(str(clue or "")))

        cleaned_query = str(query or "").strip()
        if cleaned_query:
            queries.append(cleaned_query[:160])
            queries.extend(self._version_window_queries(cleaned_query))

        deduped: List[str] = []
        seen = set()
        for item in queries:
            # NVD keyword search is sensitive to repeated noisy variants, so dedupe aggressively.
            normalized = " ".join(str(item or "").split()).strip()
            key = normalized.lower()
            if normalized and key not in seen:
                deduped.append(normalized)
                seen.add(key)
        return deduped

    def _version_window_queries(self, text: str) -> List[str]:
        """Extract compact product/version windows such as 'vsftpd 2.3.4'."""

        tokens = re.findall(r"[A-Za-z][A-Za-z0-9_.+-]*|\d+(?:\.\d+)+[A-Za-z0-9_.+-]*", text)
        queries: List[str] = []
        for index, token in enumerate(tokens):
            if not re.search(r"\d+\.\d+", token):
                continue
            start = max(0, index - 2)
            prefix_tokens = [
                candidate
                for candidate in tokens[start:index]
                if re.search(r"[A-Za-z]", candidate)
            ]
            if prefix_tokens:
                queries.append(" ".join([*prefix_tokens, token]))
            if index > 0:
                queries.append(" ".join([tokens[index - 1], token]))
        return queries

    async def _fetch_by_cve_ids(
        self,
        cve_ids: Sequence[str],
        kev_entries: Dict[str, Dict[str, Any]],
    ) -> List[ResearchEvidence]:
        """Fetch exact CVE records from NVD when IDs are already known."""

        evidences: List[ResearchEvidence] = []
        async with httpx.AsyncClient(follow_redirects=True, timeout=self._timeout) as client:
            for cve_id in cve_ids:
                response = await client.get(NVD_CVE_API, params={"cveId": cve_id})
                response.raise_for_status()
                payload = response.json()
                for vuln in payload.get("vulnerabilities", []) or []:
                    evidence = self._normalize_vulnerability(vuln, kev_entries)
                    if evidence is not None:
                        evidences.append(evidence)
        return evidences

    async def _fetch_by_keyword(
        self,
        keyword: str,
        *,
        max_results: int,
        kev_entries: Dict[str, Dict[str, Any]],
    ) -> List[ResearchEvidence]:
        """Fetch NVD records using one keywordSearch query."""

        if not keyword:
            return []
        async with httpx.AsyncClient(follow_redirects=True, timeout=self._timeout) as client:
            response = await client.get(
                NVD_CVE_API,
                params={"keywordSearch": keyword, "resultsPerPage": max(1, min(max_results, 10))},
            )
            response.raise_for_status()
            payload = response.json()

        evidences: List[ResearchEvidence] = []
        for vuln in payload.get("vulnerabilities", []) or []:
            evidence = self._normalize_vulnerability(vuln, kev_entries)
            if evidence is not None:
                evidences.append(evidence)
        return evidences

    async def _fetch_by_keywords(
        self,
        keywords: Sequence[str],
        *,
        max_results: int,
        kev_entries: Dict[str, Dict[str, Any]],
    ) -> List[ResearchEvidence]:
        """Try keyword variants until enough unique CVE evidence is found."""

        evidences_by_id: Dict[str, ResearchEvidence] = {}
        last_error: Exception | None = None
        for keyword in keywords:
            try:
                matches = await self._fetch_by_keyword(
                    keyword,
                    max_results=max_results,
                    kev_entries=kev_entries,
                )
            except httpx.HTTPError as exc:
                # Some NVD keyword variants are noisier than others. Keep trying the
                # compact product/version windows before treating the lookup as failed.
                last_error = exc
                continue
            for evidence in matches:
                evidences_by_id.setdefault(evidence.identifier, evidence)
            if len(evidences_by_id) >= max_results:
                break
        if not evidences_by_id and last_error is not None:
            raise last_error
        return sorted(
            evidences_by_id.values(),
            key=lambda item: float(item.score or 0.0),
            reverse=True,
        )

    async def _load_kev_catalog(self) -> Dict[str, Dict[str, Any]]:
        """Download and cache the CISA Known Exploited Vulnerabilities catalog."""

        if self._kev_cache is not None:
            return self._kev_cache

        async with httpx.AsyncClient(follow_redirects=True, timeout=self._timeout) as client:
            response = await client.get(CISA_KEV_JSON)
            response.raise_for_status()
            payload = response.json()

        entries: Dict[str, Dict[str, Any]] = {}
        for item in payload.get("vulnerabilities", []) or []:
            cve_id = str(item.get("cveID") or "").strip().upper()
            if cve_id:
                entries[cve_id] = dict(item)
        self._kev_cache = entries
        return entries

    def _normalize_vulnerability(
        self,
        vulnerability: Dict[str, Any],
        kev_entries: Dict[str, Dict[str, Any]],
    ) -> ResearchEvidence | None:
        """Normalize one NVD vulnerability row into librarian evidence."""

        cve = vulnerability.get("cve") or {}
        cve_id = str(cve.get("id") or "").strip().upper()
        if not cve_id:
            return None

        descriptions = cve.get("descriptions") or []
        description = ""
        for item in descriptions:
            if str(item.get("lang") or "").lower() == "en":
                description = str(item.get("value") or "").strip()
                break
        if not description and descriptions:
            description = str(descriptions[0].get("value") or "").strip()

        metrics = cve.get("metrics") or {}
        severity, base_score = self._extract_cvss(metrics)
        kev = kev_entries.get(cve_id, {})
        references = cve.get("references") or []
        # Prefer NVD's detail page as the primary citation because it is stable and official.
        primary_ref = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        metadata = {
            "cve": cve_id,
            "severity": severity,
            "base_score": base_score,
            "known_exploited": bool(kev),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "references": [str(ref.get("url") or "").strip() for ref in references if str(ref.get("url") or "").strip()],
        }
        if kev:
            metadata["kev"] = kev

        return ResearchEvidence(
            source_type="cve",
            identifier=cve_id,
            title=cve_id,
            reference=primary_ref,
            snippet=description,
            score=self._derive_score(base_score, bool(kev)),
            metadata=metadata,
        )

    def _extract_cvss(self, metrics: Dict[str, Any]) -> tuple[str | None, float | None]:
        """Return the first available CVSS severity/score across supported versions."""

        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key) or []
            if not values:
                continue
            metric = values[0] or {}
            cvss_data = metric.get("cvssData") or {}
            severity = str(cvss_data.get("baseSeverity") or metric.get("baseSeverity") or "").strip() or None
            score = cvss_data.get("baseScore")
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None
            return severity, score
        return None, None

    def _derive_score(self, base_score: float | None, known_exploited: bool) -> float:
        """Convert CVSS and KEV status into a normalized retrieval confidence score."""

        normalized = 0.55
        if base_score is not None:
            normalized = min(0.98, max(0.2, base_score / 10.0))
        if known_exploited:
            normalized = min(0.99, normalized + 0.12)
        return round(normalized, 6)
