"""Librarian agent - turns telemetry, RAG, and OSINT into an intelligence brief."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from src.agents.base import BaseAgent
from src.config import get_runtime_config
from src.database.librarian.prompts import LibrarianPrompts
from src.database.librarian.query_builder import TelemetryProcessor
from src.database.persistence import persist_state_update
from src.state.cyber_state import CyberState
from src.state.models import IntelligenceBrief
from src.utils.parsers import extract_json_payload


class LibrarianAgent(BaseAgent):
    def __init__(self, rag_orchestrator: Optional[Any] = None):
        """Initialize shared runtime plus optional RAG/OSINT helpers."""

        super().__init__("librarian", "Research and Intelligence Specialist")
        cfg = get_runtime_config()
        self._init_runtime(
            config=cfg,
            model=cfg.supervisor_model,
            api_key=cfg.openrouter_api_key,
            base_url=cfg.openrouter_base_url,
            timeout_seconds=cfg.supervisor_timeout_seconds,
        )
        self._rag_top_k = cfg.rag_kb_top_k
        self._min_docs = cfg.rag_min_docs
        self._min_score = cfg.rag_min_score
        self._telemetry_processor = TelemetryProcessor()
        self._rag = rag_orchestrator or self._build_rag()
        self._osint_client = self._build_osint_client()

    @property
    def system_prompt(self) -> str:
        """Stable research-oriented system prompt."""

        return LibrarianPrompts.SYSTEM_PROMPT

    def _build_research_query(self, state: CyberState) -> str:
        """Turn current mission telemetry into a focused research query."""

        return self._telemetry_processor.build_research_query(state)

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """Produce a cached intelligence brief for the current mission state."""

        query = self._build_research_query(state)
        cache_key = self._cache_key(query)
        research_cache = dict(state.get("research_cache", {}) or {})
        cached = research_cache.get(cache_key)
        # Cache brief synthesis so the workflow can revisit the same question cheaply.
        brief = IntelligenceBrief.model_validate(cached) if cached else await self._build_brief(query)
        if not cached:
            research_cache[cache_key] = brief.model_dump()

        return {
            **self._agent_update(state),
            "research_cache": research_cache,
            "intelligence_findings": [self._finding_from_brief(brief)],
            "rag_fallback_triggered": bool(getattr(brief, "is_osint_derived", False)),
            **self.log_action(
                state,
                action="research_brief",
                findings={
                    "query": query,
                    "citations": brief.citations,
                    "confidence": brief.confidence,
                    "is_osint_derived": brief.is_osint_derived,
                },
                reasoning="Librarian produced cited intelligence brief",
            ),
        }

    def _build_rag(self) -> Any:
        """Best-effort RAG orchestrator bootstrap."""

        try:
            from src.database.rag.rag_engine import RAGOrchestrator

            return RAGOrchestrator()
        except Exception:
            return None

    def _build_osint_client(self) -> Any:
        """Best-effort OSINT client bootstrap."""

        try:
            from src.database.librarian.osint_client import OSINTClient

            return OSINTClient()
        except Exception:
            return None

    async def _build_brief(self, query: str) -> IntelligenceBrief:
        """Retrieve local context first, then fall back to OSINT when confidence is low."""

        rag_results = await self._retrieve_from_kb(query)
        osint_results = [] if self._is_rag_confident(rag_results) else await self._retrieve_osint(query)
        return await self._research_brief(query, rag_results, osint_results)

    async def _retrieve_from_kb(self, query: str) -> List[Dict[str, Any]]:
        """Fetch candidate knowledge-base passages for the query."""

        if self._rag is None:
            return []
        try:
            result = await self._rag.retrieve(query=query, source="kb", top_k=self._rag_top_k)
            return result.get("kb_results", [])
        except Exception:
            return []

    def _is_rag_confident(self, rag_results: List[Dict[str, Any]]) -> bool:
        """Decide whether local RAG evidence is strong enough to skip OSINT."""

        if len(rag_results or []) < self._min_docs:
            return False
        scores = [
            score
            for result in rag_results
            if isinstance(result, dict)
            for score in [result.get("score") or result.get("similarity")]
            if score is not None
        ]
        return bool(scores) and max(scores) >= self._min_score

    async def _retrieve_osint(self, query: str) -> List[Dict[str, Any]]:
        """Fetch OSINT results when local retrieval is weak."""

        if self._osint_client is None:
            return []
        return await self._osint_client.search(query)

    async def _research_brief(
        self,
        query: str,
        rag_results: Optional[List[Dict[str, Any]]] = None,
        osint_results: Optional[List[Dict[str, Any]]] = None,
    ) -> IntelligenceBrief:
        """Ask the model to synthesize retrieved material into a structured brief."""

        rag_results = rag_results or []
        osint_results = osint_results or []
        if self._client is None:
            return IntelligenceBrief(
                summary=f"LLM not configured; {'partial data-based' if (rag_results or osint_results) else 'fallback'} brief for: {query}",
                technical_params={},
                is_osint_derived=bool(osint_results),
                confidence=0.0,
                citations=[],
                conflicting_sources=None,
            )

        try:
            # Librarian uses a plain chat turn and validates the structured JSON into IntelligenceBrief.
            content = await self._run_chat_agent(
                state={},
                user_prompt=LibrarianPrompts.build_user_content(query, rag_results, osint_results),
                temperature=0.0,
                error_message="Librarian chat completion failed.",
            )
            if isinstance(content, dict):
                raise RuntimeError(content.get("errors", [{}])[0].get("error", "Chat completion failed"))
            payload = extract_json_payload(content)
            if osint_results:
                payload["is_osint_derived"] = True
            if "confidence_score" in payload and "confidence" not in payload:
                payload["confidence"] = payload["confidence_score"]
            payload["citations"] = self._normalize_citations(payload.get("citations"))
            return IntelligenceBrief.model_validate(payload)
        except (RuntimeError, ValueError):
            return IntelligenceBrief(
                summary=f"Error in synthesis for: {query}",
                technical_params={},
                is_osint_derived=False,
                confidence=0.0,
                citations=[],
                conflicting_sources=None,
            )

    def _finding_from_brief(self, brief: IntelligenceBrief) -> Dict[str, Any]:
        """Convert the brief into the normalized intelligence_finding shape used by the workflow."""

        return {
            "source": "librarian",
            "description": brief.summary,
            "exploit_available": bool(brief.technical_params.get("exploit_module")),
            "data": {
                "technical_params": brief.technical_params,
                "citations": brief.citations,
                "confidence": brief.confidence,
                "is_osint_derived": brief.is_osint_derived,
                "conflicting_sources": brief.conflicting_sources or [],
            },
        }

    def _cache_key(self, query: str) -> str:
        """Generate a stable cache key for a research query."""

        return f"research_{hashlib.sha1(query.encode()).hexdigest()[:10]}"

    @staticmethod
    def _normalize_citations(raw: Any) -> List[str]:
        """Normalize citation payloads to simple printable strings."""

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


async def librarian_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper for the librarian."""

    agent = LibrarianAgent()
    updates = await agent.call_llm(state)
    persist_state_update(state, updates)
    return updates
