"""
Librarian Agent - research and intelligence worker.

Responsibilities:
- Turn CyberState telemetry + RAG + OSINT into a structured intelligence brief.
- Do NOT execute tools directly; only provide cited intelligence for other agents.
"""


from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from src.agents.base import BaseAgent
from src.config import get_runtime_config
from src.state.cyber_state import CyberState
from src.state.models import IntelligenceBrief
from src.utils.llm import build_chat_openai, extract_text_content
from src.utils.parsers import extract_json_payload

from src.database.librarian.query_builder import TelemetryProcessor
from src.database.librarian.prompts import LibrarianPrompts

MIN_DOCS = 3  # Minimum number of results needed
MIN_SCORE = 0.75  # Minimum similarity score threshold


class LibrarianAgent(BaseAgent):
    def __init__(self, rag_orchestrator: Optional[Any] = None):
        super().__init__("librarian", "Research and Intelligence Specialist")
        cfg = get_runtime_config()

        # 1. LLM Client
        self._llm = None
        if cfg.openrouter_api_key:
            self._llm = build_chat_openai(
                model=cfg.supervisor_model,
                base_url=cfg.openrouter_base_url,
                timeout_seconds=cfg.supervisor_timeout_seconds,
            )
        
        # 2. Query Builder
        self._telemetry_processor = TelemetryProcessor()

        # 3. RAG Orchestrator
        if rag_orchestrator is not None:
            self._rag = rag_orchestrator
        else:
            try:
                from src.database.rag.rag_engine import RAGOrchestrator
                self._rag = RAGOrchestrator()
            except Exception:
                self._rag = None
        
        # 4. OSINT Client
        try:
            from src.database.librarian.osint_client import OSINTClient
            self._osint_client = OSINTClient()
        except Exception:
            self._osint_client = None


    @property
    def system_prompt(self) -> str:
        return LibrarianPrompts.SYSTEM_PROMPT


    def _build_research_query(self, state: CyberState) -> str:
        """Wrapper method for backward compatibility with tests."""
        return self._telemetry_processor.build_research_query(state)


    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        # A. build query from telemetry
        query = self._telemetry_processor.build_research_query(state)
        cache_key = self._cache_key(query)

        # check cache first (simple in-memory cache keyed by query hash)
        research_cache = dict(state.get("research_cache", {}) or {})
        cached = research_cache.get(cache_key)

        if cached:
            # directly restore cached brief
            brief = IntelligenceBrief.model_validate(cached)
        else:
            # B. RAG first, check confidence
            rag_results = await self._retrieve_from_kb(query)
            rag_confident = self._is_rag_confident(rag_results)

            # C. OSINT only if RAG is not confident
            osint_results: List[Dict[str, Any]] = []
            if not rag_confident:
                osint_results = await self._retrieve_osint(query)

            # D. generate Intelligence Brief（decided by LLM is_osint_derived）
            brief = await self._research_brief(query, rag_results, osint_results)

            # E. Update State cache
            research_cache[cache_key] = brief.model_dump()

        # F. Build high-level intelligence findings for downstream agents
        intelligence_findings = [{
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
        }]

        # rag_fallback_triggered directly uses brief.is_osint_derived
        rag_fallback_triggered = bool(getattr(brief, "is_osint_derived", False))

        return {
            "current_agent": "librarian",
            "research_cache": research_cache,
            "intelligence_findings": intelligence_findings,
            "rag_fallback_triggered": rag_fallback_triggered,
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

    async def _retrieve_from_kb(self, query: str) -> List[Dict[str, Any]]:
        if self._rag is None:
            return []
        try:
            res = await self._rag.retrieve(query=query, source="kb", top_k=5)
            return res.get("kb_results", [])
        except Exception:
            return []


    def _is_rag_confident(self, rag_results: List[Dict[str, Any]]) -> bool:
        """
        Check if RAG results meet minimum quality threshold.
        
        A result is considered confident if:
        1. It has at least MIN_DOCS_THRESHOLD results
        2. The highest scoring result meets MIN_SCORE_THRESHOLD
        
        Returns:
            True if RAG is confident, False if we should fallback to OSINT
        """
        min_docs = MIN_DOCS  # Minimum number of results needed
        min_score = MIN_SCORE  # Minimum similarity score threshold

        if not rag_results or len(rag_results) < min_docs:
            return False
        
        # Extract scores from results (assuming 'score' or 'similarity' field)
        scores = []
        for result in rag_results:
            if isinstance(result, dict):
                score = result.get("score") or result.get("similarity")
                if score is not None:
                    scores.append(score)
        
        if not scores or max(scores) < min_score:
            return False
        
        return True


    async def _retrieve_osint(self, query: str) -> List[Dict[str, Any]]:
        if self._osint_client is None:
            return []
        return await self._osint_client.search(query)


    async def _research_brief(
        self,
        query: str,
        rag_results: List[Dict[str, Any]],
        osint_results: List[Dict[str, Any]],
    ) -> IntelligenceBrief:
        if self._llm is None:
            return IntelligenceBrief(
                summary=f"LLM not configured; fallback for: {query}",
                technical_params={},
                is_osint_derived=False,
                confidence=0.0,
                citations=[],
                conflicting_sources=None,
            )

        user_content = LibrarianPrompts.build_user_content(query, rag_results, osint_results)

        try:
            response = await self._llm.ainvoke(
                [
                    ("system", LibrarianPrompts.SYSTEM_PROMPT),
                    ("human", user_content),
                ]
            )
            payload = extract_json_payload(extract_text_content(response))

            if osint_results:
                payload["is_osint_derived"] = True

            if "confidence_score" in payload and "confidence" not in payload:
                payload["confidence"] = payload["confidence_score"]

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


    def _cache_key(self, query: str) -> str:
        return f"research_{hashlib.sha1(query.encode()).hexdigest()[:10]}"


async def librarian_node(state: CyberState) -> Dict[str, Any]:
    agent = LibrarianAgent()
    return await agent.call_llm(state)