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

        # 2. RAG Orchestrator
        if rag_orchestrator is not None:
            self._rag = rag_orchestrator
        else:
            try:
                from src.database.rag.rag_engine import RAGOrchestrator
                self._rag = RAGOrchestrator()
            except Exception:
                self._rag = None
        self._telemetry_processor = TelemetryProcessor()

        # 3. OSINTS
        try:
            from src.database.librarian.osint_client import OSINTClient
            self._osint_client = OSINTClient()
        except Exception:
            self._osint_client = None

    @property
    def system_prompt(self) -> str:
        return LibrarianPrompts.SYSTEM_PROMPT

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:

        # A. build query from telemetry
        query = self._telemetry_processor.build_research_query(state)
        cache_key = self._cache_key(query)

        # check cache first (simple in-memory cache keyed by query hash)
        research_cache = dict(state.get("research_cache", {}) or {})
        cached = research_cache.get(cache_key)
        if cached:
            brief = IntelligenceBrief.model_validate(cached)
        else:
            # B. RAG
            kb_results = await self._retrieve_from_kb(query)

            # C. OSINT
            osint_results = await self._retrieve_osint(query)

            # D. generate Intelligence Brief
            brief = await self._research_brief(query, kb_results, osint_results)

            # E. Update State
            research_cache = dict(state.get("research_cache", {}) or {})
            research_cache[cache_key] = brief.model_dump()


        osint_findings = [{
            "source": "librarian",
            "description": brief.summary,
            "exploit_available": bool(brief.technical_params.get("exploit_module")),
            "data": {
                "technical_params": brief.technical_params,
                "citations": brief.citations,
                "confidence": brief.confidence,
                "conflicting_sources": brief.conflicting_sources or [],
            },
        }]

        return {
            "current_agent": "librarian",
            "research_cache": research_cache,
            "osint_findings": osint_findings,
            **self.log_action(
                state,
                action="research_brief",
                findings={
                    "query": query,
                    "citations": brief.citations,
                    "confidence": brief.confidence,
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

    async def _retrieve_osint(self, query: str) -> List[Dict[str, Any]]:
        if self._osint_client is None:
            return []
        return await self._osint_client.search(query)

    async def _research_brief(
        self,
        query: str,
        kb_results: List[Dict[str, Any]],
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

        user_content = LibrarianPrompts.build_user_content(query, kb_results, osint_results)

        try:
            response = await self._llm.ainvoke(
                [
                    ("system", LibrarianPrompts.SYSTEM_PROMPT),
                    ("human", user_content),
                ]
            )
            payload = extract_json_payload(extract_text_content(response))

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