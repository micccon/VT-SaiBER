"""Librarian v2 agent built on the v2 chat/synthesis lane."""

from __future__ import annotations

from typing import Any

from src.agents.librarian import LibrarianAgent, _DEFAULT_CLIENT
from src.database.librarian.models import LibrarianDependencyStatus, ResearchEvidence
from src.database.librarian.prompts import LibrarianPrompts
from src.database.librarian.readiness import build_dependency_status
from src.state.cyber_state import CyberState
from src.state.models import IntelligenceBrief, RetrievalTrace
from src.v2.agents.common import build_default_model_config, execution_error_update, run_v2_agent_node
from src.v2.agents.librarian.context import build_research_query, build_synthesis_prompt
from src.v2.agents.librarian.mapper import map_brief_to_state
from src.v2.agents.librarian.outcome import LibrarianOutcome
from src.v2.chat import V2ChatSynthesisRunner
from src.v2.contracts.chat import ChatSynthesisSpec


class LibrarianV2Agent:
    """Structured-output librarian implementation on the parallel v2 stack."""

    def __init__(
        self,
        rag_orchestrator: Any | None = None,
        *,
        osint_client: Any | None = None,
        cve_client: Any | None = None,
        llm_client: Any | None = None,
        synthesis_runner: V2ChatSynthesisRunner | None = None,
    ):
        self.name = "librarian_v2"
        self._synthesis_runner = synthesis_runner or V2ChatSynthesisRunner(client=llm_client)
        self._core = LibrarianAgent(
            rag_orchestrator=rag_orchestrator,
            osint_client=osint_client if osint_client is not None else _DEFAULT_CLIENT,
            cve_client=cve_client if cve_client is not None else _DEFAULT_CLIENT,
            llm_client=None,
        )
        self._model_config = build_default_model_config(temperature=0.0)

    @property
    def system_prompt(self) -> str:
        """Return the fixed librarian synthesis instructions."""

        return LibrarianPrompts.SYSTEM_PROMPT

    def build_synthesis_spec(self) -> ChatSynthesisSpec[LibrarianOutcome]:
        """Build the v2 synthesis declaration for librarian."""

        return ChatSynthesisSpec(
            agent_name=self.name,
            instructions=self.system_prompt,
            model=self._model_config,
            output_type=LibrarianOutcome,
        )

    async def _build_brief(self, state: CyberState, query: str) -> tuple[IntelligenceBrief, RetrievalTrace]:
        """Run staged retrieval and synthesize a brief through the v2 chat lane."""

        status = build_dependency_status()
        if not self._model_config.api_key:
            status.mark("llm", "unavailable")
            status.add_reason("llm_unavailable")
        else:
            status.mark("llm", "ready")

        query_inputs = self._core._telemetry_processor.build_research_inputs(state)
        kb_results = await self._core._retrieve_from_kb(query, status)
        findings_results = await self._core._retrieve_from_findings(query, status)

        cve_results: list[ResearchEvidence] = []
        if self._core._should_lookup_cves(query, query_inputs, kb_results, findings_results):
            cve_results = await self._core._retrieve_cves(
                query,
                query_inputs,
                status,
                kb_results,
                findings_results,
            )
        else:
            status.mark("cve", "skipped")

        osint_results: list[dict[str, Any]] = []
        if self._core._should_lookup_osint(query, kb_results, findings_results, cve_results):
            osint_results = await self._core._retrieve_osint(query, status)
        else:
            status.mark("osint", "skipped")

        if not cve_results and osint_results:
            cve_results = await self._core._retrieve_cves_from_osint(
                query,
                query_inputs,
                status,
                kb_results,
                findings_results,
                osint_results,
            )

        if not self._model_config.api_key:
            brief = self._core._fallback_brief(
                query,
                kb_results,
                findings_results,
                cve_results,
                osint_results,
                status,
            )
        else:
            try:
                synthesis = await self._synthesis_runner.run(
                    self.build_synthesis_spec(),
                    user_input=build_synthesis_prompt(
                        query,
                        kb_results,
                        findings_results,
                        [self._core._normalize_item(item) for item in cve_results],
                        osint_results,
                        status.statuses,
                    ),
                )
                payload = synthesis.outcome.model_dump()
                payload["is_osint_derived"] = bool(osint_results)
                if "confidence_score" in payload and "confidence" not in payload:
                    payload["confidence"] = payload["confidence_score"]
                payload["citations"] = self._core._citations_from_results(
                    kb_results,
                    findings_results,
                    cve_results,
                    osint_results,
                ) or self._core._normalize_citations(payload.get("citations"))
                payload["source_types"] = self._core._source_types(
                    kb_results,
                    findings_results,
                    cve_results,
                    osint_results,
                )
                payload["source_status"] = dict(status.statuses)
                payload["degraded_reasons"] = list(status.degraded_reasons)
                self._core._apply_confidence_guard(payload)
                brief = IntelligenceBrief.model_validate(payload)
            except Exception:
                status.mark("llm", "degraded")
                status.add_reason("llm_synthesis_failed")
                brief = self._core._fallback_brief(
                    query,
                    kb_results,
                    findings_results,
                    cve_results,
                    osint_results,
                    status,
                )

        retrieval_trace = self._core._build_retrieval_trace(
            kb_results=kb_results,
            findings_results=findings_results,
            cve_results=cve_results,
            osint_results=osint_results,
            status=status,
        )
        return brief, retrieval_trace

    async def run(self, state: CyberState) -> dict[str, object]:
        """Execute librarian v2 and map the synthesized brief back into CyberState."""

        query = build_research_query(state)
        cache_key = self._core._cache_key(query)
        research_cache = dict(state.get("research_cache", {}) or {})

        try:
            cached = research_cache.get(cache_key)
            if cached:
                brief = IntelligenceBrief.model_validate(cached)
                retrieval_trace = self._core._trace_from_cached_brief(brief)
            else:
                brief, retrieval_trace = await self._build_brief(state, query)
                research_cache[cache_key] = brief.model_dump()

            return map_brief_to_state(
                state,
                agent_name=self.name,
                query=query,
                brief=brief,
                retrieval_trace=retrieval_trace,
                research_cache=research_cache,
                finding_from_brief=self._core._finding_from_brief,
            )
        except Exception as exc:
            return execution_error_update(
                state,
                agent_name=self.name,
                message="Librarian v2 execution failed.",
                exc=exc,
            )


async def librarian_v2_node(state: CyberState) -> dict[str, object]:
    """LangGraph node wrapper for librarian v2."""

    return await run_v2_agent_node(state, LibrarianV2Agent)
