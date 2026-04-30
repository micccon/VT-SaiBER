from __future__ import annotations

import asyncio
import inspect
from typing import Any

import pytest

from src.database.librarian.service import LibrarianResearchService
from src.state.models import IntelligenceBrief
from src.agents.librarian import agent as librarian_agent_mod
from src.agents.librarian.agent import LibrarianAgent
from src.agents.librarian.context import build_research_query
from src.runtime.contracts import ChatSynthesisResult


class _FakeSynthesisRunner:
    def __init__(self, outcome: Any | None = None, *, exc: Exception | None = None):
        self.outcome = outcome
        self.exc = exc
        self.calls: list[dict[str, Any]] = []

    async def run(self, spec, *, user_input: str, history=None):
        self.calls.append({"spec": spec, "user_input": user_input, "history": history})
        if self.exc is not None:
            raise self.exc
        return ChatSynthesisResult(outcome=self.outcome, raw_result=None, raw_text="")


class _FakeRag:
    def __init__(self, *, kb_results=None, findings_results=None):
        self.kb_results = list(kb_results or [])
        self.findings_results = list(findings_results or [])

    async def retrieve(self, query: str, source: str = "both", top_k: int = 5, filters=None):
        if source == "kb":
            return {"kb_results": list(self.kb_results)}
        if source == "findings":
            return {"findings_results": list(self.findings_results)}
        return {"kb_results": list(self.kb_results), "findings_results": list(self.findings_results)}


def _base_state() -> dict[str, Any]:
    return {
        "mission_goal": "Assess the target for a safe research path",
        "mission_id": "test-lib",
        "mission_status": "active",
        "current_agent": "supervisor",
        "next_agent": None,
        "iteration_count": 2,
        "target_scope": ["10.0.0.0/24"],
        "discovered_targets": {},
        "ot_discovery": {},
        "web_findings": [],
        "active_sessions": {},
        "exploited_services": [],
        "credential_findings": [],
        "exploit_attempts": [],
        "protocol_observations": [],
        "fuzzing_runs": [],
        "crash_indicators": [],
        "artifacts": [],
        "validations": [],
        "research_cache": {},
        "intelligence_findings": [],
        "supervisor_messages": [],
        "supervisor_expectations": {},
        "agent_log": [],
        "critical_findings": [],
        "errors": [],
    }


def _brief(**overrides) -> IntelligenceBrief:
    payload = {
        "summary": "Research summary",
        "technical_params": {"exploit_module": "auxiliary/scanner/ssh/ssh_login"},
        "is_osint_derived": False,
        "confidence": 0.82,
        "citations": ["kb:ssh_guide.md"],
        "conflicting_sources": None,
        "source_types": ["kb"],
        "source_status": {"kb": "ready", "findings": "empty", "cve": "skipped", "osint": "skipped", "llm": "ready", "embeddings": "ready"},
        "degraded_reasons": [],
    }
    payload.update(overrides)
    return IntelligenceBrief.model_validate(payload)


def _run(coro):
    return asyncio.run(coro)


def _enable_llm(agent: LibrarianAgent) -> LibrarianAgent:
    agent._model_config = agent._model_config.__class__(
        model=agent._model_config.model or "test-model",
        api_key="test-key",
        base_url=agent._model_config.base_url or "https://example.invalid",
        timeout_seconds=agent._model_config.timeout_seconds,
        temperature=agent._model_config.temperature,
        trace_include_sensitive_data=agent._model_config.trace_include_sensitive_data,
    )
    return agent


def test_librarian_research_query_matches_librarian_service():
    state = _base_state()
    state["discovered_targets"] = {
        "10.0.0.5": {"services": {"22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"}}}
    }
    state["web_findings"] = [{"path": "/admin", "status_code": 200}]

    assert build_research_query(state) == LibrarianResearchService()._build_research_query(state)


def test_librarian_uses_runtime_chat_lane():
    source = inspect.getsource(librarian_agent_mod)
    assert "ChatSynthesisRunner" in source
    assert "src.runtime" in source


def test_librarian_exposes_run_entrypoint():
    agent = LibrarianAgent(
        rag_orchestrator=_FakeRag(),
        synthesis_runner=_FakeSynthesisRunner(outcome=_brief()),
    )
    assert hasattr(agent, "run")


@pytest.mark.asyncio
async def test_librarian_cache_hit_reuses_brief_without_synthesis():
    state = _base_state()
    query = build_research_query(state)
    cache_key = LibrarianResearchService()._cache_key(query)
    state["research_cache"] = {cache_key: _brief(summary="Cached summary").model_dump()}
    runner = _FakeSynthesisRunner(exc=RuntimeError("should not run"))

    out = await LibrarianAgent(
        rag_orchestrator=_FakeRag(),
        synthesis_runner=runner,
    ).run(state)

    assert out["research_cache"][cache_key]["summary"] == "Cached summary"
    assert out["intelligence_findings"][0]["description"] == "Cached summary"
    assert runner.calls == []


@pytest.mark.asyncio
async def test_librarian_cache_miss_runs_synthesis_and_writes_cache():
    state = _base_state()
    runner = _FakeSynthesisRunner(outcome=_brief(summary="Synthesized summary"))
    agent = _enable_llm(LibrarianAgent(
        rag_orchestrator=_FakeRag(),
        synthesis_runner=runner,
    ))

    out = await agent.run(state)

    assert runner.calls
    assert out["research_cache"]
    cache_entry = next(iter(out["research_cache"].values()))
    assert cache_entry["summary"] == "Synthesized summary"
    assert out["intelligence_findings"][0]["description"] == "Synthesized summary"


@pytest.mark.asyncio
async def test_librarian_retrieval_metadata_overrides_model_claims():
    state = _base_state()
    kb_results = [
        {"doc_name": "guide_a.md", "score": 0.95, "chunk_text": "Strong internal evidence A"},
        {"doc_name": "guide_b.md", "score": 0.91, "chunk_text": "Strong internal evidence B"},
    ]
    model_outcome = _brief(
        citations=["osint:https://bad.example"],
        source_types=["osint"],
        source_status={"kb": "wrong"},
    )

    agent = _enable_llm(LibrarianAgent(
        rag_orchestrator=_FakeRag(kb_results=kb_results),
        synthesis_runner=_FakeSynthesisRunner(outcome=model_outcome),
    ))

    out = await agent.run(state)

    cache_entry = next(iter(out["research_cache"].values()))
    assert cache_entry["citations"] == ["kb:guide_a.md", "kb:guide_b.md"]
    assert cache_entry["source_types"] == ["kb"]
    assert cache_entry["source_status"]["kb"] == "ready"
    assert cache_entry["source_status"]["osint"] in {"skipped", "empty"}
    assert cache_entry["source_status"]["kb"] != "wrong"


@pytest.mark.asyncio
async def test_librarian_falls_back_when_synthesis_fails():
    state = _base_state()
    kb_results = [
        {"doc_name": "guide_a.md", "score": 0.88, "chunk_text": "KB evidence A"},
    ]
    agent = LibrarianAgent(
        rag_orchestrator=_FakeRag(kb_results=kb_results),
        synthesis_runner=_FakeSynthesisRunner(exc=RuntimeError("boom")),
    )
    agent = _enable_llm(agent)

    out = await agent.run(state)

    cache_entry = next(iter(out["research_cache"].values()))
    assert cache_entry["summary"].startswith("Fallback intelligence brief for:")
    assert "llm_synthesis_failed" in cache_entry["degraded_reasons"]
    assert out["intelligence_findings"][0]["source"] == "librarian"
