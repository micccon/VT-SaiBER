from __future__ import annotations

import asyncio
from typing import Any

import pytest

from src.v2.agents.supervisor.agent import SupervisorV2Agent
from src.v2.agents.supervisor.outcome import SupervisorV2Decision
from src.v2.contracts.chat import ChatSynthesisResult


class _FakeSynthesisRunner:
    def __init__(self, outcome: Any | None = None, *, exc: Exception | None = None, raw_text: str = ""):
        self.outcome = outcome
        self.exc = exc
        self.raw_text = raw_text
        self.calls: list[dict[str, Any]] = []

    async def run(self, spec, *, user_input: str, history=None):
        self.calls.append({"spec": spec, "user_input": user_input, "history": history})
        if self.exc is not None:
            raise self.exc
        return ChatSynthesisResult(outcome=self.outcome, raw_result=None, raw_text=self.raw_text)


def _base_state() -> dict[str, Any]:
    return {
        "mission_goal": "Gain validated access to the in-scope target",
        "mission_id": "test-supervisor-v2",
        "mission_status": "active",
        "current_agent": "resident_v2",
        "next_agent": None,
        "iteration_count": 0,
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


def _run(coro):
    return asyncio.run(coro)


def test_supervisor_v2_exposes_run_entrypoint():
    assert hasattr(SupervisorV2Agent(), "run")


def test_supervisor_v2_routes_no_targets_to_scout_on_fallback():
    state = _base_state()
    out = _run(SupervisorV2Agent(synthesis_runner=_FakeSynthesisRunner(exc=RuntimeError("boom"))).run(state))

    assert out["next_agent"] == "scout_v2"
    assert out["current_agent"] == "supervisor_v2"


def test_supervisor_v2_routes_http_surface_to_fuzzer_on_fallback():
    state = _base_state()
    state["discovered_targets"] = {
        "10.0.0.5": {
            "ports": [80],
            "services": {"80": {"service_name": "http", "version": "Apache 2.4.57"}},
        }
    }

    out = _run(SupervisorV2Agent(synthesis_runner=_FakeSynthesisRunner(exc=RuntimeError("boom"))).run(state))

    assert out["next_agent"] == "fuzzer_v2"


def test_supervisor_v2_routes_researched_target_to_striker_on_fallback():
    state = _base_state()
    state["discovered_targets"] = {
        "10.0.0.5": {
            "ports": [22],
            "services": {"22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"}},
        }
    }
    state["research_cache"] = {"research_demo": {"summary": "research ready"}}

    out = _run(SupervisorV2Agent(synthesis_runner=_FakeSynthesisRunner(exc=RuntimeError("boom"))).run(state))

    assert out["next_agent"] == "striker_v2"


def test_supervisor_v2_routes_live_session_to_resident_on_fallback():
    state = _base_state()
    state["active_sessions"] = {"10.0.0.5": {"session_id": 7}}

    out = _run(SupervisorV2Agent(synthesis_runner=_FakeSynthesisRunner(exc=RuntimeError("boom"))).run(state))

    assert out["next_agent"] == "resident_v2"


def test_supervisor_v2_shortcuts_completed_resident_to_end():
    state = _base_state()
    state["active_sessions"] = {"10.0.0.5": {"session_id": 7}}
    state["validations"] = [
        {
            "type": "resident_objective",
            "objective_status": "completed",
            "objective": "Collect the flag",
        }
    ]

    out = _run(SupervisorV2Agent().run(state))

    assert out["next_agent"] == "end"
    assert out["mission_status"] == "success"


def test_supervisor_v2_shortcuts_resident_approval_to_end():
    state = _base_state()
    state["active_sessions"] = {"10.0.0.5": {"session_id": 7}}
    state["validations"] = [
        {
            "type": "resident_objective",
            "objective_status": "needs_approval",
            "objective": "Dump credentials",
        }
    ]

    out = _run(SupervisorV2Agent().run(state))

    assert out["next_agent"] == "end"
    assert out["mission_status"] == "wait_for_human"


def test_supervisor_v2_scope_violation_ends_mission():
    state = _base_state()
    state["discovered_targets"] = {"203.0.113.10": {"ports": [80], "services": {}}}

    out = _run(SupervisorV2Agent().run(state))

    assert out["next_agent"] == "end"
    assert out["mission_status"] == "failed"


def test_supervisor_v2_guardrail_corrects_invalid_model_decision():
    agent = SupervisorV2Agent()
    bad = SupervisorV2Decision.model_construct(
        next_agent="bogus",
        rationale="bad",
        specific_goal="bad",
        confidence_score=0.2,
    )

    corrected, reason = agent._apply_guardrails(_base_state(), bad)

    assert corrected.next_agent == "scout_v2"
    assert reason == "invalid-next-agent-corrected"


def test_supervisor_v2_guardrail_forces_librarian_before_striker():
    agent = SupervisorV2Agent()
    state = _base_state()
    state["discovered_targets"] = {
        "10.0.0.5": {
            "ports": [22],
            "services": {"22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"}},
        }
    }
    decision = SupervisorV2Decision(
        next_agent="striker_v2",
        rationale="go exploit",
        specific_goal="Exploit the SSH service",
        confidence_score=0.8,
    )

    corrected, reason = agent._apply_guardrails(state, decision)

    assert corrected.next_agent == "librarian_v2"
    assert reason == "forced-librarian-before-striker"


def test_supervisor_v2_guardrail_backtracks_after_failed_striker():
    agent = SupervisorV2Agent()
    state = _base_state()
    state["research_cache"] = {"research_demo": {"summary": "ok"}}
    state["exploited_services"] = [{"target": "10.0.0.5", "module": "exploit/demo", "status": "failed"}]

    decision = SupervisorV2Decision(
        next_agent="striker_v2",
        rationale="retry immediately",
        specific_goal="Retry the exploit",
        confidence_score=0.6,
    )

    corrected, reason = agent._apply_guardrails(state, decision)

    assert corrected.next_agent == "librarian_v2"
    assert reason == "striker-failure-backtrack"
