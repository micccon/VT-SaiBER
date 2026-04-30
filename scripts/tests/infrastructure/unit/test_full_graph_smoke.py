from __future__ import annotations

import asyncio
from typing import Any

import pytest
from src.state.models import AgentLogEntry

builder_mod = pytest.importorskip("src.graph.builder")


def _base_state() -> dict[str, Any]:
    return {
        "mission_goal": "Validate production graph smoke path",
        "mission_id": "non-live-smoke",
        "mission_status": "active",
        "current_agent": "supervisor",
        "next_agent": None,
        "iteration_count": 0,
        "target_scope": ["10.10.10.10"],
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


def test_full_graph_smoke_uses_supervisor_specialist_supervisor(monkeypatch):
    async def fake_supervisor(state):
        next_agent = "scout" if int(state.get("iteration_count", 0)) == 0 else "end"
        return {
            "current_agent": "supervisor",
            "iteration_count": int(state.get("iteration_count", 0)) + 1,
            "next_agent": next_agent,
            "mission_status": "active" if next_agent != "end" else "wait_for_human",
            "agent_log": [AgentLogEntry(agent="supervisor", action="route_decision", decision=next_agent)],
        }

    async def fake_scout(state):
        return {
            "current_agent": "scout",
            "iteration_count": int(state.get("iteration_count", 0)) + 1,
            "discovered_targets": {"10.10.10.10": {"ports": [80], "services": {"80": {"service_name": "http"}}}},
            "agent_log": [AgentLogEntry(agent="scout", action="recon_scan")],
        }

    monkeypatch.setattr(builder_mod, "supervisor_node", fake_supervisor)
    monkeypatch.setattr(builder_mod, "scout_node", fake_scout)

    out = _run(builder_mod.build_graph().ainvoke(_base_state()))
    agents = [getattr(entry, "agent", "") for entry in out["agent_log"]]

    assert agents == ["supervisor", "scout", "supervisor"]
    assert out["current_agent"] == "supervisor"
    assert out["mission_status"] == "wait_for_human"


def test_state_compatibility_keeps_expected_cyberstate_keys(monkeypatch):
    async def fake_supervisor(state):
        return {
            "current_agent": "supervisor",
            "iteration_count": 1,
            "next_agent": "end",
            "mission_status": "wait_for_human",
            "supervisor_expectations": {"specific_goal": "Stop", "confidence_score": 1.0},
            "agent_log": [AgentLogEntry(agent="supervisor", action="route_decision", decision="end")],
        }

    monkeypatch.setattr(builder_mod, "supervisor_node", fake_supervisor)

    out = _run(builder_mod.build_graph().ainvoke(_base_state()))

    for key in [
        "current_agent",
        "next_agent",
        "iteration_count",
        "mission_status",
        "discovered_targets",
        "web_findings",
        "active_sessions",
        "research_cache",
        "intelligence_findings",
        "supervisor_expectations",
        "agent_log",
        "errors",
    ]:
        assert key in out

