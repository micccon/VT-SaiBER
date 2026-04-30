from __future__ import annotations

import asyncio
from typing import Any

import pytest
from src.state.models import AgentLogEntry

builder_mod = pytest.importorskip("src.graph.builder")


def _base_state() -> dict[str, Any]:
    return {
        "mission_goal": "Run the production workflow",
        "mission_id": "test-mission",
        "mission_status": "active",
        "current_agent": "supervisor",
        "next_agent": None,
        "iteration_count": 0,
        "target_scope": ["192.168.1.10"],
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


def test_build_graph_routes_supervisor_specialist_supervisor(monkeypatch):
    async def fake_supervisor(state):
        next_agent = "scout" if int(state.get("iteration_count", 0)) == 0 else "end"
        return {
            "current_agent": "supervisor",
            "iteration_count": int(state.get("iteration_count", 0)) + 1,
            "next_agent": next_agent,
            "mission_status": "active" if next_agent != "end" else "wait_for_human",
            "supervisor_expectations": {"specific_goal": "Discover targets", "confidence_score": 0.8},
            "agent_log": [AgentLogEntry(agent="supervisor", action="route_decision", decision=next_agent)],
        }

    async def fake_scout(state):
        return {
            "current_agent": "scout",
            "iteration_count": int(state.get("iteration_count", 0)) + 1,
            "discovered_targets": {"192.168.1.10": {"ports": [80], "services": {"80": {"service_name": "http"}}}},
            "agent_log": [AgentLogEntry(agent="scout", action="recon_scan")],
        }

    monkeypatch.setattr(builder_mod, "supervisor_node", fake_supervisor)
    monkeypatch.setattr(builder_mod, "scout_node", fake_scout)

    graph = builder_mod.build_graph()
    out = _run(graph.ainvoke(_base_state()))

    agents = [getattr(entry, "agent", "") for entry in out["agent_log"]]
    assert agents == ["supervisor", "scout", "supervisor"]
    assert out["current_agent"] == "supervisor"
    assert out["mission_status"] == "wait_for_human"

