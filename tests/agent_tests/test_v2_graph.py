from __future__ import annotations

import asyncio
from typing import Any

import pytest
from src.state.models import AgentLogEntry

builder_mod = pytest.importorskip("src.v2.graph.builder")


def _base_state() -> dict[str, Any]:
    return {
        "mission_goal": "Run the isolated v2 workflow",
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


def test_build_v2_validation_graph_runs_parallel_nodes(monkeypatch):
    async def fake_scout(state):
        return {
            "current_agent": "scout_v2",
            "iteration_count": 1,
            "discovered_targets": {
                "192.168.1.10": {
                    "ports": [80],
                    "services": {"80": {"service_name": "http"}},
                }
            },
            "agent_log": [AgentLogEntry(agent="scout_v2", action="recon_scan")],
        }

    async def fake_fuzzer(state):
        return {
            "current_agent": "fuzzer_v2",
            "iteration_count": 2,
            "web_findings": [{"path": "/", "status_code": 200, "rationale": "ok"}],
            "agent_log": [AgentLogEntry(agent="fuzzer_v2", action="web_enumeration")],
        }

    async def fake_striker(state):
        return {
            "current_agent": "striker_v2",
            "iteration_count": 3,
            "exploit_attempts": [{"status": "validated_no_session"}],
            "agent_log": [AgentLogEntry(agent="striker_v2", action="run_exploit")],
        }

    monkeypatch.setattr(builder_mod, "scout_v2_node", fake_scout)
    monkeypatch.setattr(builder_mod, "fuzzer_v2_node", fake_fuzzer)
    monkeypatch.setattr(builder_mod, "striker_v2_node", fake_striker)

    graph = builder_mod.build_v2_validation_graph()
    out = _run(graph.ainvoke(_base_state()))

    assert out["current_agent"] == "striker_v2"
    assert len(out["agent_log"]) == 3
    assert getattr(out["agent_log"][-1], "agent", "") == "striker_v2"


def test_build_resident_v2_graph_runs_seeded_session_node(monkeypatch):
    async def fake_resident(state):
        return {
            "current_agent": "resident_v2",
            "iteration_count": 1,
            "validations": [{"type": "resident_objective", "objective_status": "in_progress"}],
            "agent_log": [AgentLogEntry(agent="resident_v2", action="objective_worker")],
        }

    monkeypatch.setattr(builder_mod, "resident_v2_node", fake_resident)

    state = _base_state()
    state["active_sessions"] = {"192.168.1.10": {"session_id": 7}}
    graph = builder_mod.build_resident_v2_graph()
    out = _run(graph.ainvoke(state))

    assert out["current_agent"] == "resident_v2"
    assert getattr(out["agent_log"][-1], "agent", "") == "resident_v2"


def test_build_librarian_v2_graph_runs_librarian_node(monkeypatch):
    async def fake_librarian(state):
        return {
            "current_agent": "librarian_v2",
            "iteration_count": 1,
            "research_cache": {"research_demo": {"summary": "ok"}},
            "agent_log": [AgentLogEntry(agent="librarian_v2", action="research_brief")],
        }

    monkeypatch.setattr(builder_mod, "librarian_v2_node", fake_librarian)

    graph = builder_mod.build_librarian_v2_graph()
    out = _run(graph.ainvoke(_base_state()))

    assert out["current_agent"] == "librarian_v2"
    assert getattr(out["agent_log"][-1], "agent", "") == "librarian_v2"


def test_build_supervisor_v2_graph_routes_only_v2_nodes(monkeypatch):
    async def fake_supervisor(state):
        next_agent = "scout_v2" if int(state.get("iteration_count", 0)) == 0 else "end"
        return {
            "current_agent": "supervisor_v2",
            "iteration_count": int(state.get("iteration_count", 0)) + 1,
            "next_agent": next_agent,
            "mission_status": "active" if next_agent != "end" else "wait_for_human",
            "supervisor_expectations": {"specific_goal": "Discover targets", "confidence_score": 0.8},
            "agent_log": [AgentLogEntry(agent="supervisor_v2", action="route_decision", decision=next_agent)],
        }

    async def fake_scout(state):
        return {
            "current_agent": "scout_v2",
            "iteration_count": int(state.get("iteration_count", 0)) + 1,
            "discovered_targets": {"192.168.1.10": {"ports": [80], "services": {"80": {"service_name": "http"}}}},
            "agent_log": [AgentLogEntry(agent="scout_v2", action="recon_scan")],
        }

    monkeypatch.setattr(builder_mod, "supervisor_v2_node", fake_supervisor)
    monkeypatch.setattr(builder_mod, "scout_v2_node", fake_scout)

    graph = builder_mod.build_supervisor_v2_graph()
    out = _run(graph.ainvoke(_base_state()))

    assert out["current_agent"] == "supervisor_v2"
    assert len(out["agent_log"]) == 3
    assert getattr(out["agent_log"][0], "agent", "") == "supervisor_v2"
    assert getattr(out["agent_log"][1], "agent", "") == "scout_v2"
    assert getattr(out["agent_log"][2], "agent", "") == "supervisor_v2"
