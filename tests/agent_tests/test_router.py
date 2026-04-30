from __future__ import annotations

import pytest

langgraph_graph = pytest.importorskip("langgraph.graph")
router_mod = pytest.importorskip("src.graph.router")
END = langgraph_graph.END
get_valid_agents = router_mod.get_valid_agents
route_next_agent = router_mod.route_next_agent


def _base_state() -> dict[str, object]:
    return {
        "mission_status": "active",
        "iteration_count": 0,
        "next_agent": "scout",
        "target_scope": ["10.0.0.0/24"],
        "discovered_targets": {"10.0.0.5": {"ports": [80], "services": {}}},
    }


def test_router_accepts_valid_agents():
    for agent_name in get_valid_agents():
        state = _base_state()
        state["next_agent"] = agent_name
        assert route_next_agent(state) == agent_name


def test_router_invalid_agent_ends():
    state = _base_state()
    state["next_agent"] = "supervisor"
    assert route_next_agent(state) == END


def test_router_terminal_status_ends():
    state = _base_state()
    state["mission_status"] = "success"
    assert route_next_agent(state) == END


def test_router_iteration_cap_ends():
    state = _base_state()
    state["iteration_count"] = 10_000
    assert route_next_agent(state) == END


def test_router_scope_violation_ends():
    state = _base_state()
    state["discovered_targets"] = {"203.0.113.10": {"ports": [80], "services": {}}}
    assert route_next_agent(state) == END
