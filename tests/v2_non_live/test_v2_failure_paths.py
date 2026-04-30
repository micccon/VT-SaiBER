from __future__ import annotations

import pytest

langgraph_graph = pytest.importorskip("langgraph.graph")
router_mod = pytest.importorskip("src.v2.graph.router")

END = langgraph_graph.END
route_next_agent_v2 = router_mod.route_next_agent_v2


def _state(**overrides):
    state = {
        "mission_status": "active",
        "iteration_count": 0,
        "next_agent": "scout_v2",
        "target_scope": ["10.0.0.0/24"],
        "discovered_targets": {"10.0.0.5": {"ports": [80], "services": {}}},
    }
    state.update(overrides)
    return state


def test_v2_router_invalid_next_agent_ends():
    assert route_next_agent_v2(_state(next_agent="scout")) == END


def test_v2_router_terminal_status_ends():
    assert route_next_agent_v2(_state(mission_status="success")) == END


def test_v2_router_iteration_cap_ends():
    assert route_next_agent_v2(_state(iteration_count=10_000)) == END


def test_v2_router_out_of_scope_target_ends():
    assert route_next_agent_v2(_state(discovered_targets={"203.0.113.20": {"ports": [80], "services": {}}})) == END
