from __future__ import annotations

import pytest

from src.v2.graph.builder import build_supervisor_v2_graph
from tests.v2_live.helpers import CAPTURED_TARGET_IP, base_state, live_scope, require_live_mcp, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_full_v2_graph_live_supervisor_orchestrates_real_agents():
    require_live_mcp()
    step(f"Running full supervisor-led v2 graph live smoke: {runtime_summary()}")

    state = base_state(
        mission_goal=(
            "Run a bounded full v2 workflow validation against the authorized automotive-testbed. "
            "Use supervisor_v2 to orchestrate scout_v2, fuzzer_v2, librarian_v2, and striker_v2 as useful. "
            "Do not route to resident_v2 unless a live session is verified. End cleanly when no further safe "
            "progress is available."
        ),
        target_scope=[live_scope(), CAPTURED_TARGET_IP],
        mission_id="v2-live-full-graph",
    )

    graph = build_supervisor_v2_graph()
    out = await graph.ainvoke(state, {"recursion_limit": 14})
    agents = [
        getattr(entry, "agent", "")
        for entry in (out.get("agent_log", []) or [])
        if getattr(entry, "agent", "")
    ]

    print(f"[v2-live] FULL_GRAPH_AGENTS: {agents}", flush=True)
    print(f"[v2-live] FULL_GRAPH_STATUS: current={out.get('current_agent')} next={out.get('next_agent')} mission={out.get('mission_status')}", flush=True)

    assert agents, out
    assert agents[0] == "supervisor_v2"
    assert all(agent.endswith("_v2") for agent in agents)
    assert not any(agent in {"supervisor", "scout", "fuzzer", "librarian", "striker", "resident"} for agent in agents)
    assert "supervisor_v2" in agents
    assert any(agent in agents for agent in {"scout_v2", "fuzzer_v2", "librarian_v2", "striker_v2"})
    assert int(out.get("iteration_count", 0)) <= 14
    assert out.get("current_agent") in {
        "supervisor_v2",
        "scout_v2",
        "fuzzer_v2",
        "librarian_v2",
        "striker_v2",
        "resident_v2",
    }
