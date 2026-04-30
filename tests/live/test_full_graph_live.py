from __future__ import annotations

import pytest

from src.graph.builder import build_graph
from tests.live.helpers import CAPTURED_TARGET_IP, base_state, live_scope, require_live_mcp, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_full_graph_live_supervisor_orchestrates_real_agents():
    require_live_mcp()
    step(f"Running full supervisor-led production graph live smoke: {runtime_summary()}")

    state = base_state(
        mission_goal=(
            "Run a bounded full workflow validation against the authorized automotive-testbed. "
            "Use supervisor to orchestrate scout, fuzzer, librarian, and striker as useful. "
            "Do not route to resident unless a live session is verified. End cleanly when no further safe "
            "progress is available."
        ),
        target_scope=[live_scope(), CAPTURED_TARGET_IP],
        mission_id="live-full-graph",
    )

    graph = build_graph()
    out = await graph.ainvoke(state, {"recursion_limit": 14})
    agents = [
        getattr(entry, "agent", "")
        for entry in (out.get("agent_log", []) or [])
        if getattr(entry, "agent", "")
    ]

    print(f"[live] FULL_GRAPH_AGENTS: {agents}", flush=True)
    print(f"[live] FULL_GRAPH_STATUS: current={out.get('current_agent')} next={out.get('next_agent')} mission={out.get('mission_status')}", flush=True)

    assert agents, out
    assert agents[0] == "supervisor"
    assert "supervisor" in agents
    assert any(agent in agents for agent in {"scout", "fuzzer", "librarian", "striker"})
    assert int(out.get("iteration_count", 0)) <= 14
    assert out.get("current_agent") in {
        "supervisor",
        "scout",
        "fuzzer",
        "librarian",
        "striker",
        "resident",
    }
