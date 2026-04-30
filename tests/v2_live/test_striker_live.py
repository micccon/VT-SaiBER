from __future__ import annotations

import pytest

from src.v2.agents.striker.agent import StrikerV2Agent
from tests.v2_live.helpers import captured_automotive_state, require_live_mcp, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_striker_v2_live_planning_uses_context_without_auto_execution():
    require_live_mcp()
    step(f"Running striker_v2 live planning turn: {runtime_summary()}")

    state = captured_automotive_state(mission_id="v2-live-striker")
    state["mission_goal"] = "Plan one evidence-backed exploitation path, but do not proceed without approval."

    agent = StrikerV2Agent()
    agent.require_confirmation = True

    out = await agent.run(state)

    assert out["current_agent"] == "striker_v2"
    assert out["agent_log"]
    assert not out.get("active_sessions"), "Planning-only striker_v2 live tests must not open sessions"
