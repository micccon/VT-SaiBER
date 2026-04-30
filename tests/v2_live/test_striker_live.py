from __future__ import annotations

import os

import pytest

from src.v2.agents.striker.agent import StrikerV2Agent
from src.v2.agents.striker.constants import STRIKER_REQUIRE_CONFIRMATION
from tests.v2_live.helpers import discovered_http_state, require_live_mcp, research_seed, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_striker_v2_live_planning_uses_context_without_auto_execution():
    require_live_mcp()
    step(f"Running striker_v2 live planning turn: {runtime_summary()}")

    state = discovered_http_state(os.getenv("LIVE_STRIKER_BASE_URL") or None)
    state["mission_goal"] = "Plan one evidence-backed exploitation path, but do not proceed without approval."
    state["research_cache"] = {"v2_live_seed": research_seed()}
    state["intelligence_findings"] = [
        {
            "source": "v2_live_seed",
            "description": "Approval-gated live validation seed for striker_v2.",
            "exploit_available": False,
            "data": {"confidence": 0.65, "citations": ["live-test:seed"]},
        }
    ]

    agent = StrikerV2Agent()
    if os.getenv("LIVE_STRIKER_EXECUTE", "false").strip().lower() != "true":
        agent.require_confirmation = True

    out = await agent.run(state)

    assert out["current_agent"] == "striker_v2"
    assert out["agent_log"]
    if os.getenv("LIVE_STRIKER_EXECUTE", "false").strip().lower() != "true" or STRIKER_REQUIRE_CONFIRMATION:
        assert not out.get("active_sessions"), "Planning-only striker_v2 live tests must not open sessions"
