from __future__ import annotations

import pytest

from src.v2.agents.supervisor.agent import SupervisorV2Agent
from src.v2.agents.supervisor.constants import V2_VALID_NEXT_AGENTS
from tests.v2_live.helpers import base_state, require_live_openrouter, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_supervisor_v2_live_openrouter_route_decision():
    require_live_openrouter()
    step(f"Running supervisor_v2 live route decision: {runtime_summary()}")

    out = await SupervisorV2Agent().run(base_state(mission_goal="Start with reconnaissance on the authorized target"))

    assert out["current_agent"] == "supervisor_v2"
    assert out["next_agent"] in V2_VALID_NEXT_AGENTS
    assert out["supervisor_expectations"]["specific_goal"]
    assert out["agent_log"]
