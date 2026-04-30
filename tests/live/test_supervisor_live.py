from __future__ import annotations

import pytest

from src.agents.supervisor.agent import SupervisorAgent
from src.agents.supervisor.constants import VALID_NEXT_AGENTS
from tests.live.helpers import base_state, require_live_openrouter, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_supervisor_live_openrouter_route_decision():
    require_live_openrouter()
    step(f"Running supervisor live route decision: {runtime_summary()}")

    out = await SupervisorAgent().run(base_state(mission_goal="Start with reconnaissance on the authorized target"))

    assert out["current_agent"] == "supervisor"
    assert out["next_agent"] in VALID_NEXT_AGENTS
    assert out["supervisor_expectations"]["specific_goal"]
    assert out["agent_log"]
