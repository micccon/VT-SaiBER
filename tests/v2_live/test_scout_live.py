from __future__ import annotations

import pytest

from src.v2.agents.scout.agent import ScoutV2Agent
from tests.v2_live.helpers import base_state, live_scope, require_live_mcp, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_scout_v2_live_discovers_or_probes_target():
    require_live_mcp()
    step(f"Running scout_v2 live MCP probe: {runtime_summary()}")

    state = base_state(
        mission_goal="Discover and fingerprint the authorized live target",
        target_scope=[live_scope()],
        mission_id="v2-live-scout",
    )
    out = await ScoutV2Agent().run(state)

    assert out["current_agent"] == "scout_v2"
    assert not out.get("errors"), out.get("errors")
    assert out.get("discovered_targets"), out
    assert out["agent_log"]
