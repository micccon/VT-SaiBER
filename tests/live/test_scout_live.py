from __future__ import annotations

import pytest

from src.agents.scout.agent import ScoutAgent
from tests.live.helpers import CAPTURED_TARGET_IP, base_state, live_scope, require_live_mcp, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_scout_live_discovers_or_probes_target():
    require_live_mcp()
    step(f"Running scout live MCP probe: {runtime_summary()}")

    state = base_state(
        mission_goal="Discover and fingerprint the authorized live target",
        target_scope=[live_scope(), CAPTURED_TARGET_IP],
        mission_id="live-scout",
    )
    out = await ScoutAgent().run(state)

    assert out["current_agent"] == "scout"
    assert not out.get("errors"), out.get("errors")
    assert out.get("discovered_targets"), out
    assert out["agent_log"]
