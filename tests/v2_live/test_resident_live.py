from __future__ import annotations

import os

import pytest

from src.v2.agents.resident.agent import ResidentV2Agent
from tests.v2_live.helpers import base_state, live_scope, require_live_mcp, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_resident_v2_live_validates_seeded_session():
    require_live_mcp()
    session_id = (os.getenv("LIVE_RESIDENT_SESSION_ID") or "").strip()
    target = (os.getenv("LIVE_RESIDENT_TARGET") or os.getenv("LIVE_STRIKER_TARGET") or "").strip()
    if not session_id or not target:
        pytest.skip("Set LIVE_RESIDENT_SESSION_ID and LIVE_RESIDENT_TARGET to run resident_v2 live test")

    step(f"Running resident_v2 live session validation for session {session_id}: {runtime_summary()}")
    state = base_state(
        mission_goal="Validate the seeded session and perform one read-only orientation step.",
        target_scope=[live_scope()],
        mission_id="v2-live-resident",
    )
    state["active_sessions"] = {
        target: {
            "session_id": session_id,
            "module": "live-test-seeded-session",
        }
    }
    state["supervisor_expectations"] = {
        "specific_goal": "Validate the live session and gather a read-only orientation summary.",
        "confidence_score": 1.0,
    }

    agent = ResidentV2Agent()
    agent.require_confirmation = True
    out = await agent.run(state)

    assert out["current_agent"] == "resident_v2"
    assert out["validations"]
    assert out["agent_log"]
    assert out["validations"][0]["live_session_count"] >= 0
