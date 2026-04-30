from __future__ import annotations

import pytest

from src.agents.resident.agent import ResidentAgent
from tests.live.helpers import auto_detect_live_session, base_state, live_scope, require_live_mcp, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_resident_live_validates_seeded_session():
    require_live_mcp()
    detected = await auto_detect_live_session()
    session_id = (detected[0] if detected else "").strip()
    target = (detected[1] if detected else "").strip()
    if not session_id or not target:
        pytest.skip("No live Metasploit session available for resident")

    step(f"Running resident live session validation for session {session_id}: {runtime_summary()}")
    state = base_state(
        mission_goal="Validate the seeded session and perform one read-only orientation step.",
        target_scope=[live_scope()],
        mission_id="live-resident",
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

    agent = ResidentAgent()
    agent.require_confirmation = True
    out = await agent.run(state)

    assert out["current_agent"] == "resident"
    assert out["validations"]
    assert out["agent_log"]
    assert out["validations"][0]["live_session_count"] >= 0
