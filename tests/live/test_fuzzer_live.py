from __future__ import annotations

import pytest

from src.agents.fuzzer.agent import FuzzerAgent
from tests.live.helpers import captured_automotive_state, fuzzer_base_url, require_live_mcp, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_fuzzer_live_enumerates_configured_web_target():
    require_live_mcp()
    base_url = fuzzer_base_url()
    step(f"Running fuzzer live web enumeration against {base_url}: {runtime_summary()}")

    state = captured_automotive_state(mission_id="live-fuzzer")
    out = await FuzzerAgent().run(state)

    assert out["current_agent"] == "fuzzer"
    assert not out.get("errors"), out.get("errors")
    assert out.get("web_findings"), out
    assert out["agent_log"]
