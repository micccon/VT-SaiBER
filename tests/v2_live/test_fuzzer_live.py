from __future__ import annotations

import pytest

from src.v2.agents.fuzzer.agent import FuzzerV2Agent
from tests.v2_live.helpers import discovered_http_state, fuzzer_base_url, require_live_mcp, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_fuzzer_v2_live_enumerates_configured_web_target():
    require_live_mcp()
    base_url = fuzzer_base_url()
    step(f"Running fuzzer_v2 live web enumeration against {base_url}: {runtime_summary()}")

    out = await FuzzerV2Agent().run(discovered_http_state(base_url))

    assert out["current_agent"] == "fuzzer_v2"
    assert not out.get("errors"), out.get("errors")
    assert out.get("web_findings"), out
    assert out["agent_log"]
