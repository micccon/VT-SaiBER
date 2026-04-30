from __future__ import annotations

import pytest

from src.v2.agents.striker.agent import StrikerV2Agent
from tests.v2_live.helpers import captured_automotive_state, require_live_mcp, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_striker_v2_live_manual_approval_can_attempt_exploit():
    require_live_mcp()
    step(f"Running striker_v2 live manual-approval exploit attempt: {runtime_summary()}")

    state = captured_automotive_state(mission_id="v2-live-striker")
    state["mission_goal"] = (
        "Attempt exactly one evidence-backed exploitation path against the seeded automotive target. "
        "Use safe reconnaissance/search first if needed, then request manual approval before any exploit "
        "or high-impact action. After any Metasploit execution attempt, call msf_list_sessions."
    )

    agent = StrikerV2Agent()
    agent.require_confirmation = True

    out = await agent.run(state)

    assert out["current_agent"] == "striker_v2"
    assert out["agent_log"]

    entry = out["agent_log"][0]
    log = entry.model_dump() if hasattr(entry, "model_dump") else dict(entry)
    findings = log.get("findings") or {}
    status = findings.get("status")
    selected_tool = findings.get("selected_tool")

    assert status in {
        "approval_blocked",
        "validated_no_session",
        "session_opened",
        "execution_error",
    }, f"Striker did not reach an execution/approval path. Findings: {findings}"
    assert selected_tool in {
        "msf_run_exploit",
        "msf_run_auxiliary",
        "web_sqlmap_scan",
        "access_hydra_attack",
        "system_execute_command",
    }, f"Striker did not select an approval-gated execution tool. Findings: {findings}"

    if status == "approval_blocked":
        assert not out.get("active_sessions"), "Approval-blocked runs must not open sessions"
    if out.get("active_sessions"):
        assert status == "session_opened"
