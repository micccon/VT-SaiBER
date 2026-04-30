from __future__ import annotations

import pytest

from src.agents.striker.agent import StrikerAgent
from src.agents.striker.context import build_striker_context
from scripts.tests.helpers import captured_automotive_state, require_live_mcp, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_striker_live_manual_approval_can_attempt_exploit():
    require_live_mcp()
    step(f"Running striker live manual-approval exploit attempt: {runtime_summary()}")

    state = captured_automotive_state(mission_id="live-striker")
    state["mission_goal"] = (
        "Attempt exactly one evidence-backed exploitation path against the seeded automotive target. "
        "Use safe reconnaissance/search first if needed, then call the chosen approval-gated tool so "
        "the runtime can ask the human operator for manual approval. Do not finish by merely saying "
        "approval is needed. After any Metasploit execution attempt, call msf_list_sessions."
    )

    agent = StrikerAgent()
    agent.require_confirmation = True
    context_preview = build_striker_context(state)
    print(f"[live] STRIKER_CONTEXT:\n{context_preview[:20000]}", flush=True)

    out = await agent.run(state)

    assert out["current_agent"] == "striker"
    assert out["agent_log"]

    entry = out["agent_log"][0]
    log = entry.model_dump() if hasattr(entry, "model_dump") else dict(entry)
    findings = log.get("findings") or {}
    status = findings.get("status")
    selected_tool = findings.get("selected_tool")

    attempted_with_evidence = bool(out.get("artifacts")) or status in {
        "approval_blocked",
        "validated_no_session",
        "session_opened",
        "execution_error",
    }
    assert status in {
        "no_candidate",
        "approval_blocked",
        "validated_no_session",
        "session_opened",
        "execution_error",
    }, f"Striker did not reach an execution/approval path. Findings: {findings}"
    assert attempted_with_evidence, (
        "Striker did not produce runtime evidence that an approval-gated path was attempted. "
        f"Findings: {findings}"
    )
    if selected_tool:
        assert selected_tool in {
            "msf_run_exploit",
            "msf_run_auxiliary",
            "web_sqlmap_scan",
            "access_hydra_attack",
            "system_execute_command",
        }, f"Striker selected an unexpected execution tool. Findings: {findings}"

    if status == "approval_blocked":
        assert not out.get("active_sessions"), "Approval-blocked runs must not open sessions"
    if out.get("active_sessions"):
        assert status == "session_opened"
