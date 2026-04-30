from __future__ import annotations

from typing import Any

import pytest

from src.v2.agents.resident.agent import ResidentV2Agent
from src.v2.agents.resident.context import build_resident_context
from src.v2.agents.resident.outcome import ResidentOutcome
from src.v2.contracts.execution import ExecutionResult, ToolEvent


class _FakeExecutionRunner:
    def __init__(self, result: ExecutionResult[ResidentOutcome]):
        self.result = result
        self.last_spec = None
        self.last_input = None
        self.last_context = None
        self.last_policy = None

    async def run(self, spec, *, user_input: str, context=None, policy=None):
        self.last_spec = spec
        self.last_input = user_input
        self.last_context = context
        self.last_policy = policy
        return self.result


def _base_state() -> dict[str, Any]:
    return {
        "mission_goal": "Use the live session to validate access on the automotive testbed",
        "mission_id": "test-resident-v2",
        "mission_status": "active",
        "current_agent": "supervisor",
        "next_agent": None,
        "iteration_count": 4,
        "target_scope": ["automotive-testbed"],
        "discovered_targets": {
            "automotive-testbed": {
                "services": {
                    "22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"},
                    "8000": {"service_name": "http", "version": "Python/3.8"},
                }
            }
        },
        "ot_discovery": {},
        "web_findings": [],
        "active_sessions": {
            "automotive-testbed": {
                "session_id": 7,
                "module": "auxiliary/scanner/ssh/ssh_login",
                "established_at": "2026-01-15T10:30:00",
            }
        },
        "exploited_services": [],
        "credential_findings": [],
        "exploit_attempts": [],
        "protocol_observations": [],
        "fuzzing_runs": [],
        "crash_indicators": [],
        "artifacts": [],
        "validations": [],
        "research_cache": {"ssh privesc": "Check sudo -l and SUID binaries"},
        "intelligence_findings": [{"cve": "CVE-2021-4034", "description": "Polkit pkexec local privesc"}],
        "supervisor_messages": [],
        "supervisor_expectations": {"specific_goal": "Verify whether the existing session can enumerate sudo rights."},
        "agent_log": [],
        "critical_findings": [],
        "errors": [],
    }


def _tool_event(
    name: str,
    result: dict[str, Any],
    *,
    invocation: dict[str, Any] | None = None,
    status: str | None = None,
) -> ToolEvent:
    payload = dict(result)
    payload.setdefault("invocation", invocation or {})
    return ToolEvent(
        tool_name=name,
        invocation=invocation or {},
        source="mcp",
        server_name="attackbox",
        approval_required=False,
        approved=True,
        result=payload,
        status=status or str(payload.get("status", "success")),
    )


def test_build_resident_context_includes_core_sections():
    context = build_resident_context(_base_state())

    assert "MISSION GOAL:" in context
    assert "IMMEDIATE OBJECTIVE:" in context
    assert "ACTIVE SESSIONS:" in context
    assert "session_id=7" in context
    assert "RESEARCH & INTELLIGENCE:" in context


def test_resident_v2_exposes_run_entrypoint():
    agent = ResidentV2Agent(
        execution_runner=_FakeExecutionRunner(
            ExecutionResult(
                outcome=ResidentOutcome(
                    objective="Verify session",
                    objective_status="in_progress",
                )
            )
        )
    )
    assert hasattr(agent, "run")


@pytest.mark.asyncio
async def test_resident_v2_returns_validation_error_without_sessions():
    state = _base_state()
    state["active_sessions"] = {}

    out = await ResidentV2Agent(
        execution_runner=_FakeExecutionRunner(
            ExecutionResult(
                outcome=ResidentOutcome(
                    objective="Verify session",
                    objective_status="in_progress",
                )
            )
        )
    ).run(state)

    assert out["errors"][0].error_type == "ValidationError"
    assert out["current_agent"] == "resident_v2"


@pytest.mark.asyncio
async def test_resident_v2_stale_session_fails_and_clears_active_sessions_update():
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=ResidentOutcome(
                objective="Verify session",
                objective_status="completed",
                session_id="7",
                actions_taken=["whoami"],
                evidence_summary=["Session was expected to be alive."],
            ),
            tool_events=[
                _tool_event("msf_list_sessions", {"status": "success", "sessions": {}}),
            ],
        )
    )

    out = await ResidentV2Agent(execution_runner=runner).run(_base_state())
    assert out["validations"][0]["objective_status"] == "failed"
    assert out["active_sessions"] == {}
    assert out["agent_log"][0].findings["live_session_count"] == 0


@pytest.mark.asyncio
async def test_resident_v2_approval_blocked_overrides_model_outcome():
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=ResidentOutcome(
                objective="Modify the host firewall",
                objective_status="completed",
                session_id="7",
                actions_taken=["iptables -L"],
                evidence_summary=["A command was selected."],
            ),
            tool_events=[
                _tool_event("msf_list_sessions", {"status": "success", "sessions": {"7": {"type": "shell"}}}),
                _tool_event(
                    "msf_session_command",
                    {
                        "status": "aborted",
                        "objective_status": "needs_approval",
                        "message": "Execution blocked pending manual approval.",
                    },
                    invocation={"session_id": 7, "command": "iptables -L"},
                    status="aborted",
                ),
            ],
        )
    )

    out = await ResidentV2Agent(execution_runner=runner).run(_base_state())
    assert out["validations"][0]["objective_status"] == "needs_approval"
    assert "needs approval" in out["critical_findings"][0].lower()


@pytest.mark.asyncio
async def test_resident_v2_verified_in_progress_updates_machine_state():
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=ResidentOutcome(
                objective="Verify sudo rights",
                objective_status="in_progress",
                session_id="7",
                actions_taken=["whoami", "sudo -l"],
                evidence_summary=["The session is still live.", "sudo requires a password."],
            ),
            tool_events=[
                _tool_event(
                    "msf_list_sessions",
                    {"status": "success", "sessions": {"7": {"type": "shell", "info": "test shell"}}},
                ),
            ],
        )
    )

    out = await ResidentV2Agent(execution_runner=runner).run(_base_state())
    session = out["active_sessions"]["automotive-testbed"]
    assert out["validations"][0]["objective_status"] == "in_progress"
    assert session["resident_objective_status"] == "in_progress"
    assert session["resident_actions_taken"] == ["whoami", "sudo -l"]


@pytest.mark.asyncio
async def test_resident_v2_verified_completed_adds_critical_finding():
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=ResidentOutcome(
                objective="Validate root access",
                objective_status="completed",
                session_id="7",
                actions_taken=["id"],
                evidence_summary=["Root access was confirmed."],
            ),
            tool_events=[
                _tool_event(
                    "msf_list_sessions",
                    {"status": "success", "sessions": {"7": {"type": "shell", "info": "root shell"}}},
                ),
            ],
        )
    )

    out = await ResidentV2Agent(execution_runner=runner).run(_base_state())
    assert out["validations"][0]["objective_status"] == "completed"
    assert "completed objective" in out["critical_findings"][0].lower()


@pytest.mark.asyncio
async def test_resident_v2_blocked_with_live_session_keeps_session_context():
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=ResidentOutcome(
                objective="Investigate a possible escalation path",
                objective_status="blocked",
                session_id="7",
                actions_taken=["find / -perm -4000"],
                evidence_summary=["No actionable escalation path was confirmed."],
            ),
            tool_events=[
                _tool_event(
                    "msf_list_sessions",
                    {"status": "success", "sessions": {"7": {"type": "shell"}}},
                ),
            ],
        )
    )

    out = await ResidentV2Agent(execution_runner=runner).run(_base_state())
    assert out["validations"][0]["objective_status"] == "blocked"
    assert out["active_sessions"]["automotive-testbed"]["resident_objective_status"] == "blocked"
