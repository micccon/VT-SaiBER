from __future__ import annotations

import asyncio
from typing import Any

import pytest

import src.agents.striker_v2 as striker_v2_mod
from src.v2.agents.striker.outcome import ArtifactClaim, SessionClaim, StrikerOutcome
from src.v2.agents.striker.policy import StrikerExecutionPolicy
from src.v2.contracts.execution import ApprovalEvent, ExecutionResult, ToolEvent, ToolSpec


class _FakeExecutionRunner:
    def __init__(self, result: ExecutionResult[StrikerOutcome]):
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
        "mission_goal": "Exploit target and gain initial access",
        "mission_id": "test-mission",
        "mission_status": "active",
        "current_agent": "supervisor",
        "next_agent": None,
        "iteration_count": 0,
        "target_scope": ["192.168.1.10"],
        "discovered_targets": {},
        "ot_discovery": {},
        "web_findings": [],
        "active_sessions": {},
        "exploited_services": [],
        "credential_findings": [],
        "exploit_attempts": [],
        "protocol_observations": [],
        "fuzzing_runs": [],
        "crash_indicators": [],
        "artifacts": [],
        "validations": [],
        "research_cache": {},
        "intelligence_findings": [],
        "supervisor_messages": [],
        "supervisor_expectations": {},
        "agent_log": [],
        "critical_findings": [],
        "errors": [],
    }


def _build_state() -> dict[str, Any]:
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "services": {"80": {"service_name": "http", "version": "Werkzeug 3.1.8"}},
        }
    }
    return state


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


def _run(coro):
    return asyncio.run(coro)


def test_striker_v2_exposes_run_entrypoint():
    agent = striker_v2_mod.StrikerV2Agent(
        execution_runner=_FakeExecutionRunner(
            ExecutionResult(outcome=StrikerOutcome(status="no_candidate"))
        )
    )
    assert hasattr(agent, "run")


@pytest.mark.asyncio
async def test_striker_v2_returns_validation_error_without_targets():
    agent = striker_v2_mod.StrikerV2Agent(
        execution_runner=_FakeExecutionRunner(
            ExecutionResult(outcome=StrikerOutcome(status="no_candidate"))
        )
    )
    state = _base_state()

    out = await agent.run(state)
    assert out["errors"][0].error_type == "ValidationError"
    assert out["errors"][0].recoverable is True
    assert out["current_agent"] == "striker_v2"


@pytest.mark.asyncio
async def test_striker_v2_preserves_model_status_by_default():
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=StrikerOutcome(
                status="execution_error",
                target="192.168.1.10",
                selected_tool="msf_run_exploit",
                selected_module="multi/http/werkzeug_debug_rce",
                attempt_summary="The exploit path failed cleanly.",
                operator_summary="No access was obtained.",
            ),
            tool_events=[
                _tool_event(
                    "msf_run_exploit",
                    {"status": "error", "message": "exploit failed"},
                    invocation={
                        "module_name": "multi/http/werkzeug_debug_rce",
                        "options": {"RHOSTS": "192.168.1.10", "RPORT": 80},
                    },
                )
            ],
        )
    )
    result = await striker_v2_mod.StrikerV2Agent(execution_runner=runner).run(_build_state())

    findings = result["agent_log"][0].findings
    assert findings == {
        "status": "execution_error",
        "target": "192.168.1.10",
        "selected_tool": "msf_run_exploit",
        "selected_module": "multi/http/werkzeug_debug_rce",
        "session_opened": False,
        "verified_session_ids": [],
        "stop_reason": "The exploit path failed cleanly.",
    }
    assert result["exploit_attempts"][0]["status"] == "execution_error"
    assert result["exploited_services"][0]["selected_tool"] == "msf_run_exploit"


@pytest.mark.asyncio
async def test_striker_v2_approval_blocked_overrides_model_claim():
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=StrikerOutcome(
                status="session_opened",
                target="192.168.1.10",
                selected_tool="msf_run_exploit",
                selected_module="multi/http/werkzeug_debug_rce",
                stop_reason="Execution blocked pending manual approval.",
                operator_summary="Approval prevented exploitation.",
            ),
            approval_events=[
                ApprovalEvent(
                    tool_name="msf_run_exploit",
                    approved=False,
                    reason="approval_rejected",
                    server_name="attackbox",
                )
            ],
        )
    )

    result = await striker_v2_mod.StrikerV2Agent(execution_runner=runner).run(_build_state())
    findings = result["agent_log"][0].findings
    assert findings["status"] == "approval_blocked"
    assert result["exploit_attempts"][0]["status"] == "approval_blocked"


@pytest.mark.asyncio
async def test_striker_v2_session_opened_requires_verified_session_evidence():
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=StrikerOutcome(
                status="session_opened",
                target="192.168.1.10",
                selected_path_type="exploit",
                selected_tool="msf_run_exploit",
                selected_module="multi/http/apache_demo",
                session_claim=SessionClaim(session_id=7, target="192.168.1.10"),
                attempt_summary="Exploit claimed a session but verification never confirmed it.",
                operator_summary="Access claim was not verified.",
            ),
            tool_events=[
                _tool_event(
                    "msf_run_exploit",
                    {
                        "status": "success",
                        "module": "multi/http/apache_demo",
                        "session_id": 7,
                    },
                    invocation={
                        "module_name": "multi/http/apache_demo",
                        "options": {"RHOSTS": "192.168.1.10", "RPORT": 80},
                    },
                )
            ],
        )
    )

    result = await striker_v2_mod.StrikerV2Agent(execution_runner=runner).run(_build_state())
    findings = result["agent_log"][0].findings
    assert findings["status"] == "validated_no_session"
    assert findings["session_opened"] is False
    assert result.get("active_sessions") is None or result.get("active_sessions") == {}


@pytest.mark.asyncio
async def test_striker_v2_verified_session_updates_machine_state():
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=StrikerOutcome(
                status="session_opened",
                target="192.168.1.10",
                selected_path_type="exploit",
                selected_tool="msf_run_exploit",
                selected_module="multi/http/apache_demo",
                session_claim=SessionClaim(session_id=7, target="192.168.1.10"),
                attempt_summary="Exploit returned a session and session listing confirmed it.",
                operator_summary="Initial access established.",
            ),
            tool_events=[
                _tool_event(
                    "msf_list_sessions",
                    {"status": "success", "sessions": {"7": {"target_host": "192.168.1.10"}}},
                ),
            ],
        )
    )

    result = await striker_v2_mod.StrikerV2Agent(execution_runner=runner).run(_build_state())
    findings = result["agent_log"][0].findings
    assert findings["status"] == "session_opened"
    assert findings["verified_session_ids"] == ["7"]
    assert result["active_sessions"]["192.168.1.10"]["session_id"] == 7
    assert result["critical_findings"]


@pytest.mark.asyncio
async def test_striker_v2_only_persists_verified_artifacts():
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=StrikerOutcome(
                status="validated_no_session",
                target="192.168.1.10",
                selected_tool="web_sqlmap_scan",
                artifact_claims=[ArtifactClaim(name="sqlmap_report.txt", source_tool="web_sqlmap_scan")],
                attempt_summary="Validation created a report artifact.",
                operator_summary="Artifacts captured successfully.",
            ),
            artifacts=[{"name": "sqlmap_report.txt", "path": "/tmp/sqlmap_report.txt"}],
        )
    )

    result = await striker_v2_mod.StrikerV2Agent(execution_runner=runner).run(_build_state())
    assert result["artifacts"] == [{"name": "sqlmap_report.txt", "path": "/tmp/sqlmap_report.txt"}]
    assert result["agent_log"][0].findings["status"] == "validated_no_session"


@pytest.mark.asyncio
async def test_striker_v2_writes_compact_machine_state_for_supervisor_and_resident():
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=StrikerOutcome(
                status="validated_no_session",
                target="192.168.1.10",
                service="ssh",
                port=22,
                selected_tool="access_hydra_attack",
                attempt_summary="Validated a credential path without session creation.",
                operator_summary="Fallback validation succeeded.",
            ),
        )
    )

    result = await striker_v2_mod.StrikerV2Agent(execution_runner=runner).run(_build_state())
    findings = result["agent_log"][0].findings

    assert "agent_log" in result and result["agent_log"]
    assert "exploit_attempts" in result and result["exploit_attempts"]
    assert "exploited_services" in result and result["exploited_services"]
    assert "critical_findings" in result and result["critical_findings"]
    assert findings.keys() == {
        "status",
        "target",
        "selected_tool",
        "session_opened",
        "verified_session_ids",
        "stop_reason",
        "service",
        "port",
    }


def test_striker_policy_only_gates_approval_required_tools(monkeypatch):
    approval_calls: list[dict[str, Any]] = []

    def fake_require_manual_approval(**kwargs):
        approval_calls.append(dict(kwargs))
        return False

    monkeypatch.setattr("src.v2.agents.striker.policy.require_manual_approval", fake_require_manual_approval)
    policy = StrikerExecutionPolicy(require_confirmation=True, max_attempts=3)

    allowed = _run(
        policy.approve_tool_call(
            ToolSpec(
                name="msf_search_modules",
                description="",
                input_schema={},
                executor=lambda **kwargs: None,  # pragma: no cover - not executed
                source="mcp",
                approval_required=False,
            ),
            {"search_term": "werkzeug"},
        )
    )
    blocked = _run(
        policy.approve_tool_call(
            ToolSpec(
                name="msf_run_exploit",
                description="",
                input_schema={},
                executor=lambda **kwargs: None,  # pragma: no cover - not executed
                source="mcp",
                approval_required=True,
            ),
            {"module_name": "multi/http/demo", "options": {"RHOSTS": "192.168.1.10"}},
        )
    )

    assert allowed is True
    assert blocked is False
    assert approval_calls[0]["tool_name"] == "msf_run_exploit"
