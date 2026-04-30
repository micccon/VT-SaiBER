"""Lean CyberState mapping for Striker execution results."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from src.state.cyber_state import CyberState
from src.state.models import AgentLogEntry
from src.agents.striker.outcome import StrikerOutcome
from src.runtime.contracts import ExecutionResult, ToolEvent


def _verified_session_ids(tool_events: list[ToolEvent]) -> dict[str, Any]:
    """Read verified session ids from authoritative `msf_list_sessions` results."""

    verified: dict[str, Any] = {}
    for event in tool_events:
        if event.tool_name != "msf_list_sessions":
            continue
        if str(event.result.get("status", "")).lower() != "success":
            continue
        sessions = event.result.get("sessions")
        if isinstance(sessions, dict):
            verified = sessions
    return verified


def _default_target(state: CyberState, outcome: StrikerOutcome) -> str:
    """Resolve the best-effort default target for compact state updates."""

    discovered_targets = state.get("discovered_targets", {}) or {}
    if outcome.target:
        return str(outcome.target)
    return next(iter(discovered_targets.keys()), "unknown")


def _effective_status(
    outcome: StrikerOutcome,
    result: ExecutionResult[StrikerOutcome],
    *,
    session_opened: bool,
) -> str:
    """Use model-first status, overridden only by hard verifiers."""

    if any(not approval.approved for approval in result.approval_events):
        return "approval_blocked"
    if outcome.status == "approval_blocked":
        return "no_candidate"
    if outcome.status == "session_opened" and not session_opened:
        return "validated_no_session"
    return outcome.status


def _agent_reasoning(outcome: StrikerOutcome) -> str:
    """Build a concise reasoning string for the audit log."""

    parts = [
        str(outcome.operator_summary or "").strip(),
        str(outcome.attempt_summary or "").strip(),
        str(outcome.stop_reason or "").strip(),
    ]
    return "\n\n".join(part for part in parts if part).strip()


def _compact_attempt_record(
    *,
    target: str,
    outcome: StrikerOutcome,
    status: str,
    session_id: str | int | None,
) -> dict[str, Any]:
    """Persist one concise Striker attempt for supervisor reasoning."""

    module = outcome.selected_module or outcome.selected_tool or "unknown"
    return {
        "target": target,
        "module": module,
        "selected_tool": outcome.selected_tool,
        "status": status,
        "session_id": session_id,
        "summary": outcome.stop_reason or outcome.attempt_summary or outcome.operator_summary or "striker execution",
    }


def map_execution_result_to_state(
    state: CyberState,
    *,
    agent_name: str,
    context: str,
    result: ExecutionResult[StrikerOutcome],
) -> dict[str, Any]:
    """Convert a Striker execution result into lean CyberState updates."""

    outcome = result.outcome
    target = _default_target(state, outcome)
    verified_sessions = _verified_session_ids(result.tool_events)
    claimed_session_id = outcome.session_claim.session_id if outcome.session_claim else None
    session_opened = bool(claimed_session_id is not None and str(claimed_session_id) in verified_sessions)
    status = _effective_status(outcome, result, session_opened=session_opened)
    artifacts = [artifact for artifact in result.artifacts if isinstance(artifact, dict)]
    reasoning = _agent_reasoning(outcome) or context

    findings: dict[str, Any] = {
        "status": status,
        "target": target,
        "selected_tool": outcome.selected_tool,
        "session_opened": session_opened,
        "verified_session_ids": sorted(str(key) for key in verified_sessions),
        "stop_reason": outcome.stop_reason or outcome.attempt_summary or outcome.operator_summary or "",
    }
    if outcome.selected_module:
        findings["selected_module"] = outcome.selected_module
    if outcome.service:
        findings["service"] = outcome.service
    if outcome.port is not None:
        findings["port"] = outcome.port

    updates: dict[str, Any] = {
        "current_agent": agent_name,
        "iteration_count": int(state.get("iteration_count", 0)) + 1,
        "agent_log": [
            AgentLogEntry(
                agent=agent_name,
                action="run_exploit",
                target=target,
                findings=findings,
                reasoning=reasoning,
            )
        ],
    }

    if outcome.selected_tool:
        attempt_record = _compact_attempt_record(
            target=target,
            outcome=outcome,
            status=status,
            session_id=claimed_session_id if session_opened else None,
        )
        updates["exploited_services"] = [*state.get("exploited_services", []), attempt_record]
        updates["exploit_attempts"] = [attempt_record]

    if session_opened and claimed_session_id is not None:
        updates["active_sessions"] = {
            **state.get("active_sessions", {}),
            target: {
                "session_id": claimed_session_id,
                "module": outcome.selected_module or outcome.selected_tool or "unknown",
                "established_at": datetime.now().isoformat(),
            },
        }
        updates["critical_findings"] = [
            f"Session {claimed_session_id} opened on {target} via {outcome.selected_module or outcome.selected_tool or 'unknown'}"
        ]
    elif status == "validated_no_session" and outcome.selected_tool:
        updates["critical_findings"] = [
            f"Striker validated a fallback path on {target} via {outcome.selected_tool} without opening a session"
        ]

    if artifacts:
        updates["artifacts"] = artifacts
    return updates
