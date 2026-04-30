"""Lean CyberState mapping for resident execution results."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from src.state.cyber_state import CyberState
from src.state.models import AgentLogEntry
from src.agents.resident.constants import RESIDENT_OBJECTIVE_STATUSES
from src.agents.resident.context import resolve_objective
from src.agents.resident.outcome import ResidentOutcome
from src.runtime.contracts import ExecutionResult, ToolEvent


def _verified_sessions(tool_events: list[ToolEvent]) -> dict[str, Any]:
    """Read authoritative live session data from `msf_list_sessions` results."""

    verified: dict[str, Any] = {}
    for event in tool_events:
        if event.tool_name != "msf_list_sessions":
            continue
        if str(event.result.get("status", "")).lower() != "success":
            continue
        sessions = event.result.get("sessions")
        if not isinstance(sessions, dict):
            evidence = event.result.get("evidence")
            if isinstance(evidence, dict) and isinstance(evidence.get("sessions"), dict):
                sessions = evidence.get("sessions")
        if isinstance(sessions, dict):
            verified = sessions
    return verified


def _approval_blocked(result: ExecutionResult[ResidentOutcome]) -> bool:
    """Detect resident approval blocking from approvals or intercepted tool events."""

    if any(not approval.approved for approval in result.approval_events):
        return True
    for event in result.tool_events:
        if str(event.result.get("objective_status", "")).lower() == "needs_approval":
            return True
        if str(event.status).lower() in {"aborted", "blocked"} and "approval" in str(event.result.get("message", "")).lower():
            return True
    return False


def _effective_status(
    outcome: ResidentOutcome,
    result: ExecutionResult[ResidentOutcome],
    *,
    live_sessions: dict[str, Any],
) -> str:
    """Use the model status unless hard verification contradicts it."""

    if _approval_blocked(result):
        return "needs_approval"
    if not live_sessions:
        return "failed"
    candidate = str(outcome.objective_status or "").strip().lower()
    if candidate in RESIDENT_OBJECTIVE_STATUSES:
        return candidate
    return "in_progress"


def _resolve_target(
    state: CyberState,
    *,
    session_id: str,
    live_sessions: dict[str, Any],
) -> str | None:
    """Map a session id back to the best target key for logging and state updates."""

    active_sessions = state.get("active_sessions", {}) or {}
    for target, info in active_sessions.items():
        if str((info or {}).get("session_id", "")) == session_id:
            return str(target)
    live_payload = live_sessions.get(session_id)
    if isinstance(live_payload, dict):
        target = str(
            live_payload.get("target_host")
            or live_payload.get("tunnel_peer")
            or live_payload.get("session_host")
            or ""
        ).strip()
        if target:
            return target
    return next(iter(active_sessions.keys()), None)


def _normalize_list(values: list[str], *, fallback: str | None = None) -> list[str]:
    """Normalize summary lists to non-empty strings."""

    normalized = [str(value).strip() for value in values if str(value).strip()]
    if normalized:
        return normalized
    return [fallback] if fallback else []


def map_execution_result_to_state(
    state: CyberState,
    *,
    agent_name: str,
    context: str,
    result: ExecutionResult[ResidentOutcome],
) -> dict[str, Any]:
    """Convert a resident execution result into compact CyberState updates."""

    outcome = result.outcome
    objective = str(outcome.objective or "").strip() or resolve_objective(state)
    live_sessions = _verified_sessions(result.tool_events)
    session_id = str(outcome.session_id or "").strip()
    if not session_id and live_sessions:
        session_id = next(iter(live_sessions.keys()))
    status = _effective_status(outcome, result, live_sessions=live_sessions)
    target = _resolve_target(state, session_id=session_id, live_sessions=live_sessions)
    actions_taken = _normalize_list(outcome.actions_taken)
    evidence_summary = _normalize_list(
        outcome.evidence_summary,
        fallback=(
            "Next bounded action requires human approval."
            if status == "needs_approval"
            else "No validated live session remained after session validation."
            if status == "failed"
            else "Resident could not validate clear objective progress from the current step."
            if status == "blocked"
            else None
        ),
    )

    findings = {
        "objective": objective,
        "objective_status": status,
        "session_id": session_id or None,
        "actions_taken": actions_taken,
        "evidence_summary": evidence_summary,
        "live_session_count": len(live_sessions),
    }

    validation = {
        "type": "resident_objective",
        "status": status,
        "objective_status": status,
        "objective": objective,
        "session_id": session_id or None,
        "actions_taken": actions_taken,
        "evidence_summary": evidence_summary,
        "live_session_count": len(live_sessions),
    }

    updates: dict[str, Any] = {
        "current_agent": agent_name,
        "iteration_count": int(state.get("iteration_count", 0)) + 1,
        "agent_log": [
            AgentLogEntry(
                agent=agent_name,
                action="objective_worker",
                target=target,
                findings=findings,
                reasoning="\n\n".join(evidence_summary) or context,
            )
        ],
        "validations": [validation],
    }

    live_target_sessions: dict[str, dict[str, Any]] = {}
    active_sessions = state.get("active_sessions", {}) or {}
    for session_target, info in active_sessions.items():
        info_session_id = str((info or {}).get("session_id", ""))
        if info_session_id not in live_sessions:
            continue
        live_payload = live_sessions.get(info_session_id, {})
        live_target_sessions[str(session_target)] = {
            **info,
            **(live_payload if isinstance(live_payload, dict) else {}),
            "objective": objective,
            "resident_objective_status": status,
            "resident_actions_taken": actions_taken,
            "resident_evidence_summary": evidence_summary,
            "resident_validated_at": datetime.now().isoformat(),
        }
    updates["active_sessions"] = live_target_sessions

    if status == "completed":
        updates["critical_findings"] = [f"Resident completed objective: {objective}"]
    elif status == "needs_approval":
        updates["critical_findings"] = [f"Resident needs approval to continue objective: {objective}"]

    return updates
