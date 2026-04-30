"""Context-building helpers for supervisor."""

from __future__ import annotations

from typing import Any

from src.state.cyber_state import CyberState
from src.core.agent_parsers import iter_target_services
from src.core.validators import has_agent_run, has_service_version_intel, list_recent_agent_names


def latest_resident_outcome(state: CyberState) -> dict[str, Any]:
    """Read the latest resident objective outcome from validations or agent log."""

    for validation in reversed(state.get("validations", []) or []):
        if isinstance(validation, dict) and validation.get("type") == "resident_objective":
            payload = dict(validation)
            if not payload.get("objective_status") and payload.get("status"):
                payload["objective_status"] = payload.get("status")
            return payload
    for entry in reversed(state.get("agent_log", []) or []):
        if isinstance(entry, dict):
            agent_name = str(entry.get("agent", "")).strip().lower()
            findings = entry.get("findings")
        else:
            agent_name = str(getattr(entry, "agent", "")).strip().lower()
            findings = getattr(entry, "findings", None)
        if agent_name not in {"resident", "resident"}:
            continue
        if isinstance(findings, dict) and findings.get("objective_status"):
            return dict(findings)
    return {}


def has_any_services(discovered_targets: dict[str, dict[str, Any]]) -> bool:
    """Return True when at least one concrete service or port is known."""

    for target_data in (discovered_targets or {}).values():
        if not isinstance(target_data, dict):
            continue
        if target_data.get("ports") or target_data.get("services"):
            return True
    return False


def has_http_service(discovered_targets: dict[str, dict[str, Any]]) -> bool:
    """Return True only when a likely HTTP attack surface exists."""

    http_names = {"http", "https", "http-proxy"}
    for _ip, port, name in iter_target_services(discovered_targets or {}):
        if name in http_names or int(port) in {80, 443, 8000, 8080, 8443}:
            return True
    return False


def has_librarian_research(state: CyberState) -> bool:
    """Return True when librarian research is already present in state."""

    agent_log = state.get("agent_log", []) or []
    return bool(
        has_agent_run(agent_log, "librarian")
        or has_agent_run(agent_log, "librarian")
        or (state.get("research_cache", {}) or {})
        or (state.get("intelligence_findings", []) or [])
    )


def striker_failed_recently(state: CyberState) -> bool:
    """Detect whether the latest exploitation path failed without a session."""

    for record in reversed(state.get("exploited_services", []) or []):
        if not isinstance(record, dict):
            continue
        status = str(record.get("status", "")).strip().lower()
        if status:
            return status not in {"success", "succeeded", "opened"}
    recent_agents = [
        name
        for name in list_recent_agent_names(state.get("agent_log", []) or [], n=5)
        if name not in {"supervisor", "supervisor"}
    ]
    return bool(recent_agents and recent_agents[-1] in {"striker", "striker"} and not (state.get("active_sessions", {}) or {}))


def summarize_targets(discovered_targets: dict[str, dict[str, Any]]) -> str:
    """Render a compact discovered-target block for supervisor prompting."""

    lines: list[str] = []
    for ip, details in list((discovered_targets or {}).items())[:8]:
        service_items: list[str] = []
        service_map = details.get("services", {}) if isinstance(details, dict) else {}
        for port, service in list((service_map or {}).items())[:6]:
            if isinstance(service, dict):
                name = str(service.get("service_name") or "unknown")
                version = str(service.get("version") or "").strip()
                label = f"{port}:{name}"
                if version:
                    label += f" {version}"
            else:
                label = f"{port}:{service}"
            service_items.append(label)
        if not service_items:
            ports = ", ".join(str(port) for port in (details.get("ports", []) if isinstance(details, dict) else [])[:6]) or "no ports"
            lines.append(f"- {ip} -> {ports}")
        else:
            lines.append(f"- {ip} -> {', '.join(service_items)}")
    return "\n".join(lines) or "- none"


def mission_phase_hint(state: CyberState) -> str:
    """Return a compact phase hint for the model and fallback path."""

    discovered_targets = state.get("discovered_targets", {}) or {}
    active_sessions = state.get("active_sessions", {}) or {}
    web_findings = state.get("web_findings", []) or []
    resident = latest_resident_outcome(state)
    resident_status = str(resident.get("objective_status", "")).strip().lower()

    if resident_status == "completed":
        return "complete"
    if resident_status == "needs_approval":
        return "needs_approval"
    if active_sessions:
        return "session_active"
    if not discovered_targets:
        return "recon"
    if has_http_service(discovered_targets) and not web_findings:
        return "web_enum"
    if not has_librarian_research(state):
        return "research"
    if striker_failed_recently(state):
        return "backtrack"
    return "exploit"


def build_supervisor_context(state: CyberState) -> str:
    """Summarize the current mission state into a routing prompt."""

    discovered_targets = state.get("discovered_targets", {}) or {}
    active_sessions = state.get("active_sessions", {}) or {}
    web_findings = state.get("web_findings", []) or []
    resident = latest_resident_outcome(state)
    recent_agents = list_recent_agent_names(state.get("agent_log", []) or [], n=6)
    research_present = has_librarian_research(state)

    return (
        f"Mission goal: {state.get('mission_goal', '(unknown)')}\n"
        f"Mission status: {state.get('mission_status', 'active')}\n"
        f"Iteration: {state.get('iteration_count', 0)}\n"
        f"Target scope: {state.get('target_scope', [])}\n"
        f"Mission phase hint: {mission_phase_hint(state)}\n"
        f"Research available: {research_present}\n"
        f"Service versions known: {has_service_version_intel(discovered_targets)}\n"
        f"HTTP surface present: {has_http_service(discovered_targets)}\n"
        f"Web findings count: {len(web_findings)}\n"
        f"Active session count: {len(active_sessions)}\n"
        f"Resident objective status: {resident.get('objective_status', 'none')}\n"
        f"Resident objective: {resident.get('objective', '(none)')}\n"
        f"Recent agents: {recent_agents}\n\n"
        f"Discovered targets:\n{summarize_targets(discovered_targets)}\n"
    )


def sanitize_history(state: CyberState) -> list[dict[str, str]]:
    """Keep only clean user/assistant supervisor history entries."""

    clean: list[dict[str, str]] = []
    for message in state.get("supervisor_messages", []) or []:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role", "")).strip().lower()
        if role not in {"user", "assistant"}:
            continue
        clean.append({"role": role, "content": str(message.get("content", ""))})
    return clean
