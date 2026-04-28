"""
Database persistence hooks for runtime CyberState updates.

These helpers keep the operational database in sync with agent outputs without
forcing each agent to hand-write SQL. Persistence failures are intentionally
best-effort so the orchestrator can keep running.
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Dict, Iterable, List
from urllib.parse import urlparse

from src.database.activity_repository import (
    agent_log_exists_by_persistence_key,
    create_agent_log,
)
from src.database.attack_chain_repository import (
    create_attack_chain_step,
)
from src.database.findings_store import (
    create_finding,
    finding_exists_by_persistence_key,
)
from src.database.sessions_repository import (
    sync_sessions_for_mission,
)
from src.database.targets_repository import (
    replace_services_for_target,
    upsert_target,
)
from src.database.connection import ensure_runtime_indexes
from src.state.cyber_state import CyberState

logger = logging.getLogger(__name__)


def persist_state_update(previous_state: CyberState, updates: Dict[str, Any]) -> None:
    """Persist one CyberState delta through isolated best-effort handlers."""

    mission_id = str(updates.get("mission_id") or previous_state.get("mission_id") or "").strip()
    if not mission_id:
        return

    try:
        # Bootstrap indexes before writing, but never let persistence stop the graph.
        ensure_runtime_indexes()
        merged_targets = _merge_dict_state(previous_state, updates, "discovered_targets")
        merged_active_sessions = _merge_dict_state(previous_state, updates, "active_sessions")
    except Exception:
        logger.exception("Best-effort state persistence failed for mission %s", mission_id)
        return

    _run_persistence_handler(
        mission_id,
        "targets",
        _persist_targets,
        mission_id,
        updates.get("discovered_targets", {}) or {},
    )
    _run_persistence_handler(
        mission_id,
        "web_findings",
        _persist_web_findings,
        mission_id,
        merged_targets,
        updates.get("web_findings", []) or [],
    )
    _run_persistence_handler(
        mission_id,
        "intelligence_findings",
        _persist_intelligence_findings,
        mission_id,
        merged_targets,
        updates.get("intelligence_findings", []) or [],
    )
    _run_persistence_handler(
        mission_id,
        "generic_findings",
        _persist_generic_findings,
        mission_id,
        merged_targets,
        updates,
    )
    _run_persistence_handler(
        mission_id,
        "agent_logs",
        _persist_agent_logs,
        mission_id,
        updates.get("agent_log", []) or [],
        updates,
    )
    _run_persistence_handler(
        mission_id,
        "errors",
        _persist_errors,
        mission_id,
        updates.get("errors", []) or [],
    )
    _run_persistence_handler(
        mission_id,
        "sessions",
        _persist_sessions,
        mission_id,
        merged_targets,
        merged_active_sessions,
    )


def _merge_dict_state(previous_state: CyberState, updates: Dict[str, Any], key: str) -> Dict[str, Any]:
    """Apply a shallow merge matching the graph reducer behavior for dict fields."""

    merged = dict(previous_state.get(key, {}) or {})
    merged.update(dict(updates.get(key, {}) or {}))
    return merged


def _run_persistence_handler(mission_id: str, handler_name: str, handler, *args: Any) -> None:
    """Run one persistence path without suppressing unrelated handlers on failure."""

    try:
        handler(*args)
    except Exception:
        logger.exception(
            "Best-effort persistence handler '%s' failed for mission %s",
            handler_name,
            mission_id,
        )


def _persist_targets(mission_id: str, discovered_targets: Dict[str, Dict[str, Any]]) -> None:
    """Persist target and service snapshots from discovered target state."""

    for ip_address, target_data in discovered_targets.items():
        if not isinstance(target_data, dict):
            continue

        target_row = upsert_target(
            mission_id=mission_id,
            ip_address=ip_address,
            mac_address=target_data.get("mac_address"),
            os_guess=target_data.get("os_guess"),
            hostname=target_data.get("hostname"),
        )

        if target_row is None:
            continue

        services = _normalize_services(target_data.get("services", {}) or {})
        if services:
            replace_services_for_target(target_row["id"], services)


def _normalize_services(services: Dict[Any, Any]) -> List[Dict[str, Any]]:
    """Normalize CyberState service maps into repository insert dictionaries."""

    normalized: List[Dict[str, Any]] = []
    for port_key, service in services.items():
        port = int(port_key) if str(port_key).isdigit() else 0
        if isinstance(service, dict):
            normalized.append(
                {
                    "port": port,
                    "protocol": service.get("protocol", "tcp"),
                    "service_name": service.get("service_name", "unknown"),
                    "service_version": service.get("version") or service.get("service_version"),
                    "banner": service.get("banner"),
                }
            )
        else:
            normalized.append(
                {
                    "port": port,
                    "protocol": "tcp",
                    "service_name": str(service or "unknown"),
                    "service_version": None,
                    "banner": None,
                }
            )
    return normalized


def _persist_web_findings(
    mission_id: str,
    discovered_targets: Dict[str, Dict[str, Any]],
    web_findings: Iterable[Dict[str, Any]],
) -> None:
    """Persist fuzzer web findings as mission findings."""

    for finding in web_findings:
        if not isinstance(finding, dict):
            continue

        target_ip = _extract_target_ip_from_web_finding(finding, discovered_targets)
        title = f"Web finding: {finding.get('path') or finding.get('url') or 'unknown path'}"
        severity = "medium" if finding.get("is_interesting") else "info"
        description = str(finding.get("rationale") or "Web surface discovered")
        persisted_data = dict(finding)
        persisted_data["persistence_key"] = _persistence_key(
            "web_finding",
            title,
            target_ip,
            persisted_data,
        )

        if finding_exists_by_persistence_key(mission_id, persisted_data["persistence_key"]):
            continue

        create_finding(
            mission_id=mission_id,
            agent_name="fuzzer",
            finding_type="web_directory",
            severity=severity,
            target_ip=target_ip,
            target_port=None,
            title=title[:255],
            description=description,
            data=persisted_data,
            auto_embed=True,
        )


def _extract_target_ip_from_web_finding(
    finding: Dict[str, Any],
    discovered_targets: Dict[str, Dict[str, Any]],
) -> str | None:
    """Infer a target IP from a web finding URL or the only known target."""

    url = str(finding.get("url") or "")
    if url:
        parsed = urlparse(url)
        if parsed.hostname:
            return parsed.hostname

    if len(discovered_targets) == 1:
        return next(iter(discovered_targets.keys()))
    return None


def _persist_intelligence_findings(
    mission_id: str,
    discovered_targets: Dict[str, Dict[str, Any]],
    intelligence_findings: Iterable[Dict[str, Any]],
) -> None:
    """Persist librarian intelligence in the canonical flat finding format."""

    default_target_ip = next(iter(discovered_targets.keys()), None)
    for finding in intelligence_findings:
        if not isinstance(finding, dict):
            continue

        confidence = float(finding.get("confidence") or 0.0)
        if finding.get("exploit_available"):
            severity = "high"
        elif confidence >= 0.8:
            severity = "medium"
        else:
            severity = "info"

        # Store only the normalized downstream contract, not older nested shapes.
        description = str(finding.get("description") or "").strip() or "Librarian intelligence brief"
        technical_params = finding.get("technical_params", {}) if isinstance(finding.get("technical_params"), dict) else {}
        persisted_payload = {
            "source": str(finding.get("source") or "librarian").strip() or "librarian",
            "cve": str(finding.get("cve") or technical_params.get("cve") or "").strip() or None,
            "exploit_available": bool(finding.get("exploit_available")),
            "technical_params": dict(technical_params),
            "citations": _string_list(finding.get("citations")),
            "confidence": confidence,
            "is_osint_derived": bool(finding.get("is_osint_derived")),
            "conflicting_sources": _string_list(finding.get("conflicting_sources")),
            "source_types": _string_list(finding.get("source_types")),
            "source_status": _string_dict(finding.get("source_status")),
            "degraded_reasons": _string_list(finding.get("degraded_reasons")),
        }
        persisted_payload["persistence_key"] = _persistence_key(
            "intelligence_finding",
            description,
            default_target_ip,
            persisted_payload,
        )

        if finding_exists_by_persistence_key(mission_id, persisted_payload["persistence_key"]):
            continue

        create_finding(
            mission_id=mission_id,
            agent_name="librarian",
            finding_type="intelligence_brief",
            severity=severity,
            target_ip=default_target_ip,
            target_port=None,
            title=description[:120],
            description=description,
            data=persisted_payload,
            auto_embed=True,
        )


GENERIC_FINDING_SPECS = {
    "credential_findings": ("credential_finding", "striker", "high"),
    "exploit_attempts": ("exploit_attempt", "striker", "medium"),
    "protocol_observations": ("protocol_observation", "scout", "info"),
    "fuzzing_runs": ("fuzzing_run", "fuzzer", "medium"),
    "crash_indicators": ("crash_indicator", "fuzzer", "high"),
    "artifacts": ("artifact", "attackbox", "info"),
    "validations": ("validation", "resident", "info"),
}


def _persist_generic_findings(
    mission_id: str,
    discovered_targets: Dict[str, Dict[str, Any]],
    updates: Dict[str, Any],
) -> None:
    """Persist miscellaneous list-based CyberState findings using one spec table."""

    default_target_ip = next(iter(discovered_targets.keys()), None)
    for key, (finding_type, agent_name, severity) in GENERIC_FINDING_SPECS.items():
        for item in updates.get(key, []) or []:
            if not isinstance(item, dict):
                continue

            target_ip = (
                item.get("target")
                or item.get("target_ip")
                or item.get("host")
                or default_target_ip
            )
            title = str(item.get("title") or item.get("module") or item.get("type") or key).strip()
            description = str(item.get("summary") or item.get("status") or title or key).strip()
            persisted = dict(item)
            persisted["persistence_key"] = _persistence_key(key, target_ip, persisted)

            if finding_exists_by_persistence_key(mission_id, persisted["persistence_key"]):
                continue

            create_finding(
                mission_id=mission_id,
                agent_name=agent_name,
                finding_type=finding_type,
                severity=severity,
                target_ip=str(target_ip) if target_ip else None,
                target_port=int(item.get("port", 0) or 0) or None,
                title=title[:255] or finding_type,
                description=description or finding_type,
                data=persisted,
                auto_embed=False,
            )


def _persist_agent_logs(
    mission_id: str,
    agent_logs: Iterable[Dict[str, Any]],
    updates: Dict[str, Any],
) -> None:
    """Persist agent log entries and mirror them into attack-chain steps."""

    for entry in agent_logs:
        normalized = _normalize_entry(entry)
        if not normalized:
            continue

        persistence_key = _persistence_key(
            "agent_log",
            normalized.get("agent"),
            normalized.get("action"),
            normalized.get("decision"),
            normalized.get("target"),
            normalized.get("timestamp"),
            normalized.get("findings"),
        )
        if agent_log_exists_by_persistence_key(mission_id, persistence_key):
            continue

        persisted_details = dict(normalized)
        persisted_details["persistence_key"] = persistence_key

        create_agent_log(
            mission_id=mission_id,
            agent_name=str(normalized.get("agent") or "unknown"),
            action=str(normalized.get("action") or normalized.get("decision") or "unknown"),
            reasoning=normalized.get("reasoning"),
            result_summary=normalized.get("decision") or normalized.get("error") or normalized.get("action"),
            details=persisted_details,
        )

        create_attack_chain_step(
            mission_id=mission_id,
            agent_name=str(normalized.get("agent") or "unknown"),
            action=str(normalized.get("action") or normalized.get("decision") or "unknown"),
            target=_derive_attack_target(normalized, updates),
            outcome=_derive_attack_outcome(normalized, updates),
            timestamp=normalized.get("timestamp"),
        )


def _persist_errors(mission_id: str, errors: Iterable[Dict[str, Any]]) -> None:
    """Persist agent errors as both log entries and failed attack-chain events."""

    for error in errors:
        normalized = _normalize_entry(error)
        if not normalized:
            continue

        persistence_key = _persistence_key(
            "agent_error",
            normalized.get("agent"),
            normalized.get("error_type"),
            normalized.get("error"),
            normalized.get("timestamp"),
        )
        if agent_log_exists_by_persistence_key(mission_id, persistence_key):
            continue

        persisted_details = dict(normalized)
        persisted_details["persistence_key"] = persistence_key

        create_agent_log(
            mission_id=mission_id,
            agent_name=str(normalized.get("agent") or "unknown"),
            action="error",
            reasoning=normalized.get("error_type"),
            result_summary=normalized.get("error"),
            details=persisted_details,
        )
        create_attack_chain_step(
            mission_id=mission_id,
            agent_name=str(normalized.get("agent") or "unknown"),
            action="error",
            target=None,
            outcome="failed",
            timestamp=normalized.get("timestamp"),
        )


def _normalize_entry(entry: Any) -> Dict[str, Any]:
    """Convert dict/Pydantic log objects to plain dictionaries."""

    if isinstance(entry, dict):
        return entry
    if hasattr(entry, "model_dump"):
        return entry.model_dump()
    return {}


def _string_list(value: Any) -> List[str]:
    """Normalize optional list-like values into non-empty strings."""

    return [text for item in list(value or []) if (text := str(item).strip())]


def _string_dict(value: Any) -> Dict[str, str]:
    """Normalize optional dictionaries into string-key/string-value metadata."""

    if not isinstance(value, dict):
        return {}
    return {str(key): str(item) for key, item in value.items() if str(key).strip()}


def _derive_attack_target(entry: Dict[str, Any], updates: Dict[str, Any]) -> str | None:
    """Derive a compact target label for attack-chain reporting."""

    target = entry.get("target")
    if target:
        return str(target)

    if entry.get("action") == "route_decision":
        next_agent = updates.get("next_agent")
        return str(next_agent) if next_agent else None

    findings = entry.get("findings")
    if isinstance(findings, dict):
        for key in ("target", "targets_scanned", "query"):
            value = findings.get(key)
            if isinstance(value, list):
                return ", ".join(str(item) for item in value[:3])
            if value:
                return str(value)
    return None


def _derive_attack_outcome(entry: Dict[str, Any], updates: Dict[str, Any]) -> str:
    """Classify a log entry into a coarse attack-chain outcome."""

    action = str(entry.get("action") or "")
    findings = entry.get("findings")
    if isinstance(findings, dict):
        status = str(findings.get("status") or "").lower()
        if status in {"error", "failed", "blocked", "aborted"}:
            return "failed"
        if findings.get("session_id"):
            return "success"

    if action == "route_decision":
        mission_status = str(updates.get("mission_status") or "").lower()
        if mission_status in {"success", "failed", "wait_for_human"}:
            return mission_status
        return "routed"

    if updates.get("errors"):
        return "failed"

    if updates.get("active_sessions"):
        return "success"
    return "success"


def _persist_sessions(
    mission_id: str,
    discovered_targets: Dict[str, Dict[str, Any]],
    active_sessions: Dict[str, Dict[str, Any]],
) -> None:
    """Sync active sessions using discovered service ports as target context."""

    target_ports = _derive_target_ports(discovered_targets)
    sync_sessions_for_mission(
        mission_id=mission_id,
        active_sessions=active_sessions,
        target_ports=target_ports,
    )


def _derive_target_ports(discovered_targets: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    """Choose a representative target port for session persistence."""

    ports: Dict[str, int] = {}
    for ip_address, target_data in discovered_targets.items():
        services = target_data.get("services", {}) if isinstance(target_data, dict) else {}
        if not isinstance(services, dict):
            continue
        numeric_ports = [int(port) for port in services.keys() if str(port).isdigit()]
        if numeric_ports:
            ports[ip_address] = min(numeric_ports)
    return ports


def _persistence_key(*parts: Any) -> str:
    """Build a stable deduplication key for persisted records."""

    payload = json.dumps(parts, sort_keys=True, default=str)
    return hashlib.sha1(payload.encode("utf-8", errors="replace")).hexdigest()
