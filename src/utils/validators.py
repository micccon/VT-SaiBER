"""
Validation helpers for orchestration guardrails.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Any, Dict, Iterable, List


def target_in_scope(target: str, scope: Iterable[str]) -> bool:
    """Return True when a target host/IP is covered by the mission scope."""

    entries = [item for item in scope if item]
    if not entries:
        return False

    try:
        target_ip = ip_address(target)
    except ValueError:
        # Hostname: allow exact match in scope list.
        return target in entries

    for entry in entries:
        try:
            if target_ip in ip_network(entry, strict=False):
                return True
        except ValueError:
            if target == entry:
                return True
    return False


def has_service_version_intel(discovered_targets: Dict[str, Dict[str, Any]]) -> bool:
    """Check whether recon has already captured at least one concrete service version."""

    for target_data in (discovered_targets or {}).values():
        services = target_data.get("services", {}) if isinstance(target_data, dict) else {}
        for service in services.values():
            if isinstance(service, dict):
                version = str(service.get("version") or "").strip()
            else:
                version = ""
            if version:
                return True
    return False


def list_recent_agent_names(agent_log: List[Dict[str, Any]], n: int = 6) -> List[str]:
    """Extract the last n normalized agent names from the audit log."""

    names: List[str] = []
    for entry in (agent_log or [])[-n:]:
        if isinstance(entry, dict):
            agent_name = str(entry.get("agent") or "").strip().lower()
        else:
            agent_name = str(getattr(entry, "agent", "")).strip().lower()
        if agent_name:
            names.append(agent_name)
    return names


def has_agent_run(agent_log: List[Dict[str, Any]], agent_name: str) -> bool:
    """Check whether the named agent appears anywhere in the current agent log."""

    expected = agent_name.strip().lower()
    return any(name == expected for name in list_recent_agent_names(agent_log, n=len(agent_log)))
