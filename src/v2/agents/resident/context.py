"""Resident v2 context builder."""

from __future__ import annotations

from typing import Any, Iterable

from src.state.cyber_state import CyberState


def resolve_objective(state: CyberState) -> str:
    """Resolve the immediate resident objective from supervisor expectations or mission goal."""

    expectations = state.get("supervisor_expectations", {}) or {}
    objective = str(expectations.get("specific_goal", "") or "").strip()
    if objective:
        return objective
    return str(state.get("mission_goal") or "(not specified)").strip() or "(not specified)"


def _stringify(value: Any) -> str:
    """Normalize arbitrary values to trimmed strings."""

    return str(value or "").strip()


def _compact_lines(values: Iterable[str], *, limit: int = 8) -> str:
    """Render a compact multi-line section."""

    lines = [line for line in (_stringify(value) for value in values) if line]
    return "\n".join(lines[:limit]) if lines else "  (none)"


def build_resident_context(state: CyberState) -> str:
    """Build a compact session-backed objective prompt for resident v2."""

    objective = resolve_objective(state)
    mission_goal = str(state.get("mission_goal") or "(not specified)")
    active_sessions = state.get("active_sessions", {}) or {}
    discovered_targets = state.get("discovered_targets", {}) or {}
    research_cache = state.get("research_cache", {}) or {}
    intelligence_findings = state.get("intelligence_findings", []) or []

    session_lines: list[str] = []
    for target, info in active_sessions.items():
        session_lines.append(
            "  session_id={sid} target={target} via={module} user={user} opened={opened}".format(
                sid=info.get("session_id", "?"),
                target=target,
                module=info.get("module", info.get("exploit", "unknown")),
                user=info.get("user", "unknown"),
                opened=info.get("established_at", info.get("established", "?")),
            )
        )

    target_lines: list[str] = []
    for ip, data in discovered_targets.items():
        if not isinstance(data, dict):
            continue
        services = data.get("services", {}) or {}
        service_bits: list[str] = []
        for port, value in list(services.items())[:6]:
            if isinstance(value, dict):
                name = value.get("service_name", "unknown")
                version = f" {value.get('version')}" if value.get("version") else ""
                service_bits.append(f"{port}:{name}{version}")
            else:
                service_bits.append(f"{port}:{value}")
        target_lines.append(
            f"  {ip} os={data.get('os_guess', 'unknown')} services={', '.join(service_bits) or '(none)'}"
        )

    research_lines: list[str] = []
    for key, value in list(research_cache.items())[:5]:
        research_lines.append(f"  Research ({key}): {str(value)[:180]}")
    for finding in intelligence_findings[:5]:
        if isinstance(finding, dict):
            cve = str(finding.get("cve", "") or "").strip()
            description = str(finding.get("description", "") or "").strip()
            if cve or description:
                prefix = f"[{cve}] " if cve else ""
                research_lines.append(f"  Intel: {prefix}{description[:180]}")
        else:
            research_lines.append(f"  Intel: {str(finding)[:180]}")

    return (
        f"MISSION GOAL: {mission_goal}\n"
        f"IMMEDIATE OBJECTIVE: {objective}\n\n"
        f"ACTIVE SESSIONS:\n{_compact_lines(session_lines)}\n\n"
        f"TARGET CONTEXT:\n{_compact_lines(target_lines)}\n\n"
        f"RESEARCH & INTELLIGENCE:\n{_compact_lines(research_lines)}\n\n"
        "Validate sessions first, take one bounded next step, and stop cleanly if approval is required."
    )
