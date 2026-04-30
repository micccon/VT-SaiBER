"""CyberState mapping for Scout v2."""

from __future__ import annotations

from typing import Any

from src.state.cyber_state import CyberState
from src.state.models import AgentError, AgentLogEntry, DiscoveredTarget
from src.utils.validators import target_in_scope
from src.v2.agents.scout.constants import MAX_SCOUT_TARGETS
from src.v2.agents.scout.outcome import ScoutOutcome
from src.v2.contracts.execution import ExecutionResult

SCOUT_RECON_TOOLS = {"recon_host_discovery", "recon_port_scan", "recon_service_probe"}


def _validation_error(state: CyberState, *, agent_name: str, message: str) -> dict[str, Any]:
    """Return Scout's standard recoverable validation error update."""

    return {
        "current_agent": agent_name,
        "iteration_count": int(state.get("iteration_count", 0)) + 1,
        "errors": [
            AgentError(
                agent=agent_name,
                error_type="ValidationError",
                error=message,
                recoverable=True,
            )
        ],
    }


def _used_recon_tool(result: ExecutionResult[ScoutOutcome]) -> bool:
    """Verify Scout actually ran a reconnaissance tool before trusting output."""

    return any(event.tool_name in SCOUT_RECON_TOOLS for event in result.tool_events)


def map_execution_result_to_state(
    state: CyberState,
    *,
    agent_name: str,
    context: str,
    result: ExecutionResult[ScoutOutcome],
) -> dict[str, Any]:
    """Convert a Scout v2 execution result into CyberState updates."""

    outcome = result.outcome
    target_scope = state.get("target_scope", []) or []
    discovered_targets: dict[str, dict[str, Any]] = {}

    if not _used_recon_tool(result):
        return _validation_error(
            state,
            agent_name=agent_name,
            message="Scout v2 did not execute a reconnaissance tool.",
        )

    for target in outcome.targets:
        ip_address = str(target.ip_address).strip()
        if not ip_address or not target_in_scope(ip_address, target_scope):
            continue
        discovered_targets[ip_address] = target.model_dump()

    if not discovered_targets:
        for host in outcome.discovered_hosts[:MAX_SCOUT_TARGETS]:
            if not target_in_scope(host, target_scope):
                continue
            discovered_targets[host] = DiscoveredTarget(
                ip_address=host,
                ports=[],
                services={},
                os_guess="Unknown",
            ).model_dump()

    if not discovered_targets:
        return _validation_error(
            state,
            agent_name=agent_name,
            message="Scout v2 did not produce any in-scope targets or services.",
        )

    total_ports = sorted(
        {
            int(port)
            for target in discovered_targets.values()
            for port in (target.get("ports", []) or [])
        }
    )
    total_services = sum(
        len((target.get("services", {}) or {}))
        for target in discovered_targets.values()
        if isinstance(target, dict)
    )
    reasoning = "\n\n".join(
        item for item in [outcome.operator_summary.strip(), str(outcome.stop_reason or "").strip()] if item
    ).strip() or context

    return {
        "current_agent": agent_name,
        "iteration_count": int(state.get("iteration_count", 0)) + 1,
        "discovered_targets": discovered_targets,
        "agent_log": [
            AgentLogEntry(
                agent=agent_name,
                action="recon_scan",
                target=", ".join(discovered_targets.keys()),
                findings={
                    "targets_scanned": list(discovered_targets.keys()),
                    "ports_found": total_ports,
                    "services_found": total_services,
                },
                reasoning=reasoning,
            )
        ],
    }
