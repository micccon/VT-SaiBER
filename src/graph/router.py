"""Production graph routing helpers."""

from __future__ import annotations

import logging
from ipaddress import ip_address, ip_network

from langgraph.graph import END

from src.config import get_runtime_config
from src.state.cyber_state import CyberState

logger = logging.getLogger(__name__)

MAX_ITERATIONS = get_runtime_config().max_iterations
VALID_AGENTS = ["scout", "fuzzer", "librarian", "striker", "resident"]


def validate_all_targets_in_scope(state: CyberState) -> bool:
    """Return True when every discovered target is covered by target_scope."""

    target_scope = state.get("target_scope", []) or []
    discovered_targets = state.get("discovered_targets", {}) or {}
    if not target_scope:
        logger.warning("No target scope defined")
        return False

    for target_ip in discovered_targets.keys():
        try:
            target = ip_address(target_ip)
        except ValueError:
            if target_ip not in target_scope:
                logger.warning("Hostname %s not explicitly in scope", target_ip)
            continue

        in_scope = False
        for entry in target_scope:
            try:
                if target in ip_network(entry, strict=False):
                    in_scope = True
                    break
            except ValueError:
                if target_ip == entry:
                    in_scope = True
                    break
        if not in_scope:
            logger.error("Target %s is out of scope", target_ip)
            return False
    return True


def route_next_agent(state: CyberState) -> str:
    """Route from supervisor to the next node after hard safety checks."""

    iteration_count = int(state.get("iteration_count", 0))
    if iteration_count > MAX_ITERATIONS:
        logger.warning("Max iterations (%s) exceeded", MAX_ITERATIONS)
        return END

    mission_status = str(state.get("mission_status", "active")).strip().lower()
    if mission_status in {"success", "failed", "wait_for_human"}:
        logger.info("Mission status is terminal: %s", mission_status)
        return END

    next_agent = str(state.get("next_agent", "") or "").strip().lower()
    if next_agent == "end":
        return END
    if next_agent not in VALID_AGENTS:
        logger.warning("Invalid agent choice: %s", next_agent)
        return END
    if not validate_all_targets_in_scope(state):
        logger.error("Scope validation failed")
        return END
    return next_agent
