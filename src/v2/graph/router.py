"""V2-only graph routing helpers."""

from __future__ import annotations

import logging

from langgraph.graph import END

from src.config import get_runtime_config
from src.graph.router import validate_all_targets_in_scope
from src.state.cyber_state import CyberState

logger = logging.getLogger(__name__)

MAX_ITERATIONS = get_runtime_config().max_iterations
VALID_V2_AGENTS = ["scout_v2", "fuzzer_v2", "librarian_v2", "striker_v2", "resident_v2"]


def route_next_agent_v2(state: CyberState) -> str:
    """Route from supervisor_v2 to the next v2 node after hard safety checks."""

    iteration_count = int(state.get("iteration_count", 0))
    if iteration_count > MAX_ITERATIONS:
        logger.warning("Max iterations (%s) exceeded in v2 graph", MAX_ITERATIONS)
        return END

    mission_status = str(state.get("mission_status", "active")).strip().lower()
    if mission_status in {"success", "failed", "wait_for_human"}:
        logger.info("Mission status is terminal in v2 graph: %s", mission_status)
        return END

    next_agent = str(state.get("next_agent", "") or "").strip().lower()
    if next_agent == "end":
        return END

    if next_agent not in VALID_V2_AGENTS:
        logger.warning("Invalid v2 agent choice: %s", next_agent)
        return END

    if not validate_all_targets_in_scope(state):
        logger.error("Scope validation failed in v2 graph")
        return END

    return next_agent


def get_valid_v2_agents() -> list[str]:
    """Return the list of valid v2 graph node names."""

    return VALID_V2_AGENTS.copy()
