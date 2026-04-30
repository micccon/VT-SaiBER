"""CyberState mapping helpers for supervisor v2."""

from __future__ import annotations

import json
from typing import Any

from src.state.cyber_state import CyberState
from src.state.models import AgentLogEntry
from src.v2.agents.supervisor.outcome import SupervisorV2Decision


def map_decision_to_state(
    state: CyberState,
    *,
    agent_name: str,
    context: str,
    decision: SupervisorV2Decision,
    raw_text: str,
    guardrail_reason: str = "",
    mission_status: str | None = None,
) -> dict[str, Any]:
    """Convert a supervisor v2 routing decision into CyberState updates."""

    rationale = decision.rationale.strip()
    if guardrail_reason:
        rationale = f"{rationale} | Guardrail: {guardrail_reason}" if rationale else f"Guardrail: {guardrail_reason}"

    history = list(state.get("supervisor_messages", []) or [])
    history.extend(
        [
            {"role": "user", "content": context},
            {"role": "assistant", "content": raw_text or json.dumps(decision.model_dump())},
        ]
    )
    history = history[-12:]

    update: dict[str, Any] = {
        "current_agent": agent_name,
        "iteration_count": int(state.get("iteration_count", 0)) + 1,
        "next_agent": decision.next_agent,
        "supervisor_messages": history,
        "supervisor_expectations": {
            "specific_goal": decision.specific_goal,
            "confidence_score": decision.confidence_score,
        },
        "agent_log": [
            AgentLogEntry(
                agent=agent_name,
                action="route_decision",
                decision=decision.next_agent,
                reasoning=rationale,
                findings={
                    "specific_goal": decision.specific_goal,
                    "confidence_score": decision.confidence_score,
                },
            )
        ],
    }
    if mission_status is not None:
        update["mission_status"] = mission_status
    return update
