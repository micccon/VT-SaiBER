"""Supervisor agent built on the chat/synthesis lane."""

from __future__ import annotations

import json
from typing import Any

from src.config import get_runtime_config
from src.graph.router import validate_all_targets_in_scope
from src.state.cyber_state import CyberState
from src.agents.common import build_default_model_config, run_agent_node
from src.agents.supervisor.constants import SUPERVISOR_SYSTEM_PROMPT, VALID_NEXT_AGENTS
from src.agents.supervisor.context import (
    build_supervisor_context,
    has_any_services,
    has_http_service,
    has_librarian_research,
    latest_resident_outcome,
    sanitize_history,
    striker_failed_recently,
)
from src.agents.supervisor.mapper import map_decision_to_state
from src.agents.supervisor.outcome import SupervisorDecision
from src.runtime import ChatSynthesisRunner
from src.runtime.contracts import ChatSynthesisSpec


class SupervisorAgent:
    """Lean orchestration agent for the production graph."""

    def __init__(
        self,
        *,
        llm_client: Any | None = None,
        synthesis_runner: ChatSynthesisRunner | None = None,
    ):
        self.name = "supervisor"
        self._config = get_runtime_config()
        self._synthesis_runner = synthesis_runner or ChatSynthesisRunner(client=llm_client)
        self._model_config = build_default_model_config(temperature=0.0)

    @property
    def system_prompt(self) -> str:
        """Return the fixed supervisor-routing instructions."""

        return SUPERVISOR_SYSTEM_PROMPT

    def build_synthesis_spec(self) -> ChatSynthesisSpec[SupervisorDecision]:
        """Build the non-tool synthesis spec for one supervisor decision."""

        return ChatSynthesisSpec(
            agent_name=self.name,
            instructions=self.system_prompt,
            model=self._model_config,
            output_type=SupervisorDecision,
        )

    def _terminal_decision(self, *, rationale: str, specific_goal: str) -> SupervisorDecision:
        """Build a standard end decision."""

        return SupervisorDecision(
            next_agent="end",
            rationale=rationale,
            specific_goal=specific_goal,
            confidence_score=1.0,
        )

    def _fallback_decision(self, state: CyberState, *, reason: str) -> SupervisorDecision:
        """Use a compact deterministic fallback when synthesis fails."""

        discovered_targets = state.get("discovered_targets", {}) or {}
        active_sessions = state.get("active_sessions", {}) or {}
        web_findings = state.get("web_findings", []) or []
        resident = latest_resident_outcome(state)
        resident_status = str(resident.get("objective_status", "")).strip().lower()
        resident_objective = str(
            resident.get("objective")
            or state.get("supervisor_expectations", {}).get("specific_goal")
            or state.get("mission_goal")
            or ""
        ).strip()
        researched = has_librarian_research(state)

        if resident_status == "completed":
            return self._terminal_decision(
                rationale=f"Fallback routing due to synthesis failure: {reason}",
                specific_goal=resident_objective or "Resident completed the objective.",
            )
        if resident_status == "needs_approval":
            return self._terminal_decision(
                rationale=f"Fallback routing due to synthesis failure: {reason}",
                specific_goal=resident_objective or "Await human approval for the next resident action.",
            )
        if active_sessions:
            return SupervisorDecision(
                next_agent="resident",
                rationale=f"Fallback routing due to synthesis failure: {reason}",
                specific_goal=resident_objective or "Advance the current objective using the live session.",
                confidence_score=0.35,
            )
        if not discovered_targets:
            return SupervisorDecision(
                next_agent="scout",
                rationale=f"Fallback routing due to synthesis failure: {reason}",
                specific_goal="Discover in-scope targets and fingerprint exposed services.",
                confidence_score=0.35,
            )
        if has_http_service(discovered_targets) and not web_findings:
            return SupervisorDecision(
                next_agent="fuzzer",
                rationale=f"Fallback routing due to synthesis failure: {reason}",
                specific_goal="Enumerate the discovered HTTP surface and collect interesting findings.",
                confidence_score=0.35,
            )
        if not researched:
            return SupervisorDecision(
                next_agent="librarian",
                rationale=f"Fallback routing due to synthesis failure: {reason}",
                specific_goal="Research exploit paths and prepare a grounded plan for exploitation.",
                confidence_score=0.35,
            )
        if has_any_services(discovered_targets):
            return SupervisorDecision(
                next_agent="striker",
                rationale=f"Fallback routing due to synthesis failure: {reason}",
                specific_goal="Attempt exploitation using the researched path.",
                confidence_score=0.35,
            )
        return self._terminal_decision(
            rationale=f"Fallback routing due to synthesis failure: {reason}",
            specific_goal="No meaningful remote attack surface remains. Await operator guidance.",
        )

    def _apply_guardrails(
        self,
        state: CyberState,
        decision: SupervisorDecision,
    ) -> tuple[SupervisorDecision, str]:
        """Rewrite invalid or unsafe routing decisions into a safe path."""

        next_agent = str(decision.next_agent).strip().lower()
        resident = latest_resident_outcome(state)
        resident_status = str(resident.get("objective_status", "")).strip().lower()
        resident_objective = str(
            resident.get("objective")
            or state.get("supervisor_expectations", {}).get("specific_goal")
            or state.get("mission_goal")
            or ""
        ).strip()
        guardrail_reason = ""

        if next_agent not in VALID_NEXT_AGENTS:
            fallback = self._fallback_decision(state, reason="invalid next_agent from model")
            next_agent = fallback.next_agent
            decision = fallback
            guardrail_reason = "invalid-next-agent-corrected"
        elif next_agent == "resident" and not (state.get("active_sessions", {}) or {}):
            next_agent = "striker" if has_librarian_research(state) else "librarian"
            guardrail_reason = "resident-without-session-corrected"
        elif next_agent == "striker" and not has_librarian_research(state):
            next_agent = "librarian"
            guardrail_reason = "forced-librarian-before-striker"
        elif next_agent == "striker" and striker_failed_recently(state):
            next_agent = "librarian"
            guardrail_reason = "striker-failure-backtrack"
        elif next_agent == "end" and resident_status not in {"completed", "needs_approval"} and (state.get("active_sessions", {}) or {}):
            next_agent = "resident"
            guardrail_reason = "resident-not-finished"

        rewritten_goal = decision.specific_goal
        if next_agent == "resident" and resident_objective:
            rewritten_goal = resident_objective
        elif next_agent == "librarian" and not rewritten_goal:
            rewritten_goal = "Research exploit paths and prepare the next specialist."
        elif next_agent == "striker" and not rewritten_goal:
            rewritten_goal = "Attempt exploitation using the researched path."
        elif next_agent == "fuzzer" and not rewritten_goal:
            rewritten_goal = "Enumerate the discovered HTTP surface."
        elif next_agent == "scout" and not rewritten_goal:
            rewritten_goal = "Discover in-scope targets and services."

        return (
            SupervisorDecision(
                next_agent=next_agent,
                rationale=decision.rationale,
                specific_goal=rewritten_goal,
                confidence_score=decision.confidence_score,
            ),
            guardrail_reason,
        )

    def _derive_terminal_state(self, state: CyberState) -> str:
        """Translate the current mission context into a terminal mission status."""

        mission_status = str(state.get("mission_status", "active")).strip().lower()
        if mission_status in {"success", "failed", "wait_for_human"}:
            return mission_status
        resident = latest_resident_outcome(state)
        resident_status = str(resident.get("objective_status", "")).strip().lower()
        if resident_status == "completed":
            return "success"
        if resident_status == "needs_approval":
            return "wait_for_human"
        return "wait_for_human"

    async def run(self, state: CyberState) -> dict[str, Any]:
        """Route the next specialist or end the production graph safely."""

        mission_status = str(state.get("mission_status", "active")).strip().lower()
        if mission_status in {"success", "failed", "wait_for_human"}:
            decision = self._terminal_decision(
                rationale=f"Mission already in terminal state: {mission_status}",
                specific_goal="N/A",
            )
            return map_decision_to_state(
                state,
                agent_name=self.name,
                context="terminal-state-shortcut",
                decision=decision,
                raw_text=json.dumps(decision.model_dump()),
                mission_status=mission_status,
            )

        if int(state.get("iteration_count", 0)) > self._config.max_iterations:
            decision = self._terminal_decision(
                rationale=f"Iteration cap exceeded ({self._config.max_iterations}).",
                specific_goal="Wait for human guidance.",
            )
            return map_decision_to_state(
                state,
                agent_name=self.name,
                context="iteration-cap-shortcut",
                decision=decision,
                raw_text=json.dumps(decision.model_dump()),
                mission_status="wait_for_human",
            )

        if not validate_all_targets_in_scope(state):
            decision = self._terminal_decision(
                rationale="Out-of-scope target detected. Mission aborted for safety.",
                specific_goal="N/A",
            )
            return map_decision_to_state(
                state,
                agent_name=self.name,
                context="scope-violation-shortcut",
                decision=decision,
                raw_text=json.dumps(decision.model_dump()),
                mission_status="failed",
            )

        resident = latest_resident_outcome(state)
        resident_status = str(resident.get("objective_status", "")).strip().lower()
        resident_objective = str(resident.get("objective") or "").strip()
        if resident_status == "completed":
            decision = self._terminal_decision(
                rationale="Resident reported objective completion on a live session.",
                specific_goal=resident_objective or "Mission objectives satisfied.",
            )
            return map_decision_to_state(
                state,
                agent_name=self.name,
                context="resident-completed-shortcut",
                decision=decision,
                raw_text=json.dumps(decision.model_dump()),
                mission_status="success",
            )
        if resident_status == "needs_approval":
            decision = self._terminal_decision(
                rationale="Resident reported that the next step requires human approval.",
                specific_goal=resident_objective or "Await human approval for resident action.",
            )
            return map_decision_to_state(
                state,
                agent_name=self.name,
                context="resident-approval-shortcut",
                decision=decision,
                raw_text=json.dumps(decision.model_dump()),
                mission_status="wait_for_human",
            )

        context = build_supervisor_context(state)
        history = sanitize_history(state)
        try:
            result = await self._synthesis_runner.run(
                self.build_synthesis_spec(),
                user_input=context,
                history=history,
            )
            decision = result.outcome
            raw_text = result.raw_text
        except Exception as exc:
            decision = self._fallback_decision(state, reason=str(exc))
            raw_text = json.dumps(decision.model_dump())

        decision, guardrail_reason = self._apply_guardrails(state, decision)
        mission_status_override = self._derive_terminal_state(state) if decision.next_agent == "end" else None
        return map_decision_to_state(
            state,
            agent_name=self.name,
            context=context,
            decision=decision,
            raw_text=raw_text or json.dumps(decision.model_dump()),
            guardrail_reason=guardrail_reason,
            mission_status=mission_status_override,
        )


async def supervisor_node(state: CyberState) -> dict[str, Any]:
    """LangGraph node wrapper for supervisor."""

    return await run_agent_node(state, SupervisorAgent)
