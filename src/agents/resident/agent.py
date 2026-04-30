"""Resident agent built on the execution framework."""

from __future__ import annotations

from typing import Any

from src.state.cyber_state import CyberState
from src.agents.common import (
    build_single_mcp_execution_spec,
    execution_error_update,
    run_agent_node,
    validation_error_update,
)
from src.agents.resident.constants import (
    ATTACKBOX_MCP_URL,
    RESIDENT_ALLOWED_TOOLS,
    RESIDENT_APPROVAL_REQUIRED_TOOLS,
    RESIDENT_REQUIRE_CONFIRMATION,
    resident_SYSTEM_PROMPT,
)
from src.agents.resident.context import build_resident_context
from src.agents.resident.mapper import map_execution_result_to_state
from src.agents.resident.outcome import ResidentOutcome
from src.agents.resident.policy import ResidentExecutionPolicy
from src.runtime import AgentsSDKExecutionRunner
from src.runtime.contracts import AgentExecutionSpec


class ResidentAgent:
    """Structured-output resident implementation on the stack."""

    def __init__(
        self,
        *,
        sdk_module: Any | None = None,
        execution_runner: AgentsSDKExecutionRunner | None = None,
    ):
        self.name = "resident"
        self.require_confirmation = RESIDENT_REQUIRE_CONFIRMATION
        self._runner = execution_runner or AgentsSDKExecutionRunner(sdk_module=sdk_module)

    @property
    def system_prompt(self) -> str:
        return resident_SYSTEM_PROMPT

    def build_execution_spec(self) -> AgentExecutionSpec[ResidentOutcome]:
        """Build the execution declaration for resident."""

        return build_single_mcp_execution_spec(
            agent_name=self.name,
            instructions=self.system_prompt,
            output_type=ResidentOutcome,
            server_name="attackbox",
            server_url=ATTACKBOX_MCP_URL,
            allowed_tools=RESIDENT_ALLOWED_TOOLS,
            approval_required_tools=RESIDENT_APPROVAL_REQUIRED_TOOLS,
            max_turns=6,
        )

    async def run(self, state: CyberState) -> dict[str, Any]:
        """Execute resident and map the structured result back into CyberState."""

        if not (state.get("active_sessions", {}) or {}):
            return validation_error_update(
                state,
                agent_name=self.name,
                message="No active sessions - run Striker first",
            )

        context = build_resident_context(state)
        try:
            result = await self._runner.run(
                self.build_execution_spec(),
                user_input=context,
                context=state,
                policy=ResidentExecutionPolicy(require_confirmation=self.require_confirmation),
            )
            return map_execution_result_to_state(
                state,
                agent_name=self.name,
                context=context,
                result=result,
            )
        except Exception as exc:
            return execution_error_update(
                state,
                agent_name=self.name,
                message="Resident execution failed.",
                exc=exc,
            )


async def resident_node(state: CyberState) -> dict[str, Any]:
    """LangGraph node wrapper for resident."""

    return await run_agent_node(state, ResidentAgent)
