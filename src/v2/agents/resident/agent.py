"""Resident v2 agent built on the v2 execution framework."""

from __future__ import annotations

from typing import Any

from src.state.cyber_state import CyberState
from src.v2.agents.common import (
    build_single_mcp_execution_spec,
    execution_error_update,
    run_v2_agent_node,
    validation_error_update,
)
from src.v2.agents.resident.constants import (
    ATTACKBOX_MCP_URL,
    RESIDENT_ALLOWED_TOOLS,
    RESIDENT_APPROVAL_REQUIRED_TOOLS,
    RESIDENT_REQUIRE_CONFIRMATION,
    RESIDENT_V2_SYSTEM_PROMPT,
)
from src.v2.agents.resident.context import build_resident_context
from src.v2.agents.resident.mapper import map_execution_result_to_state
from src.v2.agents.resident.outcome import ResidentOutcome
from src.v2.agents.resident.policy import ResidentExecutionPolicy
from src.v2.contracts.execution import AgentExecutionSpec
from src.v2.execution import AgentsSDKExecutionRunner


class ResidentV2Agent:
    """Structured-output resident implementation on the parallel v2 stack."""

    def __init__(
        self,
        *,
        sdk_module: Any | None = None,
        execution_runner: AgentsSDKExecutionRunner | None = None,
    ):
        self.name = "resident_v2"
        self.require_confirmation = RESIDENT_REQUIRE_CONFIRMATION
        self._runner = execution_runner or AgentsSDKExecutionRunner(sdk_module=sdk_module)

    @property
    def system_prompt(self) -> str:
        return RESIDENT_V2_SYSTEM_PROMPT

    def build_execution_spec(self) -> AgentExecutionSpec[ResidentOutcome]:
        """Build the v2 execution declaration for resident."""

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
        """Execute resident v2 and map the structured result back into CyberState."""

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
                message="Resident v2 execution failed.",
                exc=exc,
            )


async def resident_v2_node(state: CyberState) -> dict[str, Any]:
    """LangGraph node wrapper for resident v2."""

    return await run_v2_agent_node(state, ResidentV2Agent)
