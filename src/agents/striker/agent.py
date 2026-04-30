"""Thin Striker agent built on the execution framework."""

from __future__ import annotations

from typing import Any

from src.state.cyber_state import CyberState
from src.agents.common import (
    build_single_mcp_execution_spec,
    execution_error_update,
    run_agent_node,
    validation_error_update,
)
from src.agents.striker.constants import (
    ATTACKBOX_MCP_URL,
    MAX_EXPLOIT_ATTEMPTS,
    STRIKER_ALLOWED_TOOLS,
    STRIKER_APPROVAL_REQUIRED_TOOLS,
    STRIKER_REQUIRE_CONFIRMATION,
    striker_SYSTEM_PROMPT,
)
from src.agents.striker.context import build_striker_context
from src.agents.striker.mapper import map_execution_result_to_state
from src.agents.striker.outcome import StrikerOutcome
from src.agents.striker.policy import StrikerExecutionPolicy
from src.runtime import AgentsSDKExecutionRunner
from src.runtime.contracts import AgentExecutionSpec


class StrikerAgent:
    """Structured-output Striker implementation on the stack."""

    def __init__(
        self,
        *,
        sdk_module: Any | None = None,
        execution_runner: AgentsSDKExecutionRunner | None = None,
    ):
        self.name = "striker"
        self.require_confirmation = STRIKER_REQUIRE_CONFIRMATION
        self.max_attempts = MAX_EXPLOIT_ATTEMPTS
        self._runner = execution_runner or AgentsSDKExecutionRunner(sdk_module=sdk_module)

    @property
    def system_prompt(self) -> str:
        return striker_SYSTEM_PROMPT.format(max_attempts=self.max_attempts)

    def build_execution_spec(self) -> AgentExecutionSpec[StrikerOutcome]:
        """Build the execution declaration for Striker."""

        return build_single_mcp_execution_spec(
            agent_name=self.name,
            instructions=self.system_prompt,
            output_type=StrikerOutcome,
            server_name="attackbox",
            server_url=ATTACKBOX_MCP_URL,
            allowed_tools=STRIKER_ALLOWED_TOOLS,
            approval_required_tools=STRIKER_APPROVAL_REQUIRED_TOOLS,
            max_turns=8,
        )

    async def run(self, state: CyberState) -> dict[str, Any]:
        """Execute Striker and map the structured result back into CyberState."""

        if not (state.get("discovered_targets", {}) or {}):
            return validation_error_update(
                state,
                agent_name=self.name,
                message="No discovered targets available for striker exploitation.",
            )

        context = build_striker_context(state)
        try:
            result = await self._runner.run(
                self.build_execution_spec(),
                user_input=context,
                context=state,
                policy=StrikerExecutionPolicy(
                    require_confirmation=self.require_confirmation,
                    max_attempts=self.max_attempts,
                ),
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
                message="Striker execution failed.",
                exc=exc,
            )


async def striker_node(state: CyberState) -> dict[str, Any]:
    """LangGraph node wrapper for Striker."""

    return await run_agent_node(state, StrikerAgent)
