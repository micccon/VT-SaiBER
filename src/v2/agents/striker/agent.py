"""Thin Striker v2 agent built on the v2 execution framework."""

from __future__ import annotations

from typing import Any

from src.state.cyber_state import CyberState
from src.v2.agents.common import (
    build_single_mcp_execution_spec,
    execution_error_update,
    run_v2_agent_node,
    validation_error_update,
)
from src.v2.agents.striker.constants import (
    ATTACKBOX_MCP_URL,
    MAX_EXPLOIT_ATTEMPTS,
    STRIKER_ALLOWED_TOOLS,
    STRIKER_APPROVAL_REQUIRED_TOOLS,
    STRIKER_REQUIRE_CONFIRMATION,
    STRIKER_V2_SYSTEM_PROMPT,
)
from src.v2.agents.striker.context import build_striker_context
from src.v2.agents.striker.mapper import map_execution_result_to_state
from src.v2.agents.striker.outcome import StrikerOutcome
from src.v2.agents.striker.policy import StrikerExecutionPolicy
from src.v2.contracts.execution import AgentExecutionSpec
from src.v2.execution import AgentsSDKExecutionRunner


class StrikerV2Agent:
    """Structured-output Striker implementation on the parallel v2 stack."""

    def __init__(
        self,
        *,
        sdk_module: Any | None = None,
        execution_runner: AgentsSDKExecutionRunner | None = None,
    ):
        self.name = "striker_v2"
        self.require_confirmation = STRIKER_REQUIRE_CONFIRMATION
        self.max_attempts = MAX_EXPLOIT_ATTEMPTS
        self._runner = execution_runner or AgentsSDKExecutionRunner(sdk_module=sdk_module)

    @property
    def system_prompt(self) -> str:
        return STRIKER_V2_SYSTEM_PROMPT.format(max_attempts=self.max_attempts)

    def build_execution_spec(self) -> AgentExecutionSpec[StrikerOutcome]:
        """Build the v2 execution declaration for Striker."""

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
        """Execute Striker v2 and map the structured result back into CyberState."""

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
                message="Striker v2 execution failed.",
                exc=exc,
            )


async def striker_v2_node(state: CyberState) -> dict[str, Any]:
    """LangGraph node wrapper for Striker v2."""

    return await run_v2_agent_node(state, StrikerV2Agent)
