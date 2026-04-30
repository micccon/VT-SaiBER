"""Scout v2 agent built on the v2 execution framework."""

from __future__ import annotations

from typing import Any

from src.state.cyber_state import CyberState
from src.v2.agents.common import (
    build_single_mcp_execution_spec,
    execution_error_update,
    run_v2_agent_node,
    validation_error_update,
)
from src.v2.agents.scout.constants import ATTACKBOX_MCP_URL, MAX_SCOUT_TARGETS, SCOUT_ALLOWED_TOOLS, SCOUT_V2_SYSTEM_PROMPT
from src.v2.agents.scout.context import build_scout_context
from src.v2.agents.scout.mapper import map_execution_result_to_state
from src.v2.agents.scout.outcome import ScoutOutcome
from src.v2.contracts.execution import AgentExecutionSpec
from src.v2.execution import AgentsSDKExecutionRunner


class ScoutV2Agent:
    """Structured-output Scout implementation on the parallel v2 stack."""

    def __init__(
        self,
        *,
        sdk_module: Any | None = None,
        execution_runner: AgentsSDKExecutionRunner | None = None,
    ):
        self.name = "scout_v2"
        self._runner = execution_runner or AgentsSDKExecutionRunner(sdk_module=sdk_module)

    @property
    def system_prompt(self) -> str:
        return SCOUT_V2_SYSTEM_PROMPT.format(max_targets=MAX_SCOUT_TARGETS)

    def build_execution_spec(self) -> AgentExecutionSpec[ScoutOutcome]:
        """Build the v2 execution declaration for Scout."""

        return build_single_mcp_execution_spec(
            agent_name=self.name,
            instructions=self.system_prompt,
            output_type=ScoutOutcome,
            server_name="attackbox",
            server_url=ATTACKBOX_MCP_URL,
            allowed_tools=SCOUT_ALLOWED_TOOLS,
            max_turns=6,
            require_tool_use=True,
        )

    async def run(self, state: CyberState) -> dict[str, Any]:
        """Execute Scout v2 and map the structured result back into CyberState."""

        if not (state.get("target_scope", []) or []):
            return validation_error_update(
                state,
                agent_name=self.name,
                message="No targets in target_scope",
            )

        context = build_scout_context(state)
        try:
            result = await self._runner.run(
                self.build_execution_spec(),
                user_input=context,
                context=state,
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
                message="Scout v2 execution failed.",
                exc=exc,
            )


async def scout_v2_node(state: CyberState) -> dict[str, Any]:
    """LangGraph node wrapper for Scout v2."""

    return await run_v2_agent_node(state, ScoutV2Agent)
