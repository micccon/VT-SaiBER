"""Scout agent built on the execution framework."""

from __future__ import annotations

from typing import Any

from src.state.cyber_state import CyberState
from src.agents.common import (
    build_single_mcp_execution_spec,
    execution_error_update,
    run_agent_node,
    validation_error_update,
)
from src.agents.scout.constants import ATTACKBOX_MCP_URL, MAX_SCOUT_TARGETS, SCOUT_ALLOWED_TOOLS, scout_SYSTEM_PROMPT
from src.agents.scout.context import build_scout_context
from src.agents.scout.mapper import map_execution_result_to_state
from src.agents.scout.outcome import ScoutOutcome
from src.runtime import AgentsSDKExecutionRunner
from src.runtime.contracts import AgentExecutionSpec


class ScoutAgent:
    """Structured-output Scout implementation on the stack."""

    def __init__(
        self,
        *,
        sdk_module: Any | None = None,
        execution_runner: AgentsSDKExecutionRunner | None = None,
    ):
        self.name = "scout"
        self._runner = execution_runner or AgentsSDKExecutionRunner(sdk_module=sdk_module)

    @property
    def system_prompt(self) -> str:
        return scout_SYSTEM_PROMPT.format(max_targets=MAX_SCOUT_TARGETS)

    def build_execution_spec(self) -> AgentExecutionSpec[ScoutOutcome]:
        """Build the execution declaration for Scout."""

        return build_single_mcp_execution_spec(
            agent_name=self.name,
            instructions=self.system_prompt,
            output_type=ScoutOutcome,
            server_name="attackbox",
            server_url=ATTACKBOX_MCP_URL,
            allowed_tools=SCOUT_ALLOWED_TOOLS,
            max_turns=10,
        )

    async def run(self, state: CyberState) -> dict[str, Any]:
        """Execute Scout and map the structured result back into CyberState."""

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
                message="Scout execution failed.",
                exc=exc,
            )


async def scout_node(state: CyberState) -> dict[str, Any]:
    """LangGraph node wrapper for Scout."""

    return await run_agent_node(state, ScoutAgent)
