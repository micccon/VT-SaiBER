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

NO_RECON_TOOL_ERROR = "Scout v2 did not execute a reconnaissance tool."


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
            max_turns=10,
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
            updates = await self._run_once(state, context)
            if _has_validation_error(updates, NO_RECON_TOOL_ERROR):
                retry_context = (
                    f"{context}\n\n"
                    "CORRECTION: The previous attempt failed because no reconnaissance tool was called. "
                    "Call recon_service_probe exactly once for the concrete target in scope, then return ScoutOutcome."
                )
                updates = await self._run_once(state, retry_context)
            return updates
        except Exception as exc:
            return execution_error_update(
                state,
                agent_name=self.name,
                message="Scout v2 execution failed.",
                exc=exc,
            )

    async def _run_once(self, state: CyberState, context: str) -> dict[str, Any]:
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


def _has_validation_error(updates: dict[str, Any], message: str) -> bool:
    """Check whether a mapped update contains a specific validation error."""

    for error in updates.get("errors", []) or []:
        if getattr(error, "error", "") == message:
            return True
    return False


async def scout_v2_node(state: CyberState) -> dict[str, Any]:
    """LangGraph node wrapper for Scout v2."""

    return await run_v2_agent_node(state, ScoutV2Agent)
