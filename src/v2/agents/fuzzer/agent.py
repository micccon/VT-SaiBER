"""Fuzzer v2 agent built on the v2 execution framework."""

from __future__ import annotations

from typing import Any

from src.state.cyber_state import CyberState
from src.v2.agents.common import (
    build_single_mcp_execution_spec,
    execution_error_update,
    run_v2_agent_node,
    validation_error_update,
)
from src.v2.agents.fuzzer.constants import ATTACKBOX_MCP_URL, FUZZER_ALLOWED_TOOLS, FUZZER_V2_SYSTEM_PROMPT
from src.v2.agents.fuzzer.context import build_fuzzer_context, build_target_url, pick_web_target
from src.v2.agents.fuzzer.mapper import map_execution_result_to_state
from src.v2.agents.fuzzer.outcome import FuzzerOutcome
from src.v2.contracts.execution import AgentExecutionSpec
from src.v2.execution import AgentsSDKExecutionRunner


class FuzzerV2Agent:
    """Structured-output Fuzzer implementation on the parallel v2 stack."""

    def __init__(
        self,
        *,
        sdk_module: Any | None = None,
        execution_runner: AgentsSDKExecutionRunner | None = None,
    ):
        self.name = "fuzzer_v2"
        self._runner = execution_runner or AgentsSDKExecutionRunner(sdk_module=sdk_module)

    @property
    def system_prompt(self) -> str:
        return FUZZER_V2_SYSTEM_PROMPT

    def build_execution_spec(self) -> AgentExecutionSpec[FuzzerOutcome]:
        """Build the v2 execution declaration for Fuzzer."""

        return build_single_mcp_execution_spec(
            agent_name=self.name,
            instructions=self.system_prompt,
            output_type=FuzzerOutcome,
            server_name="attackbox",
            server_url=ATTACKBOX_MCP_URL,
            allowed_tools=FUZZER_ALLOWED_TOOLS,
            max_turns=5,
        )

    async def run(self, state: CyberState) -> dict[str, Any]:
        """Execute Fuzzer v2 and map the structured result back into CyberState."""

        target = pick_web_target(state.get("discovered_targets", {}) or {})
        if target is None:
            return validation_error_update(
                state,
                agent_name=self.name,
                message="No HTTP/HTTPS service found in discovered_targets",
            )

        base_url = build_target_url(target)
        context = build_fuzzer_context(state, base_url)
        try:
            result = await self._runner.run(
                self.build_execution_spec(),
                user_input=context,
                context={**state, "_v2_base_url": base_url},
            )
            if not result.outcome.base_url:
                result.outcome.base_url = base_url
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
                message="Fuzzer v2 execution failed.",
                exc=exc,
            )


async def fuzzer_v2_node(state: CyberState) -> dict[str, Any]:
    """LangGraph node wrapper for Fuzzer v2."""

    return await run_v2_agent_node(state, FuzzerV2Agent)
