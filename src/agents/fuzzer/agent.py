"""Fuzzer agent built on the execution framework."""

from __future__ import annotations

from typing import Any

from src.state.cyber_state import CyberState
from src.agents.common import (
    build_single_mcp_execution_spec,
    execution_error_update,
    run_agent_node,
    validation_error_update,
)
from src.agents.fuzzer.constants import ATTACKBOX_MCP_URL, FUZZER_ALLOWED_TOOLS, fuzzer_SYSTEM_PROMPT
from src.agents.fuzzer.context import build_fuzzer_context, build_target_url, pick_web_target
from src.agents.fuzzer.mapper import map_execution_result_to_state
from src.agents.fuzzer.outcome import FuzzerOutcome
from src.runtime import AgentsSDKExecutionRunner
from src.runtime.contracts import AgentExecutionSpec


class FuzzerAgent:
    """Structured-output Fuzzer implementation on the stack."""

    def __init__(
        self,
        *,
        sdk_module: Any | None = None,
        execution_runner: AgentsSDKExecutionRunner | None = None,
    ):
        self.name = "fuzzer"
        self._runner = execution_runner or AgentsSDKExecutionRunner(sdk_module=sdk_module)

    @property
    def system_prompt(self) -> str:
        return fuzzer_SYSTEM_PROMPT

    def build_execution_spec(self) -> AgentExecutionSpec[FuzzerOutcome]:
        """Build the execution declaration for Fuzzer."""

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
        """Execute Fuzzer and map the structured result back into CyberState."""

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
                context={**state, "_base_url": base_url},
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
                message="Fuzzer execution failed.",
                exc=exc,
            )


async def fuzzer_node(state: CyberState) -> dict[str, Any]:
    """LangGraph node wrapper for Fuzzer."""

    return await run_agent_node(state, FuzzerAgent)
