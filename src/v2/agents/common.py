"""Shared helper functions for thin v2 specialist agents."""

from __future__ import annotations

from typing import Any, Callable, TypeVar

from src.config import get_runtime_config
from src.state.cyber_state import CyberState
from src.state.models import AgentError
from src.v2.contracts.execution import AgentExecutionSpec, MCPServerConfig, ModelConfig

TOutcome = TypeVar("TOutcome")


def build_default_model_config(*, temperature: float = 0.0) -> ModelConfig:
    """Build the standard model configuration for one v2 specialist run."""

    config = get_runtime_config()
    return ModelConfig(
        model=config.openrouter_model,
        api_key=config.openrouter_api_key,
        base_url=config.openrouter_base_url,
        timeout_seconds=config.supervisor_timeout_seconds,
        temperature=temperature,
        trace_include_sensitive_data=False,
    )


def build_single_mcp_execution_spec(
    *,
    agent_name: str,
    instructions: str,
    output_type: type[TOutcome],
    server_name: str,
    server_url: str,
    allowed_tools: set[str] | list[str],
    approval_required_tools: set[str] | list[str] | None = None,
    max_turns: int = 8,
    temperature: float = 0.0,
) -> AgentExecutionSpec[TOutcome]:
    """Build the standard single-MCP-server execution spec for a v2 specialist."""

    return AgentExecutionSpec(
        agent_name=agent_name,
        instructions=instructions,
        model=build_default_model_config(temperature=temperature),
        output_type=output_type,
        mcp_servers=[
            MCPServerConfig(
                name=server_name,
                url=server_url,
                allowed_tools=set(allowed_tools),
                approval_required_tools=set(approval_required_tools or []),
            )
        ],
        max_turns=max_turns,
    )


def validation_error_update(
    state: CyberState,
    *,
    agent_name: str,
    message: str,
    recoverable: bool = True,
) -> dict[str, Any]:
    """Return the standard v2 validation error update."""

    return {
        "current_agent": agent_name,
        "iteration_count": int(state.get("iteration_count", 0)) + 1,
        "errors": [
            AgentError(
                agent=agent_name,
                error_type="ValidationError",
                error=message,
                recoverable=recoverable,
            )
        ],
    }


def execution_error_update(
    state: CyberState,
    *,
    agent_name: str,
    message: str,
    exc: Exception,
    recoverable: bool = False,
) -> dict[str, Any]:
    """Return the standard v2 execution failure update."""

    return {
        "current_agent": agent_name,
        "iteration_count": int(state.get("iteration_count", 0)) + 1,
        "errors": [
            AgentError(
                agent=agent_name,
                error_type="LLMError",
                error=f"{message} {exc}",
                recoverable=recoverable,
            )
        ],
    }


async def run_v2_agent_node(
    state: CyberState,
    agent_factory: Callable[[], Any],
) -> dict[str, Any]:
    """Run one v2 specialist node and persist its state delta."""

    from src.database.persistence import persist_state_update

    updates = await agent_factory().run(state)
    persist_state_update(state, updates)
    return updates
