"""Typed contracts for the v2 execution framework."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Generic, TypeVar

TOutcome = TypeVar("TOutcome")


@dataclass(frozen=True)
class ModelConfig:
    """Resolved model configuration for one agent execution."""

    model: str
    api_key: str
    base_url: str
    timeout_seconds: int | None = None
    temperature: float = 0.0
    trace_include_sensitive_data: bool = False


@dataclass(frozen=True)
class MCPServerConfig:
    """One MCP server the v2 runner should connect to directly."""

    name: str
    url: str
    allowed_tools: set[str] = field(default_factory=set)
    approval_required_tools: set[str] = field(default_factory=set)
    cache_tools_list: bool = True


@dataclass(frozen=True)
class LocalToolSpec:
    """A local function tool surfaced through the Agents SDK."""

    name: str
    description: str
    input_schema: dict[str, Any]
    executor: Callable[..., Awaitable[Any]]
    defaults: dict[str, Any] = field(default_factory=dict)
    approval_required: bool = False


@dataclass(frozen=True)
class ToolSpec:
    """Normalized runtime tool surfaced to the runner."""

    name: str
    description: str
    input_schema: dict[str, Any]
    executor: Callable[..., Awaitable[Any]]
    source: str
    defaults: dict[str, Any] = field(default_factory=dict)
    server_name: str | None = None
    approval_required: bool = False


@dataclass(frozen=True)
class AgentExecutionSpec(Generic[TOutcome]):
    """Declarative description of one v2 agent run."""

    agent_name: str
    instructions: str
    model: ModelConfig
    output_type: type[TOutcome]
    mcp_servers: list[MCPServerConfig] = field(default_factory=list)
    local_tools: list[LocalToolSpec] = field(default_factory=list)
    max_turns: int = 8


@dataclass(frozen=True)
class ToolCallInterception:
    """Synthetic tool payload returned before a tool executes."""

    payload: Any
    reason: str | None = None


@dataclass(frozen=True)
class ApprovalEvent:
    """Approval decision captured during a tool call."""

    tool_name: str
    approved: bool
    reason: str
    server_name: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass(frozen=True)
class ToolEvent:
    """Normalized telemetry for one tool call."""

    tool_name: str
    invocation: dict[str, Any]
    source: str
    status: str
    result: dict[str, Any]
    server_name: str | None = None
    approval_required: bool = False
    approved: bool | None = None
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ExecutionResult(Generic[TOutcome]):
    """Typed result returned by the v2 execution runner."""

    outcome: TOutcome
    tool_events: list[ToolEvent] = field(default_factory=list)
    approval_events: list[ApprovalEvent] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    raw_result: Any = None
