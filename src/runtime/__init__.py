"""Shared runtime surface for promoted agent execution."""

from .approval import derive_command_target, require_manual_approval
from .chat import ChatSynthesisRunner
from .contracts import (
    AgentExecutionSpec,
    ApprovalEvent,
    ChatSynthesisResult,
    ChatSynthesisSpec,
    ExecutionResult,
    LocalToolSpec,
    MCPServerConfig,
    ModelConfig,
    ToolCallInterception,
    ToolEvent,
    ToolSpec,
)
from .execution import AgentsSDKExecutionRunner, ExecutionPolicy
from .tracing import (
    TraceSettings,
    get_trace_settings,
    trace_execution_result,
    trace_execution_start,
    trace_failure,
    trace_synthesis_result,
    trace_synthesis_start,
)

__all__ = [
    "AgentExecutionSpec",
    "AgentsSDKExecutionRunner",
    "ApprovalEvent",
    "ChatSynthesisResult",
    "ChatSynthesisRunner",
    "ChatSynthesisSpec",
    "ExecutionPolicy",
    "ExecutionResult",
    "LocalToolSpec",
    "MCPServerConfig",
    "ModelConfig",
    "ToolCallInterception",
    "ToolEvent",
    "ToolSpec",
    "TraceSettings",
    "derive_command_target",
    "get_trace_settings",
    "require_manual_approval",
    "trace_execution_result",
    "trace_execution_start",
    "trace_failure",
    "trace_synthesis_result",
    "trace_synthesis_start",
]
