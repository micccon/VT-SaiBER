"""Shared contracts for the v2 execution architecture."""

from .chat import ChatSynthesisResult, ChatSynthesisSpec
from .execution import (
    AgentExecutionSpec,
    ApprovalEvent,
    ExecutionResult,
    LocalToolSpec,
    MCPServerConfig,
    ModelConfig,
    ToolCallInterception,
    ToolEvent,
    ToolSpec,
)

__all__ = [
    "AgentExecutionSpec",
    "ApprovalEvent",
    "ChatSynthesisResult",
    "ChatSynthesisSpec",
    "ExecutionResult",
    "LocalToolSpec",
    "MCPServerConfig",
    "ModelConfig",
    "ToolCallInterception",
    "ToolEvent",
    "ToolSpec",
]
