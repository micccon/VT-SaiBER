"""Shared runtime data models for tool execution."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable


@dataclass
class RuntimeTool:
    """Framework-neutral representation of an MCP-discovered tool."""

    # Public tool name exposed to the model.
    name: str
    # Human-readable description used in OpenAI tool definitions.
    description: str
    # JSON schema describing accepted arguments.
    input_schema: dict[str, Any]
    # Async executor that actually calls through to the MCP bridge.
    executor: Callable[..., Awaitable[Any]]
    # Default argument values advertised by the underlying MCP tool.
    defaults: dict[str, Any] = field(default_factory=dict)
