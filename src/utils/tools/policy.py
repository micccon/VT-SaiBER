"""Shared policy hooks for guarded tool execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.utils.tools.models import RuntimeTool


@dataclass
class ToolInterception:
    """Synthetic tool result returned by a policy before a tool executes."""

    payload: Any


class BaseToolPolicy:
    """Hook surface for agents that need approval, retry, or budget controls."""

    async def before_call(
        self,
        tool: RuntimeTool,
        arguments: dict[str, Any],
    ) -> ToolInterception | None:
        """Inspect an impending tool call and optionally replace/block it."""

        return None

    async def after_call(
        self,
        tool: RuntimeTool,
        arguments: dict[str, Any],
        raw_result: Any,
    ) -> Any:
        """Inspect or rewrite a tool result after execution."""

        return raw_result
