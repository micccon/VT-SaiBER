"""Policy hooks for guarded v2 tool execution."""

from __future__ import annotations

from typing import Any

from src.v2.contracts.execution import ToolCallInterception, ToolSpec


class ExecutionPolicy:
    """Hook surface for approvals, guardrails, and result validation."""

    async def approve_tool_call(self, tool: ToolSpec, arguments: dict[str, Any]) -> bool:
        """Return True when an approval-required call may proceed."""

        return True

    async def before_tool_call(
        self,
        tool: ToolSpec,
        arguments: dict[str, Any],
    ) -> ToolCallInterception | None:
        """Inspect an impending call and optionally replace or block it."""

        return None

    async def after_tool_call(
        self,
        tool: ToolSpec,
        arguments: dict[str, Any],
        raw_result: Any,
    ) -> Any:
        """Inspect or rewrite a raw tool result after execution."""

        return raw_result
