"""
Shared tool policy hooks for executable agent loops.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ToolInterception:
    """Short-circuit a tool call with a synthetic payload."""

    payload: Any


class BaseToolPolicy:
    """Optional hooks around shared tool execution."""

    async def before_call(self, tool: Any, arguments: dict[str, Any]) -> ToolInterception | None:
        return None

    async def after_call(self, tool: Any, arguments: dict[str, Any], raw_result: Any) -> Any:
        return raw_result
