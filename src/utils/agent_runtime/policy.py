"""
Shared policy hooks for guarded tool execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.utils.agent_runtime.models import RuntimeTool


@dataclass
class ToolInterception:
    payload: Any


class BaseToolPolicy:
    async def before_call(
        self,
        tool: RuntimeTool,
        arguments: dict[str, Any],
    ) -> ToolInterception | None:
        return None

    async def after_call(
        self,
        tool: RuntimeTool,
        arguments: dict[str, Any],
        raw_result: Any,
    ) -> Any:
        return raw_result
