"""
Shared attackbox worker harness for executable agents.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Iterable, List, Optional

from langchain_core.tools import StructuredTool

from src.mcp.mcp_tool_bridge import get_mcp_bridge
from src.utils.parsers import normalize_tool_result


class WorkerHarnessError(RuntimeError):
    """Raised when attackbox tool loading fails."""


async def load_filtered_tools(allowed_tools: Iterable[str]) -> List[StructuredTool]:
    """
    Load and filter attackbox tools for one worker.
    """
    bridge = await get_mcp_bridge()
    return bridge.get_tools_for_agent(set(allowed_tools))


def find_tool(tools: Iterable[StructuredTool], *names: str) -> Optional[StructuredTool]:
    """
    Locate a tool by exact name, preserving declared server names.
    """
    candidates = {name for name in names if name}
    for tool in tools:
        if tool.name in candidates:
            return tool
    return None


async def invoke_tool(tool: StructuredTool, **kwargs: Any) -> Any:
    """
    Execute a StructuredTool regardless of sync/async implementation.
    """
    if tool.coroutine is not None:
        return await tool.coroutine(**kwargs)
    if tool.func is not None:
        return await asyncio.to_thread(tool.func, **kwargs)
    raise WorkerHarnessError(f"Tool {tool.name} has no callable handler")


async def call_tool(tool: StructuredTool, **kwargs: Any) -> Dict[str, Any]:
    """
    Execute a tool and normalize the response into a dictionary when possible.
    """
    raw = await invoke_tool(tool, **kwargs)
    normalized = normalize_tool_result(raw)
    if normalized:
        return normalized
    if isinstance(raw, dict):
        return raw
    return {"status": "error", "summary": f"Tool {tool.name} returned a non-JSON payload", "raw": raw}


def tool_names(tools: Iterable[StructuredTool]) -> set[str]:
    return {tool.name for tool in tools}
