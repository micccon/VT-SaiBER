"""
Shared runtime helpers for executable agents.
"""

from .openrouter_client import OpenRouterRuntime, build_openrouter_client, resolve_openrouter_runtime
from .result_extract import collect_reasoning_chunks, iter_tool_payloads
from .tool_loop import ToolLoopResult, run_agent_tool_loop
from .tool_policy import BaseToolPolicy, ToolInterception
from .tool_schema import build_openai_tools, serialize_tool_result

__all__ = [
    "BaseToolPolicy",
    "OpenRouterRuntime",
    "ToolInterception",
    "ToolLoopResult",
    "build_openai_tools",
    "build_openrouter_client",
    "collect_reasoning_chunks",
    "iter_tool_payloads",
    "resolve_openrouter_runtime",
    "run_agent_tool_loop",
    "serialize_tool_result",
]
