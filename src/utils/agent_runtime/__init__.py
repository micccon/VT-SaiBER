"""
Shared agent runtime built on the OpenAI SDK + OpenRouter.
"""

from .client import (
    OpenRouterRuntime,
    build_openrouter_client,
    resolve_openrouter_runtime,
    run_chat_completion,
    try_resolve_openrouter_runtime,
)
from .transcript import (
    collect_reasoning_chunks,
    extract_message_text,
    iter_tool_messages,
    make_assistant_message,
    make_tool_message,
)
from src.utils.tools import (
    BaseToolPolicy,
    RuntimeTool,
    ToolInterception,
    ToolLoopResult,
    build_openai_tools,
    call_tool,
    find_tool,
    invoke_tool,
    load_filtered_tools,
    normalize_tool_payload,
    parse_tool_arguments,
    run_agent_tool_loop,
    run_tool_worker,
    serialize_tool_result,
    tool_names,
)

__all__ = [
    "BaseToolPolicy",
    "OpenRouterRuntime",
    "RuntimeTool",
    "ToolInterception",
    "ToolLoopResult",
    "build_openai_tools",
    "build_openrouter_client",
    "call_tool",
    "collect_reasoning_chunks",
    "extract_message_text",
    "find_tool",
    "invoke_tool",
    "iter_tool_messages",
    "load_filtered_tools",
    "make_assistant_message",
    "make_tool_message",
    "normalize_tool_payload",
    "parse_tool_arguments",
    "resolve_openrouter_runtime",
    "run_chat_completion",
    "run_agent_tool_loop",
    "run_tool_worker",
    "serialize_tool_result",
    "tool_names",
    "try_resolve_openrouter_runtime",
]
