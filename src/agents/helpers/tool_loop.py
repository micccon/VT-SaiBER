"""
Shared OpenRouter-backed tool loop for executable agents.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, List

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import StructuredTool

from src.agents.helpers.tool_policy import BaseToolPolicy, ToolInterception
from src.agents.helpers.tool_schema import build_openai_tools, parse_tool_arguments, serialize_tool_result
from src.agents.worker_harness import find_tool, invoke_tool


@dataclass
class ToolLoopResult:
    messages: List[Any]
    final_text: str
    rounds: int


def _assistant_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue
            if isinstance(item, dict):
                text = item.get("text") or item.get("content")
                if isinstance(text, str):
                    parts.append(text)
        return "\n".join(part for part in parts if part).strip()
    return str(content or "")


def _assistant_message_payload(message: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "role": "assistant",
        "content": message.content or "",
    }
    if getattr(message, "tool_calls", None):
        payload["tool_calls"] = [
            {
                "id": tool_call.id,
                "type": "function",
                "function": {
                    "name": tool_call.function.name,
                    "arguments": tool_call.function.arguments,
                },
            }
            for tool_call in message.tool_calls
        ]
    return payload


async def run_agent_tool_loop(
    *,
    client: Any,
    model: str,
    system_prompt: str,
    user_prompt: str,
    tools: Iterable[StructuredTool],
    policy: BaseToolPolicy | None = None,
    max_rounds: int = 8,
    temperature: float = 0.0,
) -> ToolLoopResult:
    """Run a simple assistant/tool loop using OpenRouter via the OpenAI SDK."""
    tool_list = list(tools)
    tool_policy = policy or BaseToolPolicy()
    tool_definitions = build_openai_tools(tool_list)

    conversation: List[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    transcript: List[Any] = []

    for round_number in range(1, max_rounds + 1):
        response = await client.chat.completions.create(
            model=model,
            messages=conversation,
            tools=tool_definitions,
            tool_choice="auto",
            temperature=temperature,
        )
        message = response.choices[0].message
        assistant_text = _assistant_text(message.content)
        tool_calls = getattr(message, "tool_calls", None) or []

        ai_tool_calls = []
        for tool_call in tool_calls:
            try:
                args = parse_tool_arguments(tool_call.function.arguments)
            except Exception:
                args = {}
            ai_tool_calls.append(
                {
                    "id": tool_call.id,
                    "name": tool_call.function.name,
                    "args": args,
                }
            )

        if ai_tool_calls:
            transcript.append(AIMessage(content=assistant_text, tool_calls=ai_tool_calls))
        else:
            transcript.append(AIMessage(content=assistant_text))
        conversation.append(_assistant_message_payload(message))

        if not tool_calls:
            return ToolLoopResult(messages=transcript, final_text=assistant_text, rounds=round_number)

        for tool_call in tool_calls:
            tool_name = tool_call.function.name
            try:
                call_arguments = parse_tool_arguments(tool_call.function.arguments)
            except Exception as exc:
                payload = {
                    "status": "error",
                    "summary": f"Invalid tool arguments for {tool_name}",
                    "raw": str(exc),
                }
                serialized = serialize_tool_result(payload)
                transcript.append(ToolMessage(tool_call_id=tool_call.id, name=tool_name, content=serialized))
                conversation.append({"role": "tool", "tool_call_id": tool_call.id, "content": serialized})
                continue

            tool = find_tool(tool_list, tool_name)
            if tool is None:
                payload = {
                    "status": "error",
                    "summary": f"Requested tool {tool_name} is unavailable to this agent.",
                }
                serialized = serialize_tool_result(payload)
                transcript.append(ToolMessage(tool_call_id=tool_call.id, name=tool_name, content=serialized))
                conversation.append({"role": "tool", "tool_call_id": tool_call.id, "content": serialized})
                continue

            intercepted = await tool_policy.before_call(tool, call_arguments)
            if isinstance(intercepted, ToolInterception):
                tool_result = intercepted.payload
            else:
                raw_result = await invoke_tool(tool, **call_arguments)
                tool_result = await tool_policy.after_call(tool, call_arguments, raw_result)

            serialized = serialize_tool_result(tool_result)
            transcript.append(ToolMessage(tool_call_id=tool_call.id, name=tool_name, content=serialized))
            conversation.append({"role": "tool", "tool_call_id": tool_call.id, "content": serialized})

    return ToolLoopResult(messages=transcript, final_text="", rounds=max_rounds)
