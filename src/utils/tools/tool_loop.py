"""Shared OpenRouter-backed tool loop for executable agents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, List

from src.utils.agent_runtime.transcript import extract_message_text, make_assistant_message, make_tool_message
from src.utils.tools.loader import (
    build_openai_tools,
    find_tool,
    invoke_tool,
    load_filtered_tools,
    normalize_tool_payload,
    parse_tool_arguments,
    serialize_tool_result,
    tool_names,
)
from src.utils.tools.models import RuntimeTool
from src.utils.tools.policy import BaseToolPolicy, ToolInterception


@dataclass
class ToolLoopResult:
    """Transcript plus final text returned by the shared tool loop."""

    messages: List[dict[str, Any]]
    final_text: str
    rounds: int


async def run_tool_worker(
    *,
    client: Any,
    model: str,
    system_prompt: str,
    user_prompt: str,
    allowed_tools: Iterable[str],
    required_tools: Iterable[str] | None = None,
    policy: BaseToolPolicy | None = None,
    max_rounds: int = 8,
    temperature: float = 0.0,
) -> ToolLoopResult:
    """Load allowed MCP tools, validate requirements, and run the shared tool loop."""

    tools = await load_filtered_tools(allowed_tools)
    if not tools:
        raise RuntimeError("No allowed tools were available from the MCP bridge")

    missing = sorted(set(required_tools or ()) - tool_names(tools))
    if missing:
        raise RuntimeError(f"Required tool(s) missing from bridge: {', '.join(missing)}")

    return await run_agent_tool_loop(
        client=client,
        model=model,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        tools=tools,
        policy=policy,
        max_rounds=max_rounds,
        temperature=temperature,
    )


async def run_agent_tool_loop(
    *,
    client: Any,
    model: str,
    system_prompt: str,
    user_prompt: str,
    tools: Iterable[RuntimeTool],
    policy: BaseToolPolicy | None = None,
    max_rounds: int = 8,
    temperature: float = 0.0,
) -> ToolLoopResult:
    """Drive the OpenAI tool-calling loop for executable agents."""

    tool_list = list(tools)
    tool_policy = policy or BaseToolPolicy()
    tool_definitions = build_openai_tools(tool_list)

    conversation: List[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    transcript: List[dict[str, Any]] = []

    # Each round asks the model what to do next, then executes any requested tools and feeds results back.
    for round_number in range(1, max_rounds + 1):
        response = await client.chat.completions.create(
            model=model,
            messages=conversation,
            tools=tool_definitions,
            tool_choice="auto",
            temperature=temperature,
        )
        message = response.choices[0].message
        assistant_text = extract_message_text(message)
        tool_calls = getattr(message, "tool_calls", None) or []

        transcript_tool_calls: list[dict[str, Any]] = []
        conversation_tool_calls: list[dict[str, Any]] = []
        for tool_call in tool_calls:
            try:
                args = parse_tool_arguments(tool_call.function.arguments)
            except Exception:
                args = {}
            transcript_tool_calls.append(
                {
                    "id": tool_call.id,
                    "name": tool_call.function.name,
                    "args": args,
                }
            )
            conversation_tool_calls.append(
                {
                    "id": tool_call.id,
                    "type": "function",
                    "function": {
                        "name": tool_call.function.name,
                        "arguments": tool_call.function.arguments,
                    },
                }
            )

        transcript.append(make_assistant_message(assistant_text, transcript_tool_calls or None))

        assistant_payload: dict[str, Any] = {
            "role": "assistant",
            "content": assistant_text or "",
        }
        if conversation_tool_calls:
            assistant_payload["tool_calls"] = conversation_tool_calls
        conversation.append(assistant_payload)

        if not tool_calls:
            # No more tool calls means the assistant has reached its final answer for this turn.
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
                transcript.append(make_tool_message(tool_name, tool_call.id, payload))
                conversation.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": serialize_tool_result(payload),
                })
                continue

            tool = find_tool(tool_list, tool_name)
            if tool is None:
                payload = {
                    "status": "error",
                    "summary": f"Requested tool {tool_name} is unavailable to this agent.",
                    "invocation": call_arguments,
                }
                transcript.append(make_tool_message(tool_name, tool_call.id, payload))
                conversation.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": serialize_tool_result(payload),
                })
                continue

            # Policies can block or replace execution for approval gates, retry limits, or guardrails.
            intercepted = await tool_policy.before_call(tool, call_arguments)
            if isinstance(intercepted, ToolInterception):
                tool_result = normalize_tool_payload(
                    intercepted.payload,
                    tool_name=tool_name,
                    invocation=call_arguments,
                )
            else:
                raw_result = await invoke_tool(tool, **call_arguments)
                policy_result = await tool_policy.after_call(tool, call_arguments, raw_result)
                tool_result = normalize_tool_payload(
                    policy_result,
                    tool_name=tool_name,
                    invocation=call_arguments,
                )

            transcript.append(make_tool_message(tool_name, tool_call.id, tool_result))
            conversation.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": serialize_tool_result(tool_result),
            })

    return ToolLoopResult(messages=transcript, final_text="", rounds=max_rounds)
