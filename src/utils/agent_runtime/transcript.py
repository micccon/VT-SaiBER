"""
Transcript helpers for framework-neutral agent execution.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, Iterator, Tuple

from src.utils.parsers import normalize_tool_result


def extract_message_text(message: Any) -> str:
    content = message
    if isinstance(message, dict):
        content = message.get("content", "")
    elif hasattr(message, "content"):
        content = getattr(message, "content", "")

    if isinstance(content, dict):
        text = content.get("content") or content.get("text")
        if isinstance(text, str):
            return text
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
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


def make_assistant_message(content: str, tool_calls: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "role": "assistant",
        "content": content or "",
    }
    if tool_calls:
        payload["tool_calls"] = tool_calls
    return payload


def make_tool_message(name: str, tool_call_id: str, content: Any) -> dict[str, Any]:
    return {
        "role": "tool",
        "name": name,
        "tool_call_id": tool_call_id,
        "content": content,
    }


def collect_reasoning_chunks(messages: Iterable[Any]) -> list[str]:
    chunks: list[str] = []
    for message in messages:
        if isinstance(message, dict) and message.get("role") == "tool":
            continue
        text = extract_message_text(message)
        if text:
            chunks.append(text)
    return chunks


def iter_tool_messages(messages: Iterable[Any]) -> Iterator[Tuple[Dict[str, Any], Dict[str, Any]]]:
    for message in messages:
        if not isinstance(message, dict) or message.get("role") != "tool":
            continue

        content = message.get("content")
        normalized = normalize_tool_result(content)
        if not normalized and isinstance(content, str):
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                parsed = {}
            if isinstance(parsed, dict):
                normalized = parsed

        yield message, normalized
