"""
Shared transcript helpers for executable-agent result extraction.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Iterator, Tuple

from langchain_core.messages import ToolMessage

from src.utils.llm import extract_text_content
from src.utils.parsers import normalize_tool_result


def collect_reasoning_chunks(messages: Iterable[Any]) -> list[str]:
    chunks: list[str] = []
    for message in messages:
        if isinstance(message, ToolMessage):
            continue
        text = extract_text_content(message)
        if text:
            chunks.append(text)
    return chunks


def iter_tool_payloads(messages: Iterable[Any]) -> Iterator[Tuple[ToolMessage, Dict[str, Any]]]:
    for message in messages:
        if not isinstance(message, ToolMessage):
            continue
        yield message, normalize_tool_result(message.content)
