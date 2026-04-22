"""
Shared LangChain chat-model helpers.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage

try:
    from langchain_openai import ChatOpenAI
except Exception:  # pragma: no cover - optional dependency path
    ChatOpenAI = None


DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_LLM_MODEL = "nvidia/nemotron-3-super-120b-a12b:free"


def build_chat_openai(
    *,
    model: str | None = None,
    base_url: str | None = None,
    temperature: float = 0.0,
    timeout_seconds: int | None = None,
):
    """Build the shared ChatOpenAI client used across agent LLM calls."""
    if ChatOpenAI is None:
        raise RuntimeError("langchain-openai is not installed")

    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is required for agent LLM calls")

    resolved_model = (model or os.getenv("LLM_MODEL", DEFAULT_LLM_MODEL)).strip()
    resolved_base_url = (base_url or os.getenv("OPENROUTER_BASE_URL", DEFAULT_OPENROUTER_BASE_URL)).strip()
    resolved_base_url = resolved_base_url or DEFAULT_OPENROUTER_BASE_URL

    kwargs: Dict[str, Any] = {
        "model": resolved_model,
        "api_key": api_key,
        "base_url": resolved_base_url,
        "temperature": temperature,
    }
    if timeout_seconds is not None:
        kwargs["timeout"] = timeout_seconds

    return ChatOpenAI(**kwargs)


def to_langchain_messages(messages: Iterable[Dict[str, Any]]) -> List[BaseMessage]:
    """Convert stored role/content dicts into LangChain chat messages."""
    converted: List[BaseMessage] = []
    for message in messages:
        if not isinstance(message, dict):
            continue

        role = str(message.get("role", "")).strip().lower()
        content = str(message.get("content", ""))

        if role == "system":
            converted.append(SystemMessage(content=content))
        elif role == "user":
            converted.append(HumanMessage(content=content))
        elif role == "assistant":
            converted.append(AIMessage(content=content))

    return converted


def extract_text_content(message: Any) -> str:
    """Normalize LangChain message content into plain text."""
    content = getattr(message, "content", message)
    if isinstance(content, dict):
        text = content.get("content") or content.get("text")
        if isinstance(text, str):
            return text
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
