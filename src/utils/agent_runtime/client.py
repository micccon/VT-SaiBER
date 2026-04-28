"""
OpenRouter client helpers built on the OpenAI Python SDK.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Iterable

from src.config import RuntimeConfig, get_runtime_config

try:
    from openai import AsyncOpenAI
except Exception:  # pragma: no cover - optional dependency path
    AsyncOpenAI = None


DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = "nvidia/nemotron-3-super-120b-a12b:free"


@dataclass(frozen=True)
class OpenRouterRuntime:
    """Resolved async client plus model name for agent execution."""

    client: AsyncOpenAI
    model: str


def build_openrouter_client(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    timeout_seconds: int | None = None,
):
    """Build the shared AsyncOpenAI client pointed at OpenRouter."""

    if AsyncOpenAI is None:
        raise RuntimeError("openai is not installed")

    resolved_api_key = (api_key or os.getenv("OPENROUTER_API_KEY", "")).strip()
    if not resolved_api_key:
        raise RuntimeError("OPENROUTER_API_KEY is required for agent LLM calls")

    resolved_base_url = (base_url or os.getenv("OPENROUTER_BASE_URL", DEFAULT_OPENROUTER_BASE_URL)).strip()
    resolved_base_url = resolved_base_url or DEFAULT_OPENROUTER_BASE_URL

    # Keep the client constructor shape centralized so agents only pass config, not raw SDK plumbing.
    kwargs = {
        "api_key": resolved_api_key,
        "base_url": resolved_base_url,
    }
    if timeout_seconds is not None:
        kwargs["timeout"] = timeout_seconds

    return AsyncOpenAI(**kwargs)


def resolve_openrouter_runtime(
    *,
    config: RuntimeConfig | None = None,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    timeout_seconds: int | None = None,
) -> OpenRouterRuntime:
    """Resolve model and client settings from config plus optional overrides."""

    runtime_config = config or get_runtime_config()
    resolved_model = (
        model
        or runtime_config.supervisor_model
        or os.getenv("LLM_MODEL", DEFAULT_MODEL)
    ).strip()
    resolved_model = resolved_model or DEFAULT_MODEL

    client = build_openrouter_client(
        api_key=api_key or runtime_config.openrouter_api_key,
        base_url=base_url or runtime_config.openrouter_base_url,
        timeout_seconds=timeout_seconds or runtime_config.supervisor_timeout_seconds,
    )
    return OpenRouterRuntime(client=client, model=resolved_model)


def try_resolve_openrouter_runtime(
    *,
    config: RuntimeConfig | None = None,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    timeout_seconds: int | None = None,
) -> tuple[OpenRouterRuntime | None, str | None]:
    """Best-effort runtime resolution that returns an error string instead of raising."""

    try:
        return (
            resolve_openrouter_runtime(
                config=config,
                model=model,
                api_key=api_key,
                base_url=base_url,
                timeout_seconds=timeout_seconds,
            ),
            None,
        )
    except Exception as exc:
        return None, str(exc)


async def run_chat_completion(
    *,
    client: Any,
    model: str,
    system_prompt: str,
    user_prompt: str,
    history: Iterable[dict[str, Any]] | None = None,
    temperature: float = 0.0,
) -> str:
    """Run a plain chat-completion turn and return only the assistant text."""

    from src.utils.agent_runtime.transcript import extract_message_text

    # Non-tool agents all flow through the same message shape to keep the runtime uniform.
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            *(list(history or [])),
            {"role": "user", "content": user_prompt},
        ],
        temperature=temperature,
    )
    return extract_message_text(response.choices[0].message)
