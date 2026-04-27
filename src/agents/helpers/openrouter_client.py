"""
OpenRouter client helpers built on the OpenAI Python SDK.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from src.config import RuntimeConfig, get_runtime_config

try:
    from openai import AsyncOpenAI
except Exception:  # pragma: no cover - optional dependency path
    AsyncOpenAI = None


DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = "nvidia/nemotron-3-super-120b-a12b:free"


@dataclass(frozen=True)
class OpenRouterRuntime:
    client: AsyncOpenAI
    model: str


def build_openrouter_client(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    timeout_seconds: int | None = None,
):
    """Build a reusable AsyncOpenAI client pointed at OpenRouter."""
    if AsyncOpenAI is None:
        raise RuntimeError("openai is not installed")

    resolved_api_key = (api_key or os.getenv("OPENROUTER_API_KEY", "")).strip()
    if not resolved_api_key:
        raise RuntimeError("OPENROUTER_API_KEY is required for agent LLM calls")

    resolved_base_url = (base_url or os.getenv("OPENROUTER_BASE_URL", DEFAULT_OPENROUTER_BASE_URL)).strip()
    resolved_base_url = resolved_base_url or DEFAULT_OPENROUTER_BASE_URL

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
    """Resolve the client + model tuple used by an executable agent."""
    runtime_config = config or get_runtime_config()
    resolved_model = (model or runtime_config.supervisor_model or os.getenv("LLM_MODEL", DEFAULT_MODEL)).strip()
    resolved_model = resolved_model or DEFAULT_MODEL

    client = build_openrouter_client(
        api_key=api_key or runtime_config.openrouter_api_key,
        base_url=base_url or runtime_config.openrouter_base_url,
        timeout_seconds=timeout_seconds or runtime_config.supervisor_timeout_seconds,
    )
    return OpenRouterRuntime(client=client, model=resolved_model)
