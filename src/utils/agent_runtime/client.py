"""
OpenRouter client helpers built on the OpenAI Python SDK.
"""

from __future__ import annotations

import asyncio
import logging
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
DEFAULT_RETRY_DELAY_SECONDS = 1.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_LOG_MAX_CHARS = 12000

logger = logging.getLogger(__name__)


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
        "max_retries": 0,
    }
    if timeout_seconds is not None:
        kwargs["timeout"] = timeout_seconds

    return AsyncOpenAI(**kwargs)


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _log_max_chars() -> int:
    return max(500, _env_int("RUNTIME_LOG_MAX_CHARS", DEFAULT_LOG_MAX_CHARS))


def _compact_text(value: Any) -> str:
    text = str(value)
    limit = _log_max_chars()
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... [truncated {len(text) - limit} chars]"


def _response_dump(response: Any) -> str:
    if hasattr(response, "model_dump_json"):
        try:
            return response.model_dump_json(indent=2)
        except TypeError:
            return response.model_dump_json()
        except Exception:
            pass
    if hasattr(response, "model_dump"):
        try:
            import json

            return json.dumps(response.model_dump(), indent=2, default=str)
        except Exception:
            pass
    return str(response)


def _is_rate_limit_error(exc: Exception) -> bool:
    status_code = getattr(exc, "status_code", None)
    if status_code == 429:
        return True
    response = getattr(exc, "response", None)
    if getattr(response, "status_code", None) == 429:
        return True
    text = str(exc).lower()
    return "429" in text or "rate limit" in text or "too many requests" in text


async def create_chat_completion_with_retry(
    *,
    client: Any,
    model: str,
    messages: list[dict[str, Any]],
    purpose: str,
    temperature: float = 0.0,
    tools: list[dict[str, Any]] | None = None,
    tool_choice: str | None = None,
) -> Any:
    """Create a chat completion with visible successful-response logging and 429 retry delay."""

    max_retries = max(0, _env_int("OPENROUTER_MAX_RETRIES", DEFAULT_MAX_RETRIES))
    retry_delay = max(0.0, _env_float("OPENROUTER_RETRY_DELAY_SECONDS", DEFAULT_RETRY_DELAY_SECONDS))

    for attempt in range(max_retries + 1):
        try:
            kwargs: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
            }
            if tools is not None:
                kwargs["tools"] = tools
            if tool_choice is not None:
                kwargs["tool_choice"] = tool_choice
            response = await client.chat.completions.create(**kwargs)
            logger.info(
                "Chat completion result [%s model=%s attempt=%s]: %s",
                purpose,
                model,
                attempt + 1,
                _compact_text(_response_dump(response)),
            )
            return response
        except Exception as exc:
            if not _is_rate_limit_error(exc) or attempt >= max_retries:
                raise
            logger.warning(
                "Chat completion rate limited [%s model=%s attempt=%s/%s]; retrying in %.1fs: %s",
                purpose,
                model,
                attempt + 1,
                max_retries + 1,
                retry_delay,
                exc,
            )
            await asyncio.sleep(retry_delay)

    raise RuntimeError("unreachable chat completion retry state")


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
        or runtime_config.openrouter_model
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
    response = await create_chat_completion_with_retry(
        client=client,
        model=model,
        purpose="chat",
        messages=[
            {"role": "system", "content": system_prompt},
            *(list(history or [])),
            {"role": "user", "content": user_prompt},
        ],
        temperature=temperature,
    )
    return extract_message_text(response.choices[0].message)
