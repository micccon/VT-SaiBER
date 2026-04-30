"""Production tracing for runtime lanes."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from src.core.parsers import to_jsonable
from src.runtime.contracts import ChatSynthesisResult, ExecutionResult

LOGGER = logging.getLogger("src.trace")
SENSITIVE_KEY_PARTS = ("api_key", "apikey", "authorization", "bearer", "password", "secret", "token")


@dataclass(frozen=True)
class TraceSettings:
    """Runtime tracing controls for lanes."""

    enabled: bool = False
    include_raw: bool = False
    max_chars: int = 2000


def get_trace_settings() -> TraceSettings:
    """Read tracing settings from the shared runtime config."""

    try:
        from src.config import get_runtime_config

        config = get_runtime_config()
        return TraceSettings(
            enabled=bool(getattr(config, "trace_enabled", False)),
            include_raw=bool(getattr(config, "trace_include_raw", False)),
            max_chars=max(200, int(getattr(config, "trace_max_chars", 2000) or 2000)),
        )
    except Exception:
        return TraceSettings()


def trace_execution_start(
    *,
    agent_name: str,
    model: str,
    mcp_server_count: int,
    local_tool_count: int,
    max_turns: int,
) -> None:
    """Log the start of a tool-execution run."""

    settings = get_trace_settings()
    if not settings.enabled:
        return
    _emit(
        "execution_start",
        {
            "agent": agent_name,
            "model": model,
            "mcp_servers": mcp_server_count,
            "local_tools": local_tool_count,
            "max_turns": max_turns,
        },
        settings=settings,
    )


def trace_execution_result(*, agent_name: str, result: ExecutionResult[Any]) -> None:
    """Log a compact summary of a tool-execution result."""

    settings = get_trace_settings()
    if not settings.enabled:
        return
    tool_events = [
        {
            "tool": event.tool_name,
            "source": event.source,
            "server": event.server_name,
            "status": event.status,
            "approval_required": event.approval_required,
            "approved": event.approved,
            "invocation": _redact(event.invocation),
            "artifact_count": len(event.artifacts),
            "result": _maybe_payload(event.result, settings=settings),
        }
        for event in result.tool_events
    ]
    approval_events = [
        {
            "tool": event.tool_name,
            "server": event.server_name,
            "approved": event.approved,
            "reason": event.reason,
            "timestamp": event.timestamp,
        }
        for event in result.approval_events
    ]
    _emit(
        "execution_result",
        {
            "agent": agent_name,
            "outcome": _maybe_payload(result.outcome, settings=settings),
            "tool_events": tool_events,
            "approval_events": approval_events,
            "artifact_count": len(result.artifacts),
            "raw_result": _maybe_payload(result.raw_result, settings=settings) if settings.include_raw else "<disabled>",
        },
        settings=settings,
    )


def trace_synthesis_start(*, agent_name: str, model: str, history_count: int) -> None:
    """Log the start of a chat/synthesis run."""

    settings = get_trace_settings()
    if not settings.enabled:
        return
    _emit(
        "synthesis_start",
        {"agent": agent_name, "model": model, "history_messages": history_count},
        settings=settings,
    )


def trace_synthesis_result(*, agent_name: str, result: ChatSynthesisResult[Any]) -> None:
    """Log a compact summary of a chat/synthesis result."""

    settings = get_trace_settings()
    if not settings.enabled:
        return
    _emit(
        "synthesis_result",
        {
            "agent": agent_name,
            "outcome": _maybe_payload(result.outcome, settings=settings),
            "raw_text": _maybe_payload(result.raw_text, settings=settings) if settings.include_raw else "<disabled>",
            "raw_result": _maybe_payload(result.raw_result, settings=settings) if settings.include_raw else "<disabled>",
        },
        settings=settings,
    )


def trace_failure(*, lane: str, agent_name: str, exc: Exception) -> None:
    """Log a runner failure without dumping raw request state."""

    settings = get_trace_settings()
    if not settings.enabled:
        return
    _emit(
        "run_failure",
        {"lane": lane, "agent": agent_name, "error_type": type(exc).__name__, "message": str(exc)},
        settings=settings,
    )


def _emit(event: str, payload: dict[str, Any], *, settings: TraceSettings) -> None:
    envelope = {"event": event, **payload}
    LOGGER.info("agent_trace %s", _preview(envelope, max_chars=settings.max_chars))


def _maybe_payload(value: Any, *, settings: TraceSettings) -> Any:
    return _preview(_redact(to_jsonable(value)), max_chars=settings.max_chars)


def _preview(value: Any, *, max_chars: int) -> str:
    try:
        text = json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        text = str(value)
    if len(text) <= max_chars:
        return text
    return f"{text[:max_chars]}...<truncated {len(text) - max_chars} chars>"


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key).lower()
            if any(part in key_text for part in SENSITIVE_KEY_PARTS):
                redacted[key] = "<redacted>"
            else:
                redacted[key] = _redact(item)
        return redacted
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact(item) for item in value)
    return value
