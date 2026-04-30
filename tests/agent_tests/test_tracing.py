from __future__ import annotations

import logging

import pytest
from pydantic import BaseModel

from src.config import get_runtime_config
from src.runtime.contracts import ChatSynthesisResult, ExecutionResult, ToolEvent
from src.runtime.tracing import trace_execution_result, trace_synthesis_result


class _Outcome(BaseModel):
    status: str
    api_key: str = "should-not-leak"


@pytest.fixture(autouse=True)
def _clear_runtime_config_cache():
    get_runtime_config.cache_clear()
    yield
    get_runtime_config.cache_clear()


def _reset_config(monkeypatch, *, enabled: bool, include_raw: bool = False, max_chars: int = 2000) -> None:
    monkeypatch.setenv("SAIBER_TRACE_ENABLED", "true" if enabled else "false")
    monkeypatch.setenv("SAIBER_TRACE_INCLUDE_RAW", "true" if include_raw else "false")
    monkeypatch.setenv("SAIBER_TRACE_MAX_CHARS", str(max_chars))
    get_runtime_config.cache_clear()


def test_tracing_is_disabled_by_default(monkeypatch, caplog):
    _reset_config(monkeypatch, enabled=False)
    caplog.set_level(logging.INFO, logger="src.trace")

    trace_synthesis_result(
        agent_name="supervisor",
        result=ChatSynthesisResult(outcome=_Outcome(status="ok"), raw_text="raw secret"),
    )

    assert "agent_trace" not in caplog.text


def test_synthesis_tracing_redacts_and_hides_raw_by_default(monkeypatch, caplog):
    _reset_config(monkeypatch, enabled=True, include_raw=False)
    caplog.set_level(logging.INFO, logger="src.trace")

    trace_synthesis_result(
        agent_name="supervisor",
        result=ChatSynthesisResult(outcome=_Outcome(status="ok"), raw_text="raw model text"),
    )

    assert "synthesis_result" in caplog.text
    assert "supervisor" in caplog.text
    assert "should-not-leak" not in caplog.text
    assert "raw model text" not in caplog.text
    assert "<redacted>" in caplog.text


def test_execution_tracing_logs_tool_summary_with_redaction(monkeypatch, caplog):
    _reset_config(monkeypatch, enabled=True, include_raw=False, max_chars=4000)
    caplog.set_level(logging.INFO, logger="src.trace")
    result = ExecutionResult(
        outcome={"status": "session_opened"},
        tool_events=[
            ToolEvent(
                tool_name="msf_list_sessions",
                invocation={"target": "10.0.0.5", "api_token": "abc123"},
                source="mcp",
                server_name="attackbox",
                status="success",
                result={"status": "success", "password": "hunter2"},
            )
        ],
        raw_result={"secret": "raw-sdk"},
    )

    trace_execution_result(agent_name="striker", result=result)

    assert "execution_result" in caplog.text
    assert "msf_list_sessions" in caplog.text
    assert "abc123" not in caplog.text
    assert "hunter2" not in caplog.text
    assert "raw-sdk" not in caplog.text
    assert "<redacted>" in caplog.text
