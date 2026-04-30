from __future__ import annotations

from typing import Any

import pytest

from src.v2.agents.fuzzer.agent import FuzzerV2Agent
from src.v2.agents.fuzzer.outcome import FuzzerOutcome, WebFinding
from src.v2.contracts.execution import ExecutionResult, ToolEvent


class _FakeExecutionRunner:
    def __init__(self, result: ExecutionResult[FuzzerOutcome] | list[ExecutionResult[FuzzerOutcome]]):
        self.results = list(result) if isinstance(result, list) else [result]
        self.last_spec = None
        self.last_input = None
        self.last_context = None
        self.calls: list[str] = []

    async def run(self, spec, *, user_input: str, context=None, policy=None):
        self.last_spec = spec
        self.last_input = user_input
        self.last_context = context
        self.calls.append(user_input)
        return self.results.pop(0)


def _tool_event(name: str = "web_content_enum") -> ToolEvent:
    return ToolEvent(
        tool_name=name,
        invocation={"base_url": "http://192.168.1.10"},
        source="mcp",
        status="success",
        result={"status": "success"},
    )


def _base_state() -> dict[str, Any]:
    return {
        "mission_goal": "Enumerate the web attack surface",
        "mission_id": "test-mission",
        "mission_status": "active",
        "current_agent": "supervisor",
        "next_agent": None,
        "iteration_count": 0,
        "target_scope": ["192.168.1.10"],
        "discovered_targets": {},
        "ot_discovery": {},
        "web_findings": [],
        "active_sessions": {},
        "exploited_services": [],
        "credential_findings": [],
        "exploit_attempts": [],
        "protocol_observations": [],
        "fuzzing_runs": [],
        "crash_indicators": [],
        "artifacts": [],
        "validations": [],
        "research_cache": {},
        "intelligence_findings": [],
        "supervisor_messages": [],
        "supervisor_expectations": {},
        "agent_log": [],
        "critical_findings": [],
        "errors": [],
    }


def test_fuzzer_v2_exposes_run_entrypoint():
    agent = FuzzerV2Agent(
        execution_runner=_FakeExecutionRunner(
            ExecutionResult(outcome=FuzzerOutcome(base_url="http://example.com"))
        )
    )
    assert hasattr(agent, "run")


@pytest.mark.asyncio
async def test_fuzzer_v2_returns_validation_error_without_http_target():
    out = await FuzzerV2Agent(
        execution_runner=_FakeExecutionRunner(
            ExecutionResult(outcome=FuzzerOutcome(base_url="http://example.com"))
        )
    ).run(_base_state())
    assert out["errors"][0].error_type == "ValidationError"
    assert out["current_agent"] == "fuzzer_v2"


@pytest.mark.asyncio
async def test_fuzzer_v2_persists_structured_findings():
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "ports": [80],
            "services": {"80": {"service_name": "http", "version": "Apache 2.4"}},
        }
    }
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=FuzzerOutcome(
                base_url="http://192.168.1.10",
                web_findings=[
                    WebFinding(
                        url="http://192.168.1.10/admin",
                        path="/admin",
                        status_code=200,
                        content_length=123,
                        content_type="text/html",
                        is_interesting=True,
                        discovery_depth=1,
                        rationale="Admin path discovered",
                        source_tool="web_content_enum",
                    )
                ],
                operator_summary="Found one interesting admin endpoint.",
            )
            ,
            tool_events=[_tool_event()],
        )
    )
    out = await FuzzerV2Agent(execution_runner=runner).run(state)

    assert out["web_findings"][0]["path"] == "/admin"
    assert out["agent_log"][0].action == "web_enumeration"
    assert out["agent_log"][0].findings["findings_count"] == 1


@pytest.mark.asyncio
async def test_fuzzer_v2_uses_normalized_fallback_when_sparse():
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "ports": [443],
            "services": {"443": {"service_name": "https"}},
        }
    }
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=FuzzerOutcome(
                base_url="https://192.168.1.10",
                web_findings=[],
                operator_summary="No normalized findings were produced.",
            ),
            tool_events=[_tool_event("web_nikto_scan")],
        )
    )
    out = await FuzzerV2Agent(execution_runner=runner).run(state)

    assert out["web_findings"][0]["path"] == "/"
    assert out["web_findings"][0]["rationale"] == "Fallback finding while MCP scan is unavailable"


@pytest.mark.asyncio
async def test_fuzzer_v2_rejects_model_output_without_web_tool_use():
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "ports": [80],
            "services": {"80": {"service_name": "http"}},
        }
    }
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=FuzzerOutcome(
                base_url="http://192.168.1.10",
                web_findings=[
                    WebFinding(url="http://192.168.1.10/admin", path="/admin", status_code=200)
                ],
            )
        )
    )

    out = await FuzzerV2Agent(execution_runner=runner).run(state)

    assert out["errors"][0].error_type == "ValidationError"
    assert "did not execute" in out["errors"][0].error
    assert len(runner.calls) == 1
