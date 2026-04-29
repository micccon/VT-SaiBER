from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import src.agents.striker as striker_mod
import src.agents.striker_v2 as striker_v2_mod
from src.utils.tools import RuntimeTool


class _FakeFunctionTool:
    def __init__(self, *, name: str, description: str, params_json_schema: dict[str, Any], on_invoke_tool):
        self.name = name
        self.description = description
        self.params_json_schema = params_json_schema
        self.on_invoke_tool = on_invoke_tool


class _FakeMCPServerStreamableHttp:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _FakeMCPModule:
    MCPServerStreamableHttp = _FakeMCPServerStreamableHttp

    @staticmethod
    def create_static_tool_filter(*, allowed_tool_names):
        return {"allowed_tool_names": list(allowed_tool_names)}


class _FakeAsyncOpenAI:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _FakeChatModel:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _FakeRunConfig:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _FakeModelSettings:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _FakeAgent:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.tools = kwargs.get("tools", [])
        self.mcp_servers = kwargs.get("mcp_servers", [])


class _FakeRunResult:
    def __init__(self, messages: list[dict[str, Any]], final_output: Any = ""):
        self._messages = messages
        self.final_output = final_output
        self.new_items = []
        self.raw_responses = [object()]

    def to_input_list(self, mode: str = "preserve_all"):
        return list(self._messages)


class _FakeRunner:
    result: _FakeRunResult = _FakeRunResult(messages=[])

    @classmethod
    async def run(cls, agent, input, context=None, max_turns=8, run_config=None):
        return cls.result


class _FakeSDK:
    Agent = _FakeAgent
    Runner = _FakeRunner
    FunctionTool = _FakeFunctionTool
    AsyncOpenAI = _FakeAsyncOpenAI
    OpenAIChatCompletionsModel = _FakeChatModel
    RunConfig = _FakeRunConfig
    ModelSettings = _FakeModelSettings
    mcp = _FakeMCPModule()


def _base_state() -> Dict[str, Any]:
    return {
        "mission_goal": "Exploit target and gain initial access",
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


def _runtime_tool(name: str) -> RuntimeTool:
    async def executor(**kwargs):
        return {"status": "success", "invocation": kwargs, "summary": f"{name} executed"}

    return RuntimeTool(
        name=name,
        description=name,
        input_schema={"type": "object", "properties": {}},
        executor=executor,
        defaults={},
    )


def _plain(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    return value


def _strip_unstable_fields(update: Dict[str, Any]) -> Dict[str, Any]:
    plain = _plain(update)
    for entry in plain.get("agent_log", []) or []:
        if isinstance(entry, dict):
            entry.pop("timestamp", None)
    for entry in plain.get("errors", []) or []:
        if isinstance(entry, dict):
            entry.pop("timestamp", None)
    return plain


def _run(coro):
    return asyncio.run(coro)


@pytest.mark.asyncio
async def test_striker_v2_returns_validation_error_without_targets():
    agent = striker_v2_mod.StrikerV2Agent(sdk_module=_FakeSDK)
    state = _base_state()

    out = await agent.call_llm(state)
    assert out["errors"][0].error_type == "ValidationError"
    assert out["errors"][0].recoverable is True


def _scenario_messages() -> Dict[str, list[dict[str, Any]]]:
    return {
        "approval_blocked": [
            {
                "role": "tool",
                "name": "msf_run_exploit",
                "tool_call_id": "c1",
                "content": {
                    "status": "aborted",
                    "message": "Execution blocked pending manual approval.",
                    "invocation": {
                        "module_name": "multi/http/werkzeug_debug_rce",
                        "options": {"RHOSTS": "192.168.1.10", "RPORT": 80},
                    },
                },
            }
        ],
        "validated_no_session": [
            {
                "role": "tool",
                "name": "access_hydra_attack",
                "tool_call_id": "c1",
                "content": {
                    "status": "success",
                    "validation": {"outcome": "positive", "reason": "Hydra confirmed at least one valid credential."},
                    "invocation": {"target": "192.168.1.10", "service": "ssh"},
                },
            }
        ],
        "session_opened": [
            {
                "role": "tool",
                "name": "msf_run_exploit",
                "tool_call_id": "c1",
                "content": {
                    "status": "success",
                    "module": "multi/http/apache_demo",
                    "session_id": 7,
                    "invocation": {
                        "module_name": "multi/http/apache_demo",
                        "options": {"RHOSTS": "192.168.1.10", "RPORT": 80},
                    },
                },
            },
            {
                "role": "tool",
                "name": "msf_list_sessions",
                "tool_call_id": "c2",
                "content": {"status": "success", "sessions": {"7": {"target_host": "192.168.1.10"}}},
            },
        ],
        "search_only": [
            {
                "role": "tool",
                "name": "msf_search_modules",
                "tool_call_id": "c1",
                "content": {
                    "status": "success",
                    "result": ["multi/http/werkzeug_debug_rce"],
                    "invocation": {"search_term": "werkzeug"},
                },
            }
        ],
    }


def _build_state() -> Dict[str, Any]:
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "services": {"80": {"service_name": "http", "version": "Werkzeug 3.1.8"}},
        }
    }
    return state


def _fake_runtime_tools(monkeypatch):
    monkeypatch.setattr(striker_v2_mod, "load_filtered_tools", lambda allowed: [_runtime_tool("msf_run_exploit"), _runtime_tool("msf_list_sessions"), _runtime_tool("access_hydra_attack"), _runtime_tool("msf_search_modules")])


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", ["approval_blocked", "validated_no_session", "session_opened", "search_only"])
async def test_striker_v2_matches_old_contract_on_mocked_scenarios(monkeypatch, scenario):
    _fake_runtime_tools(monkeypatch)
    _FakeRunner.result = _FakeRunResult(messages=_scenario_messages()[scenario])

    state = _build_state()
    context = striker_v2_mod.build_striker_context(state)

    expected = striker_mod.StrikerAgent()._extract_updates(_scenario_messages()[scenario], state, context)
    result = await striker_v2_mod.StrikerV2Agent(sdk_module=_FakeSDK).call_llm(state)

    expected_plain = _strip_unstable_fields(expected)
    result_plain = _strip_unstable_fields(result)

    assert result_plain["current_agent"] == "striker"
    assert result_plain["iteration_count"] == expected_plain["iteration_count"]
    assert result_plain.get("critical_findings", []) == expected_plain.get("critical_findings", [])
    assert result_plain.get("active_sessions", {}) == expected_plain.get("active_sessions", {})
    assert result_plain.get("exploited_services", []) == expected_plain.get("exploited_services", [])
    assert result_plain.get("exploit_attempts", []) == expected_plain.get("exploit_attempts", [])

    expected_findings = expected_plain["agent_log"][0]["findings"]
    result_findings = result_plain["agent_log"][0]["findings"]
    assert result_findings["status"] == expected_findings["status"]
    assert result_findings.get("module") == expected_findings.get("module")
    assert result_findings.get("selected_module") == expected_findings.get("selected_module")
    assert result_findings.get("session_opened") == expected_findings.get("session_opened")

