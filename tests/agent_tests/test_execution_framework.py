from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any, Dict

import pytest

from src.agents.execution import AgentsExecutionEngine, MCPServerSpec, normalize_run_result_messages
from src.utils.tools import BaseToolPolicy, RuntimeTool, ToolInterception


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
    def __init__(self, *, messages: list[dict[str, Any]], final_output: Any = "", new_items: list[Any] | None = None):
        self._messages = messages
        self.final_output = final_output
        self.new_items = new_items or []
        self.raw_responses = [object()]

    def to_input_list(self, mode: str = "preserve_all"):
        return list(self._messages)


class _FakeRunner:
    result: _FakeRunResult = _FakeRunResult(messages=[])
    last_call: Dict[str, Any] = {}

    @classmethod
    async def run(cls, agent, input, context=None, max_turns=8, run_config=None):
        cls.last_call = {
            "agent": agent,
            "input": input,
            "context": context,
            "max_turns": max_turns,
            "run_config": run_config,
        }
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


def _runtime_tool(name: str, executor, *, description: str | None = None, schema: dict[str, Any] | None = None) -> RuntimeTool:
    return RuntimeTool(
        name=name,
        description=description or name,
        input_schema=schema or {"type": "object", "properties": {}},
        executor=executor,
        defaults={},
    )


class _BlockingPolicy(BaseToolPolicy):
    def __init__(self, blocked_tool: str):
        self.blocked_tool = blocked_tool

    async def before_call(self, tool: RuntimeTool, arguments: dict[str, Any]) -> ToolInterception | None:
        if tool.name == self.blocked_tool:
            return ToolInterception({"status": "aborted", "message": "blocked by policy", "tool": tool.name})
        return None


class _RecordingPolicy(BaseToolPolicy):
    def __init__(self):
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def before_call(self, tool: RuntimeTool, arguments: dict[str, Any]) -> ToolInterception | None:
        self.calls.append((tool.name, dict(arguments)))
        return None


def test_local_tool_wrapper_applies_policy_and_blocks(monkeypatch):
    engine = AgentsExecutionEngine(
        agent_name="striker",
        instructions="test",
        model_name="test-model",
        api_key="test-key",
        base_url="https://example.invalid",
        runtime_tools=[],
        policy=_BlockingPolicy("msf_run_exploit"),
    )

    called = {"count": 0}

    async def executor(**kwargs):
        called["count"] += 1
        return {"status": "success", "output": "should not happen", "invocation": kwargs}

    tool = _runtime_tool("msf_run_exploit", executor, schema={"type": "object", "properties": {"target": {"type": "string"}}})
    wrapped = engine._build_function_tool(_FakeSDK, tool)

    payload = asyncio.run(wrapped.on_invoke_tool(SimpleNamespace(), json.dumps({"target": "10.0.0.5"})))
    parsed = json.loads(payload)

    assert parsed["status"] == "aborted"
    assert parsed["message"] == "blocked by policy"
    assert called["count"] == 0


def test_local_tool_wrapper_runs_executor_and_records_args():
    policy = _RecordingPolicy()
    engine = AgentsExecutionEngine(
        agent_name="striker",
        instructions="test",
        model_name="test-model",
        api_key="test-key",
        base_url="https://example.invalid",
        runtime_tools=[],
        policy=policy,
    )

    async def executor(**kwargs):
        return {"status": "success", "summary": "done", "invocation": kwargs}

    tool = _runtime_tool("msf_search_modules", executor)
    wrapped = engine._build_function_tool(_FakeSDK, tool)

    payload = asyncio.run(wrapped.on_invoke_tool(SimpleNamespace(), json.dumps({"search_term": "werkzeug"})))
    parsed = json.loads(payload)

    assert parsed["status"] == "success"
    assert parsed["summary"] == "done"
    assert parsed["invocation"]["search_term"] == "werkzeug"
    assert policy.calls == [("msf_search_modules", {"search_term": "werkzeug"})]


def test_mcp_server_spec_builds_allowlist_and_approval_policy():
    engine = AgentsExecutionEngine(
        agent_name="striker",
        instructions="test",
        model_name="test-model",
        api_key="test-key",
        base_url="https://example.invalid",
        runtime_tools=[],
        mcp_servers=[
            MCPServerSpec(
                name="attackbox",
                url="http://attackbox.invalid/mcp",
                allowed_tools={"msf_search_modules", "msf_run_exploit"},
                approval_tools={"msf_run_exploit"},
            )
        ],
    )

    server = engine._build_mcp_server(_FakeSDK, engine.mcp_servers[0])
    assert server.kwargs["name"] == "attackbox"
    assert server.kwargs["params"] == {"url": "http://attackbox.invalid/mcp"}
    assert server.kwargs["cache_tools_list"] is True
    assert server.kwargs["tool_filter"] == {"allowed_tool_names": ["msf_run_exploit", "msf_search_modules"]}
    assert server.kwargs["require_approval"] == {"always": {"tool_names": ["msf_run_exploit"]}}


def test_normalize_run_result_messages_prefers_input_items():
    result = _FakeRunResult(
        messages=[
            {"role": "assistant", "content": "Working"},
            {
                "role": "tool",
                "name": "msf_list_sessions",
                "tool_call_id": "abc",
                "content": {"status": "success", "sessions": {"7": {"type": "shell"}}},
            },
        ]
    )

    messages = normalize_run_result_messages(result)
    assert messages[0]["role"] == "assistant"
    assert messages[1]["role"] == "tool"
    assert messages[1]["content"]["status"] == "success"
