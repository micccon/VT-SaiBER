from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import BaseModel

from src.v2.contracts.execution import (
    AgentExecutionSpec,
    LocalToolSpec,
    MCPServerConfig,
    ModelConfig,
    ToolCallInterception,
)
from src.v2.execution import AgentsSDKExecutionRunner, ExecutionPolicy


class _SampleOutcome(BaseModel):
    status: str


class _FakeFunctionTool:
    def __init__(self, *, name: str, description: str, params_json_schema: dict[str, Any], on_invoke_tool):
        self.name = name
        self.description = description
        self.params_json_schema = params_json_schema
        self.on_invoke_tool = on_invoke_tool


class _FakeToolDef:
    def __init__(self, name: str, description: str = "", input_schema: dict[str, Any] | None = None):
        self.name = name
        self.description = description or name
        self.inputSchema = input_schema or {"type": "object", "properties": {}}


class _FakeMCPServerStreamableHttp:
    registry: dict[str, dict[str, Any]] = {}
    instances: list["_FakeMCPServerStreamableHttp"] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.url = kwargs["params"]["url"]
        self.config = self.registry[self.url]
        self.instances.append(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def list_tools(self):
        return SimpleNamespace(tools=self.config["tools"])

    async def call_tool(self, tool_name: str, args: dict[str, Any]):
        self.calls.append((tool_name, dict(args)))
        response = self.config["results"][tool_name]
        if isinstance(response, Exception):
            raise response
        return response


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


class _FakeOpenAIProvider:
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


class _FakeRunResult:
    def __init__(self, final_output: Any):
        self.final_output = final_output


class _FakeRunner:
    script: list[tuple[str, dict[str, Any]]] = []
    final_output: Any = {"status": "done"}
    last_call: dict[str, Any] = {}

    @classmethod
    async def run(cls, agent, input, context=None, max_turns=8, run_config=None):
        cls.last_call = {
            "agent": agent,
            "input": input,
            "context": context,
            "max_turns": max_turns,
            "run_config": run_config,
        }
        for tool_name, arguments in cls.script:
            tool = next(item for item in agent.tools if item.name == tool_name)
            await tool.on_invoke_tool(SimpleNamespace(context=context), json.dumps(arguments))
        return _FakeRunResult(cls.final_output)


class _FakeSDK:
    Agent = _FakeAgent
    Runner = _FakeRunner
    FunctionTool = _FakeFunctionTool
    AsyncOpenAI = _FakeAsyncOpenAI
    OpenAIChatCompletionsModel = _FakeChatModel
    OpenAIProvider = _FakeOpenAIProvider
    RunConfig = _FakeRunConfig
    ModelSettings = _FakeModelSettings
    mcp = _FakeMCPModule()


def _model_config() -> ModelConfig:
    return ModelConfig(
        model="test-model",
        api_key="test-key",
        base_url="https://example.invalid",
    )


class _DenyApprovalPolicy(ExecutionPolicy):
    async def approve_tool_call(self, tool, arguments: dict[str, Any]) -> bool:
        return False


class _InterceptPolicy(ExecutionPolicy):
    async def before_tool_call(self, tool, arguments: dict[str, Any]) -> ToolCallInterception | None:
        return ToolCallInterception({"status": "blocked", "message": "blocked by policy", "tool": tool.name})


def _run(coro):
    return asyncio.run(coro)


def test_local_tool_execution_records_telemetry_and_artifacts():
    called: list[dict[str, Any]] = []

    async def executor(**kwargs):
        called.append(dict(kwargs))
        return {
            "status": "success",
            "summary": "done",
            "artifacts": [{"name": "note.txt"}],
        }

    spec = AgentExecutionSpec(
        agent_name="demo",
        instructions="test",
        model=_model_config(),
        output_type=_SampleOutcome,
        local_tools=[
            LocalToolSpec(
                name="echo",
                description="echo",
                input_schema={"type": "object", "properties": {"target": {"type": "string"}}},
                executor=executor,
            )
        ],
    )

    _FakeRunner.script = [("echo", {"target": "10.0.0.5"})]
    _FakeRunner.final_output = {"status": "ok"}
    result = _run(AgentsSDKExecutionRunner(sdk_module=_FakeSDK).run(spec, user_input="hello"))

    assert called == [{"target": "10.0.0.5"}]
    assert result.outcome.status == "ok"
    assert len(result.tool_events) == 1
    assert result.tool_events[0].tool_name == "echo"
    assert result.tool_events[0].status == "success"
    assert result.artifacts == [{"name": "note.txt"}]


def test_mcp_tool_allowlist_uses_direct_sdk_server():
    _FakeMCPServerStreamableHttp.instances.clear()
    _FakeMCPServerStreamableHttp.registry = {
        "http://attackbox.invalid/mcp": {
            "tools": [
                _FakeToolDef("allowed_tool"),
                _FakeToolDef("blocked_tool"),
            ],
            "results": {"allowed_tool": {"status": "success", "summary": "allowed"}},
        }
    }

    spec = AgentExecutionSpec(
        agent_name="demo",
        instructions="test",
        model=_model_config(),
        output_type=_SampleOutcome,
        mcp_servers=[
            MCPServerConfig(
                name="attackbox",
                url="http://attackbox.invalid/mcp",
                allowed_tools={"allowed_tool"},
            )
        ],
    )

    _FakeRunner.script = [("allowed_tool", {})]
    _FakeRunner.final_output = {"status": "ok"}
    result = _run(AgentsSDKExecutionRunner(sdk_module=_FakeSDK).run(spec, user_input="hello"))

    server = _FakeMCPServerStreamableHttp.instances[0]
    assert server.kwargs["params"] == {"url": "http://attackbox.invalid/mcp"}
    assert server.kwargs["tool_filter"] == {"allowed_tool_names": ["allowed_tool"]}
    assert [tool.name for tool in _FakeRunner.last_call["agent"].tools] == ["allowed_tool"]
    assert server.calls == [("allowed_tool", {})]
    assert result.tool_events[0].source == "mcp"


def test_approval_gating_aborts_tool_call():
    _FakeMCPServerStreamableHttp.instances.clear()
    _FakeMCPServerStreamableHttp.registry = {
        "http://attackbox.invalid/mcp": {
            "tools": [_FakeToolDef("dangerous_tool")],
            "results": {"dangerous_tool": {"status": "success", "summary": "should not run"}},
        }
    }

    spec = AgentExecutionSpec(
        agent_name="demo",
        instructions="test",
        model=_model_config(),
        output_type=_SampleOutcome,
        mcp_servers=[
            MCPServerConfig(
                name="attackbox",
                url="http://attackbox.invalid/mcp",
                allowed_tools={"dangerous_tool"},
                approval_required_tools={"dangerous_tool"},
            )
        ],
    )

    _FakeRunner.script = [("dangerous_tool", {"target": "10.0.0.8"})]
    _FakeRunner.final_output = {"status": "ok"}
    result = _run(
        AgentsSDKExecutionRunner(sdk_module=_FakeSDK).run(
            spec,
            user_input="hello",
            policy=_DenyApprovalPolicy(),
        )
    )

    server = _FakeMCPServerStreamableHttp.instances[0]
    assert server.calls == []
    assert result.approval_events[0].approved is False
    assert result.tool_events[0].status == "aborted"


def test_failure_normalization_records_error():
    async def executor(**kwargs):
        raise RuntimeError("boom")

    spec = AgentExecutionSpec(
        agent_name="demo",
        instructions="test",
        model=_model_config(),
        output_type=_SampleOutcome,
        local_tools=[
            LocalToolSpec(
                name="explode",
                description="explode",
                input_schema={"type": "object", "properties": {}},
                executor=executor,
            )
        ],
    )

    _FakeRunner.script = [("explode", {})]
    _FakeRunner.final_output = {"status": "ok"}
    result = _run(AgentsSDKExecutionRunner(sdk_module=_FakeSDK).run(spec, user_input="hello"))

    assert result.tool_events[0].status == "error"
    assert "boom" in str(result.tool_events[0].result.get("message"))


def test_policy_interception_blocks_before_local_execution():
    called = {"count": 0}

    async def executor(**kwargs):
        called["count"] += 1
        return {"status": "success"}

    spec = AgentExecutionSpec(
        agent_name="demo",
        instructions="test",
        model=_model_config(),
        output_type=_SampleOutcome,
        local_tools=[
            LocalToolSpec(
                name="blocked",
                description="blocked",
                input_schema={"type": "object", "properties": {}},
                executor=executor,
            )
        ],
    )

    _FakeRunner.script = [("blocked", {})]
    _FakeRunner.final_output = {"status": "ok"}
    result = _run(
        AgentsSDKExecutionRunner(sdk_module=_FakeSDK).run(
            spec,
            user_input="hello",
            policy=_InterceptPolicy(),
        )
    )

    assert called["count"] == 0
    assert result.tool_events[0].status == "blocked"
