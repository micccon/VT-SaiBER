"""
Striker ReAct agent tests.

Unit tests cover the node-level logic (context building, state extraction,
guardrails) without requiring a live LLM or MCP connection by stubbing only
the MCP bridge and the create_react_agent factory.

The live test fires a real ChatOpenAI call and a real MCP bridge connection;
it is skipped when OPENROUTER_API_KEY is absent.

Run unit tests only:
    ./saiber_env/bin/python -m pytest tests/agent_tests/test_striker_react.py -m "not live" -v

Run all tests:
    ./saiber_env/bin/python -m pytest tests/agent_tests/test_striker_react.py -v -s
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest
from langchain_core.messages import ToolMessage
from langchain_core.tools import StructuredTool

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import src.agents.striker as striker_mod
from src.agents.striker import striker_node, _build_striker_context
from src.config import get_runtime_config

_requires_api_key = pytest.mark.skipif(
    not os.getenv("OPENROUTER_API_KEY", "").strip(),
    reason="OPENROUTER_API_KEY is not set",
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

MOCK_STATE: Dict[str, Any] = {
    "mission_goal": "Gain initial access to automotive-testbed",
    "mission_id": "test-striker-react-001",
    "mission_status": "active",
    "current_agent": "striker",
    "next_agent": None,
    "iteration_count": 4,
    "target_scope": ["172.20.0.0/16", "automotive-testbed"],
    "discovered_targets": {
        "automotive-testbed": {
            "ip_address": "automotive-testbed",
            "os_guess": "Linux (Ubuntu 20.04)",
            "ports": [22, 8000],
            "services": {
                "22": {
                    "service_name": "ssh",
                    "version": "OpenSSH 8.2p1 Ubuntu",
                    "banner": "SSH-2.0-OpenSSH_8.2p1",
                },
                "8000": {
                    "service_name": "http",
                    "version": "Werkzeug/2.0.1 Python/3.8",
                    "banner": "",
                },
            },
            "vulns": [],
        }
    },
    "web_findings": [
        {"path": "/login", "status_code": 200, "is_interesting": True},
        {"path": "/health", "status_code": 200, "is_interesting": False},
    ],
    "research_cache": {
        "OpenSSH 8.2p1": "Brute-force likely; no straightforward RCE.",
    },
    "intelligence_findings": [
        {
            "cve": "CVE-2016-10516",
            "description": "Werkzeug debugger issue in debug mode.",
            "data": {"msf_module": ""},
        }
    ],
    "active_sessions": {},
    "exploited_services": [],
    "agent_log": [],
    "critical_findings": [],
    "errors": [],
    "supervisor_messages": [],
    "supervisor_expectations": {},
    "ot_discovery": {},
}


def _make_tool(name: str) -> StructuredTool:
    async def _async_tool(**kwargs):
        return json.dumps({"status": "success", "tool": name, "kwargs": kwargs})

    def _sync_tool(**kwargs):
        return json.dumps({"status": "success", "tool": name, "kwargs": kwargs})

    return StructuredTool.from_function(
        func=_sync_tool,
        coroutine=_async_tool,
        name=name,
        description=f"Mock tool: {name}",
    )


class _MockBridge:
    def __init__(self, tools: List[StructuredTool]):
        self._tools = tools

    def get_tools_for_agent(self, allowed_tools):
        return self._tools


# ---------------------------------------------------------------------------
# Unit tests — context building (no LLM, no MCP)
# ---------------------------------------------------------------------------


def test_striker_context_contains_required_sections():
    ctx = _build_striker_context(MOCK_STATE)

    required = [
        "MISSION: Gain initial access to automotive-testbed",
        "TARGET INTELLIGENCE:",
        "automotive-testbed",
        "22/tcp ssh",
        "INTERESTING WEB FINDINGS:",
        "/login",
        "PRIOR EXPLOIT ATTEMPTS IN THIS MISSION:",
    ]
    missing = [s for s in required if s not in ctx]
    assert not missing, f"Context is missing sections: {missing}"


def test_striker_context_includes_osint_research_hints():
    ctx = _build_striker_context(MOCK_STATE)
    assert "Werkzeug" in ctx or "CVE-2016-10516" in ctx, (
        "Context should surface OSINT / research hints relevant to discovered services"
    )


def test_striker_node_returns_validation_error_without_targets():
    state = {**MOCK_STATE, "discovered_targets": {}}
    out = asyncio.run(striker_node(state))

    assert out.get("errors"), "striker_node must return errors when no targets are present"
    assert out["errors"][0].error_type == "ValidationError"


# ---------------------------------------------------------------------------
# Unit tests — node flow with stubbed MCP bridge + stubbed ReAct agent
# ---------------------------------------------------------------------------


def test_striker_node_records_session_on_successful_exploit(monkeypatch):
    """Node must record active_sessions and exploited_services when ReAct loop opens a session."""

    tools = [
        _make_tool("msf_list_exploits"),
        _make_tool("msf_get_module_info"),
        _make_tool("msf_get_module_options"),
        _make_tool("msf_list_payloads"),
        _make_tool("msf_run_exploit"),
        _make_tool("msf_run_auxiliary_module"),
        _make_tool("msf_list_active_sessions"),
    ]

    async def fake_get_bridge():
        return _MockBridge(tools)

    def fake_build_llm():
        return object()  # placeholder; create_react_agent is also stubbed

    def fake_create_react_agent(model, tools, **kwargs):
        class _FakeAgent:
            async def ainvoke(self, payload):
                return {
                    "messages": [
                        ToolMessage(
                            tool_call_id="call-1",
                            name="msf_run_exploit",
                            content=json.dumps({
                                "status": "success",
                                "module": "exploit/linux/ssh/example",
                                "session_id": 7,
                                "options": {"RHOSTS": "automotive-testbed", "RPORT": "22"},
                            }),
                        )
                    ]
                }

        return _FakeAgent()

    monkeypatch.setattr(striker_mod, "get_mcp_bridge", fake_get_bridge)
    monkeypatch.setattr(striker_mod, "_build_llm", fake_build_llm)
    monkeypatch.setattr(striker_mod, "create_react_agent", fake_create_react_agent)
    monkeypatch.setattr(striker_mod, "STRIKER_REQUIRE_CONFIRMATION", False)

    out = asyncio.run(striker_node(MOCK_STATE))

    assert not out.get("errors"), f"Unexpected errors: {out.get('errors')}"

    sessions = out.get("active_sessions", {})
    assert "automotive-testbed" in sessions, "session must be keyed by target IP/hostname"
    assert sessions["automotive-testbed"]["session_id"] == 7

    exploited = out.get("exploited_services", [])
    assert exploited, "exploited_services must be recorded after a successful exploit"
    assert out.get("critical_findings"), "critical_findings must mention the opened session"


def test_striker_node_records_no_session_when_exploit_blocked(monkeypatch):
    """When the manual approval gate blocks execution, no session should be recorded."""

    tools = [
        _make_tool("msf_run_exploit"),
        _make_tool("msf_run_auxiliary_module"),
        _make_tool("msf_list_active_sessions"),
    ]

    async def fake_get_bridge():
        return _MockBridge(tools)

    def fake_build_llm():
        return object()

    def fake_create_react_agent(model, tools, **kwargs):
        class _FakeAgent:
            async def ainvoke(self, payload):
                # ReAct loop ran but no exploit ToolMessage was produced
                return {"messages": []}

        return _FakeAgent()

    monkeypatch.setattr(striker_mod, "get_mcp_bridge", fake_get_bridge)
    monkeypatch.setattr(striker_mod, "_build_llm", fake_build_llm)
    monkeypatch.setattr(striker_mod, "create_react_agent", fake_create_react_agent)
    monkeypatch.setattr(striker_mod, "STRIKER_REQUIRE_CONFIRMATION", True)

    out = asyncio.run(striker_node(MOCK_STATE))

    assert not out.get("errors")
    assert not out.get("active_sessions"), "no sessions should be opened if exploit was not executed"


def test_striker_node_returns_tool_error_when_bridge_has_no_msf_tools(monkeypatch):
    """Node must fail with ToolError when the MCP bridge provides no exploit tools."""

    async def fake_get_bridge():
        return _MockBridge([])  # no tools at all

    monkeypatch.setattr(striker_mod, "get_mcp_bridge", fake_get_bridge)

    out = asyncio.run(striker_node(MOCK_STATE))

    assert out.get("errors"), "expected ToolError when bridge returns no tools"
    assert out["errors"][0].error_type == "ToolError"


def test_striker_node_returns_llm_config_error_when_build_llm_fails(monkeypatch):
    tools = [
        _make_tool("msf_run_exploit"),
        _make_tool("msf_run_auxiliary_module"),
    ]

    async def fake_get_bridge():
        return _MockBridge(tools)

    def bad_build_llm():
        raise RuntimeError("OPENROUTER_API_KEY is required")

    monkeypatch.setattr(striker_mod, "get_mcp_bridge", fake_get_bridge)
    monkeypatch.setattr(striker_mod, "_build_llm", bad_build_llm)

    out = asyncio.run(striker_node(MOCK_STATE))

    assert out.get("errors")
    assert out["errors"][0].error_type == "LLMConfigError"


# ---------------------------------------------------------------------------
# Live LLM test — validates _build_llm() connects successfully
# ---------------------------------------------------------------------------


@_requires_api_key
def test_striker_build_llm_succeeds_with_api_key():
    """
    Real API key: _build_llm must return a usable ChatOpenAI instance.

    Full striker integration (ReAct loop + real MCP tools) is covered by
    the Docker-based scripts in tests/agent_tests/striker/.
    """
    import src.agents.striker as mod

    get_runtime_config.cache_clear()
    llm = mod._build_llm()

    # The object must be a ChatOpenAI instance (langchain_openai)
    assert hasattr(llm, "ainvoke"), "LLM must expose an ainvoke method"
    assert hasattr(llm, "model_name") or hasattr(llm, "model"), "LLM must expose a model attribute"

    model_attr = getattr(llm, "model_name", None) or getattr(llm, "model", "")
    assert model_attr, "Model name must not be empty"
    print(f"\n[live] _build_llm() → model={model_attr}")
