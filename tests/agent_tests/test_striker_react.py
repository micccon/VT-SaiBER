#!/usr/bin/env python3
"""
Striker ReAct Agent Tests
=========================
Validates current src/agents/striker.py behavior without requiring live MCP/model calls.

Run inside agents container:
    docker exec vt-saiber-agents python tests/agent_tests/test_striker_react.py
"""

import asyncio
import json
import sys
import traceback

sys.path.insert(0, "/app")

import src.agents.striker as striker_mod
from langchain_core.messages import ToolMessage
from langchain_core.tools import StructuredTool


class Results:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def add_pass(self, name):
        self.passed += 1
        print(f"  [PASS] {name}")

    def add_fail(self, name, err):
        self.failed += 1
        self.errors.append((name, err))
        print(f"  [FAIL] {name}: {err}")

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*60}")
        print(f"Striker ReAct Tests: {self.passed}/{total} passed")
        if self.errors:
            print("Failed:")
            for name, err in self.errors:
                print(f"  - {name}: {err}")
        print(f"{'='*60}")
        return self.failed == 0


results = Results()


MOCK_STATE = {
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
                    "version": "Python/3.8 BaseHTTPServer",
                    "banner": "",
                },
            },
            "vulns": [],
        }
    },
    "web_findings": [
        {
            "path": "/login",
            "status_code": 200,
            "is_interesting": True,
        },
        {
            "path": "/health",
            "status_code": 200,
            "is_interesting": False,
        },
    ],
    "research_cache": {
        "OpenSSH 8.2p1": "Brute-force likely; no straightforward RCE.",
    },
    "osint_findings": [
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
}


def _make_tool(name: str) -> StructuredTool:
    def _sync_tool(**kwargs):
        return json.dumps({"status": "success", "tool": name, "kwargs": kwargs})

    async def _async_tool(**kwargs):
        return json.dumps({"status": "success", "tool": name, "kwargs": kwargs})

    return StructuredTool.from_function(
        func=_sync_tool,
        coroutine=_async_tool,
        name=name,
        description=f"Mock tool: {name}",
    )


class MockBridge:
    def __init__(self, tools):
        self._tools = tools

    def get_tools_for_agent(self, allowed_tools):
        _ = allowed_tools
        return self._tools


class PatchContext:
    """Minimal monkeypatch helper without pytest dependency."""

    def __init__(self):
        self._saved = {}

    def set(self, obj, attr, value):
        self._saved[(obj, attr)] = getattr(obj, attr)
        setattr(obj, attr, value)

    def restore(self):
        for (obj, attr), val in reversed(list(self._saved.items())):
            setattr(obj, attr, val)
        self._saved.clear()


def test_build_context_includes_key_sections():
    ctx = striker_mod._build_striker_context(MOCK_STATE)
    required_snippets = [
        "MISSION: Gain initial access to automotive-testbed",
        "TARGET INTELLIGENCE:",
        "automotive-testbed",
        "22/tcp ssh",
        "INTERESTING WEB FINDINGS:",
        "/login",
        "PRIOR EXPLOIT ATTEMPTS IN THIS MISSION:",
    ]
    missing = [snippet for snippet in required_snippets if snippet not in ctx]
    if missing:
        results.add_fail("test_build_context_includes_key_sections", f"Missing: {missing}")
    else:
        results.add_pass("test_build_context_includes_key_sections")


async def test_striker_node_no_targets_returns_validation_error():
    state = {**MOCK_STATE, "discovered_targets": {}}
    out = await striker_mod.striker_node(state)
    errs = out.get("errors", [])
    if not errs:
        results.add_fail("test_striker_node_no_targets_returns_validation_error", "No errors returned")
        return

    first_err = errs[0]
    err_type = getattr(first_err, "error_type", "")
    if err_type != "ValidationError":
        results.add_fail(
            "test_striker_node_no_targets_returns_validation_error",
            f"Expected ValidationError, got {err_type}",
        )
        return

    results.add_pass("test_striker_node_no_targets_returns_validation_error")


async def test_striker_node_success_with_mocked_react_loop():
    patches = PatchContext()
    try:
        tools = [
            _make_tool("msf_list_exploits"),
            _make_tool("msf_get_module_options"),
            _make_tool("msf_list_payloads"),
            _make_tool("msf_run_exploit"),
            _make_tool("msf_run_auxiliary_module"),
            _make_tool("msf_list_active_sessions"),
        ]

        async def fake_get_bridge():
            return MockBridge(tools)

        def fake_build_llm():
            return object()

        def fake_create_react_agent(model, tools, **kwargs):
            _ = (model, tools, kwargs)

            class FakeAgent:
                async def ainvoke(self, payload):
                    _ = payload
                    return {
                        "messages": [
                            ToolMessage(
                                tool_call_id="call-1",
                                name="msf_run_exploit",
                                content=json.dumps(
                                    {
                                        "status": "success",
                                        "module": "exploit/linux/ssh/example",
                                        "session_id": 7,
                                        "options": {"RHOSTS": "automotive-testbed", "RPORT": "22"},
                                    }
                                ),
                            )
                        ]
                    }

            return FakeAgent()

        patches.set(striker_mod, "get_mcp_bridge", fake_get_bridge)
        patches.set(striker_mod, "_build_llm", fake_build_llm)
        patches.set(striker_mod, "create_react_agent", fake_create_react_agent)
        patches.set(striker_mod, "STRIKER_REQUIRE_CONFIRMATION", False)

        out = await striker_mod.striker_node(MOCK_STATE)

        if out.get("errors"):
            results.add_fail("test_striker_node_success_with_mocked_react_loop", f"Unexpected errors: {out['errors']}")
            return

        sessions = out.get("active_sessions", {})
        target_session = sessions.get("automotive-testbed", {})
        sid = target_session.get("session_id")
        if sid != 7:
            results.add_fail(
                "test_striker_node_success_with_mocked_react_loop",
                f"Expected session_id 7 for automotive-testbed, got {sid}",
            )
            return

        exploited = out.get("exploited_services", [])
        if not exploited:
            results.add_fail("test_striker_node_success_with_mocked_react_loop", "No exploited_services entry recorded")
            return

        results.add_pass("test_striker_node_success_with_mocked_react_loop")
    except Exception as e:
        traceback.print_exc()
        results.add_fail("test_striker_node_success_with_mocked_react_loop", str(e))
    finally:
        patches.restore()


async def main():
    print("=" * 60)
    print("Striker ReAct Agent Test Suite")
    print("=" * 60)

    test_build_context_includes_key_sections()
    await test_striker_node_no_targets_returns_validation_error()
    await test_striker_node_success_with_mocked_react_loop()

    ok = results.summary()
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
