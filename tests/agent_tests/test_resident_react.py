#!/usr/bin/env python3
"""
Resident ReAct Agent Tests
===========================
Validates src/agents/resident.py behavior without requiring live MCP/model calls.

Run inside agents container:
    docker exec vt-saiber-agents python tests/agent_tests/test_resident_react.py
"""

import asyncio
import json
import sys
import traceback

sys.path.insert(0, "/app")

import src.agents.resident as resident_mod
from langchain_core.messages import ToolMessage, AIMessage
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
        print(f"Resident ReAct Tests: {self.passed}/{total} passed")
        if self.errors:
            print("Failed:")
            for name, err in self.errors:
                print(f"  - {name}: {err}")
        print(f"{'='*60}")
        return self.failed == 0


results = Results()


MOCK_STATE = {
    "mission_goal": "Post-exploit automotive-testbed and enumerate",
    "mission_id": "test-resident-001",
    "mission_status": "active",
    "current_agent": "resident",
    "next_agent": None,
    "iteration_count": 6,
    "target_scope": ["172.20.0.0/16", "automotive-testbed"],
    "discovered_targets": {
        "automotive-testbed": {
            "ip_address": "automotive-testbed",
            "os_guess": "Linux (Ubuntu 20.04)",
            "ports": [22, 8000],
            "services": {
                "22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"},
                "8000": {"service_name": "http", "version": "Python/3.8"},
            },
        }
    },
    "active_sessions": {
        "automotive-testbed": {
            "session_id": 7,
            "module": "auxiliary/scanner/ssh/ssh_login",
            "lhost": "msf-mcp",
            "lport": "4444",
            "established_at": "2025-01-15T10:30:00",
        }
    },
    "research_cache": {
        "ssh privesc": "Check sudo -l and SUID binaries for escalation paths",
    },
    "intelligence_findings": [
        {
            "cve": "CVE-2021-4034",
            "description": "Polkit pkexec local privilege escalation",
            "data": {},
        }
    ],
    "web_findings": [],
    "exploited_services": [],
    "supervisor_messages": [],
    "supervisor_expectations": {},
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
    def __init__(self):
        self._saved = {}

    def set(self, obj, attr, value):
        self._saved[(obj, attr)] = getattr(obj, attr)
        setattr(obj, attr, value)

    def restore(self):
        for (obj, attr), val in reversed(list(self._saved.items())):
            setattr(obj, attr, val)
        self._saved.clear()


# ═══════════════════════════════════════════════════════════════
# TEST: Context builder
# ═══════════════════════════════════════════════════════════════

def test_build_context_includes_key_sections():
    ctx = resident_mod._build_resident_context(MOCK_STATE)
    required_snippets = [
        "MISSION: Post-exploit automotive-testbed",
        "ACTIVE SESSIONS:",
        "session_id=7",
        "automotive-testbed",
        "TARGET CONTEXT:",
        "RESEARCH & OSINT INTELLIGENCE:",
        "ssh privesc",
        "OSINT:",
        "Polkit pkexec",
    ]
    missing = [s for s in required_snippets if s not in ctx]
    if missing:
        results.add_fail("test_build_context_includes_key_sections", f"Missing: {missing}")
    else:
        results.add_pass("test_build_context_includes_key_sections")


def test_build_context_empty_sessions():
    state = {**MOCK_STATE, "active_sessions": {}}
    ctx = resident_mod._build_resident_context(state)
    if "(none)" not in ctx:
        results.add_fail("test_build_context_empty_sessions", "Expected '(none)' for empty sessions")
    else:
        results.add_pass("test_build_context_empty_sessions")


def test_build_context_empty_research():
    state = {**MOCK_STATE, "research_cache": {}, "intelligence_findings": []}
    ctx = resident_mod._build_resident_context(state)
    research_section = ctx.split("RESEARCH & OSINT INTELLIGENCE:")[1]
    if "(none)" not in research_section.split("\n\n")[0]:
        results.add_fail("test_build_context_empty_research", "Expected '(none)' for empty research")
    else:
        results.add_pass("test_build_context_empty_research")


# ═══════════════════════════════════════════════════════════════
# TEST: Validation errors
# ═══════════════════════════════════════════════════════════════

async def test_resident_node_no_sessions_returns_validation_error():
    state = {**MOCK_STATE, "active_sessions": {}}
    out = await resident_mod.resident_node(state)
    errs = out.get("errors", [])
    if not errs:
        results.add_fail("test_no_sessions_validation_error", "No errors returned")
        return
    err_type = getattr(errs[0], "error_type", "")
    if err_type != "ValidationError":
        results.add_fail("test_no_sessions_validation_error", f"Expected ValidationError, got {err_type}")
        return
    recoverable = getattr(errs[0], "recoverable", None)
    if recoverable is not True:
        results.add_fail("test_no_sessions_validation_error", "Expected recoverable=True")
        return
    results.add_pass("test_no_sessions_validation_error")


async def test_resident_node_no_tools_returns_tool_error():
    patches = PatchContext()
    try:
        async def fake_get_bridge():
            return MockBridge([])

        patches.set(resident_mod, "get_mcp_bridge", fake_get_bridge)
        out = await resident_mod.resident_node(MOCK_STATE)
        errs = out.get("errors", [])
        if not errs:
            results.add_fail("test_no_tools_error", "No errors returned")
            return
        err_type = getattr(errs[0], "error_type", "")
        if err_type != "ToolError":
            results.add_fail("test_no_tools_error", f"Expected ToolError, got {err_type}")
            return
        recoverable = getattr(errs[0], "recoverable", None)
        if recoverable is not False:
            results.add_fail("test_no_tools_error", "Expected recoverable=False")
            return
        results.add_pass("test_no_tools_error")
    finally:
        patches.restore()


async def test_resident_node_missing_send_session_command():
    patches = PatchContext()
    try:
        tools = [
            _make_tool("msf_list_active_sessions"),
            _make_tool("msf_run_post_module"),
        ]

        async def fake_get_bridge():
            return MockBridge(tools)

        patches.set(resident_mod, "get_mcp_bridge", fake_get_bridge)
        out = await resident_mod.resident_node(MOCK_STATE)
        errs = out.get("errors", [])
        if not errs:
            results.add_fail("test_missing_send_session_command", "No errors returned")
            return
        err_msg = getattr(errs[0], "error", "")
        if "msf_send_session_command" not in err_msg:
            results.add_fail("test_missing_send_session_command", f"Expected mention of missing tool: {err_msg}")
            return
        results.add_pass("test_missing_send_session_command")
    finally:
        patches.restore()


# ═══════════════════════════════════════════════════════════════
# TEST: State update extraction
# ═══════════════════════════════════════════════════════════════

def test_extract_root_privilege_detection():
    messages = [
        AIMessage(content="Checking session..."),
        ToolMessage(
            tool_call_id="call-1",
            name="msf_send_session_command",
            content=json.dumps({
                "output": "uid=0(root) gid=0(root) groups=0(root)",
                "status": "success",
            }),
        ),
    ]
    updates = resident_mod._extract_resident_updates(messages, MOCK_STATE)
    log_entries = updates.get("agent_log", [])
    if not log_entries:
        results.add_fail("test_root_detection", "No agent_log entries")
        return
    findings = updates.get("critical_findings", [])
    has_root = any("root" in f.lower() for f in findings)
    if not has_root:
        results.add_fail("test_root_detection", f"Expected root finding in critical_findings: {findings}")
        return
    sessions = updates.get("active_sessions", {})
    target_info = sessions.get("automotive-testbed", {})
    if target_info.get("privilege") != "root":
        results.add_fail("test_root_detection", f"Expected privilege=root in enriched session: {target_info}")
        return
    results.add_pass("test_root_detection")


def test_extract_user_privilege_detection():
    messages = [
        ToolMessage(
            tool_call_id="call-1",
            name="msf_send_session_command",
            content=json.dumps({
                "output": "uid=1000(admin) gid=1000(admin) groups=1000(admin)",
                "status": "success",
            }),
        ),
    ]
    updates = resident_mod._extract_resident_updates(messages, MOCK_STATE)
    sessions = updates.get("active_sessions", {})
    target_info = sessions.get("automotive-testbed", {})
    if target_info.get("privilege") != "user":
        results.add_fail("test_user_detection", f"Expected privilege=user: {target_info}")
        return
    results.add_pass("test_user_detection")


def test_extract_os_info_from_uname():
    messages = [
        ToolMessage(
            tool_call_id="call-1",
            name="msf_send_session_command",
            content=json.dumps({
                "output": "Linux testbed 5.4.0-91-generic #102-Ubuntu SMP x86_64 GNU/Linux",
                "status": "success",
            }),
        ),
    ]
    updates = resident_mod._extract_resident_updates(messages, MOCK_STATE)
    sessions = updates.get("active_sessions", {})
    target_info = sessions.get("automotive-testbed", {})
    os_info = target_info.get("os_info", "")
    if "5.4.0-91" not in os_info:
        results.add_fail("test_os_info_extraction", f"Expected kernel version in os_info: {os_info}")
        return
    results.add_pass("test_os_info_extraction")


def test_extract_post_module_success():
    messages = [
        ToolMessage(
            tool_call_id="call-1",
            name="msf_run_post_module",
            content=json.dumps({
                "status": "success",
                "module": "post/linux/gather/enum_system",
                "module_output": "Linux testbed 5.4.0",
            }),
        ),
    ]
    updates = resident_mod._extract_resident_updates(messages, MOCK_STATE)
    findings = updates.get("critical_findings", [])
    has_post = any("post module succeeded" in f.lower() for f in findings)
    if not has_post:
        results.add_fail("test_post_module_success", f"Expected post module finding: {findings}")
        return
    results.add_pass("test_post_module_success")


def test_extract_ignores_non_post_tools():
    messages = [
        ToolMessage(
            tool_call_id="call-1",
            name="msf_list_active_sessions",
            content=json.dumps({"sessions": {"7": {"type": "shell"}}, "count": 1}),
        ),
    ]
    updates = resident_mod._extract_resident_updates(messages, MOCK_STATE)
    if updates.get("critical_findings"):
        results.add_fail("test_ignores_non_post", "Should not produce critical_findings from list_active_sessions")
        return
    results.add_pass("test_ignores_non_post")


def test_extract_handles_malformed_json():
    messages = [
        ToolMessage(
            tool_call_id="call-1",
            name="msf_send_session_command",
            content="this is not valid json {{{",
        ),
    ]
    try:
        updates = resident_mod._extract_resident_updates(messages, MOCK_STATE)
        if "iteration_count" not in updates:
            results.add_fail("test_malformed_json", "Expected iteration_count in updates")
            return
        results.add_pass("test_malformed_json")
    except Exception as e:
        results.add_fail("test_malformed_json", f"Should not raise: {e}")


def test_iteration_count_incremented():
    messages = []
    updates = resident_mod._extract_resident_updates(messages, MOCK_STATE)
    expected = MOCK_STATE["iteration_count"] + 1
    if updates.get("iteration_count") != expected:
        results.add_fail("test_iteration_increment", f"Expected {expected}, got {updates.get('iteration_count')}")
        return
    results.add_pass("test_iteration_increment")


# ═══════════════════════════════════════════════════════════════
# TEST: Full ReAct loop (mocked)
# ═══════════════════════════════════════════════════════════════

async def test_resident_node_success_with_mocked_react_loop():
    patches = PatchContext()
    try:
        tools = [
            _make_tool("msf_list_active_sessions"),
            _make_tool("msf_send_session_command"),
            _make_tool("msf_run_post_module"),
            _make_tool("msf_list_exploits"),
            _make_tool("msf_terminate_session"),
        ]

        async def fake_get_bridge():
            return MockBridge(tools)

        def fake_build_llm():
            return object()

        def fake_create_react_agent(model, tools, **kwargs):
            class FakeAgent:
                async def ainvoke(self, payload):
                    return {
                        "messages": [
                            ToolMessage(
                                tool_call_id="call-1",
                                name="msf_send_session_command",
                                content=json.dumps({
                                    "output": "uid=0(root) gid=0(root) groups=0(root)",
                                    "status": "success",
                                }),
                            ),
                            ToolMessage(
                                tool_call_id="call-2",
                                name="msf_send_session_command",
                                content=json.dumps({
                                    "output": "Linux testbed 5.4.0-91-generic #102-Ubuntu SMP x86_64 GNU/Linux",
                                    "status": "success",
                                }),
                            ),
                            ToolMessage(
                                tool_call_id="call-3",
                                name="msf_run_post_module",
                                content=json.dumps({
                                    "status": "success",
                                    "module": "post/linux/gather/enum_system",
                                    "module_output": "System enumeration complete",
                                }),
                            ),
                        ]
                    }
            return FakeAgent()

        patches.set(resident_mod, "get_mcp_bridge", fake_get_bridge)
        patches.set(resident_mod, "_build_llm", fake_build_llm)
        patches.set(resident_mod, "create_react_agent", fake_create_react_agent)

        out = await resident_mod.resident_node(MOCK_STATE)

        if out.get("errors"):
            results.add_fail("test_mocked_react_loop", f"Unexpected errors: {out['errors']}")
            return

        sessions = out.get("active_sessions", {})
        target = sessions.get("automotive-testbed", {})
        if target.get("privilege") != "root":
            results.add_fail("test_mocked_react_loop", f"Expected root privilege: {target}")
            return

        if "5.4.0" not in target.get("os_info", ""):
            results.add_fail("test_mocked_react_loop", f"Expected OS info: {target}")
            return

        findings = out.get("critical_findings", [])
        if len(findings) < 2:
            results.add_fail("test_mocked_react_loop", f"Expected >=2 critical findings: {findings}")
            return

        if target.get("post_exploitation_at") is None:
            results.add_fail("test_mocked_react_loop", "Expected post_exploitation_at timestamp")
            return

        results.add_pass("test_mocked_react_loop")
    except Exception as e:
        traceback.print_exc()
        results.add_fail("test_mocked_react_loop", str(e))
    finally:
        patches.restore()


# ═══════════════════════════════════════════════════════════════
# TEST: Prompt import
# ═══════════════════════════════════════════════════════════════

def test_prompt_imported_from_prompts_module():
    from src.prompts.resident_prompt import RESIDENT_SYSTEM_PROMPT as external_prompt
    if resident_mod.RESIDENT_SYSTEM_PROMPT is not external_prompt:
        results.add_fail("test_prompt_import", "resident.py should import prompt from prompts/resident_prompt.py")
        return
    if len(external_prompt) < 500:
        results.add_fail("test_prompt_import", f"Prompt too short ({len(external_prompt)} chars), expected comprehensive prompt")
        return
    required_sections = ["Phase 1", "Phase 2", "Phase 3", "Phase 4", "Phase 5", "Phase 6", "Rules:"]
    missing = [s for s in required_sections if s not in external_prompt]
    if missing:
        results.add_fail("test_prompt_import", f"Prompt missing sections: {missing}")
        return
    results.add_pass("test_prompt_import")


# ═══════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════

async def main():
    print("=" * 60)
    print("Resident ReAct Agent Test Suite")
    print("=" * 60)

    # Context builder tests
    test_build_context_includes_key_sections()
    test_build_context_empty_sessions()
    test_build_context_empty_research()

    # Validation error tests
    await test_resident_node_no_sessions_returns_validation_error()
    await test_resident_node_no_tools_returns_tool_error()
    await test_resident_node_missing_send_session_command()

    # State extraction tests
    test_extract_root_privilege_detection()
    test_extract_user_privilege_detection()
    test_extract_os_info_from_uname()
    test_extract_post_module_success()
    test_extract_ignores_non_post_tools()
    test_extract_handles_malformed_json()
    test_iteration_count_incremented()

    # Full loop test
    await test_resident_node_success_with_mocked_react_loop()

    # Prompt test
    test_prompt_imported_from_prompts_module()

    ok = results.summary()
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
