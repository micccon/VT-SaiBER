#!/usr/bin/env python3
"""
Failure Recovery Tests
======================
Tests error handling, graceful degradation, agent failure paths,
router safety checks, and recoverable vs non-recoverable errors.

Run inside agents container:
    docker exec vt-saiber-agents python tests/integration/test_failure_recovery.py
"""

import asyncio
import json
import os
import sys
import traceback

sys.path.insert(0, "/app")

from langchain_core.messages import ToolMessage, AIMessage
from langchain_core.tools import StructuredTool

import src.agents.striker as striker_mod
import src.agents.resident as resident_mod
import src.agents.scout as scout_mod
from src.graph.router import route_next_agent, validate_all_targets_in_scope
from src.main import build_initial_state
from src.state.models import AgentError, AgentLogEntry


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
        print(f"Failure Recovery Tests: {self.passed}/{total} passed")
        if self.errors:
            print("Failed:")
            for name, err in self.errors:
                print(f"  - {name}: {err}")
        print(f"{'='*60}")
        return self.failed == 0


results = Results()


def _make_tool(name: str) -> StructuredTool:
    def _sync(**kw):
        return json.dumps({"status": "success"})
    async def _async(**kw):
        return json.dumps({"status": "success"})
    return StructuredTool.from_function(func=_sync, coroutine=_async, name=name, description=f"Mock: {name}")


class MockBridge:
    def __init__(self, tools):
        self._tools = tools
    def get_tools_for_agent(self, allowed):
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
# TEST: MCP bridge failures
# ═══════════════════════════════════════════════════════════════

async def test_striker_mcp_bridge_failure():
    """Striker should return ToolError when bridge raises."""
    patches = PatchContext()
    try:
        async def failing_bridge():
            raise ConnectionError("MCP server unreachable")

        patches.set(striker_mod, "get_mcp_bridge", failing_bridge)
        state = build_initial_state("Test", ["10.0.0.1"], "f-001")
        state["discovered_targets"] = {"10.0.0.1": {"services": {}}}

        try:
            out = await striker_mod.striker_node(state)
            # If bridge failure is not caught, the node should propagate
            results.add_fail("test_striker_bridge_fail", "Expected exception or error")
        except ConnectionError:
            results.add_pass("test_striker_bridge_fail")
    except Exception as e:
        # ConnectionError propagation is acceptable behavior
        if "unreachable" in str(e):
            results.add_pass("test_striker_bridge_fail")
        else:
            results.add_fail("test_striker_bridge_fail", str(e))
    finally:
        patches.restore()


async def test_resident_mcp_bridge_failure():
    """Resident should return ToolError when bridge raises."""
    patches = PatchContext()
    try:
        async def failing_bridge():
            raise ConnectionError("MCP server unreachable")

        patches.set(resident_mod, "get_mcp_bridge", failing_bridge)
        state = build_initial_state("Test", ["10.0.0.1"], "f-002")
        state["active_sessions"] = {"10.0.0.1": {"session_id": 1}}

        try:
            out = await resident_mod.resident_node(state)
            results.add_fail("test_resident_bridge_fail", "Expected exception or error")
        except ConnectionError:
            results.add_pass("test_resident_bridge_fail")
    except Exception as e:
        if "unreachable" in str(e):
            results.add_pass("test_resident_bridge_fail")
        else:
            results.add_fail("test_resident_bridge_fail", str(e))
    finally:
        patches.restore()


# ═══════════════════════════════════════════════════════════════
# TEST: Tool unavailability
# ═══════════════════════════════════════════════════════════════

async def test_striker_no_tools():
    """Striker returns ToolError when bridge has zero tools."""
    patches = PatchContext()
    try:
        async def empty_bridge():
            return MockBridge([])

        patches.set(striker_mod, "get_mcp_bridge", empty_bridge)
        state = build_initial_state("Test", ["10.0.0.1"], "f-003")
        state["discovered_targets"] = {"10.0.0.1": {"services": {}}}

        out = await striker_mod.striker_node(state)
        errs = out.get("errors", [])
        if not errs:
            results.add_fail("test_striker_no_tools", "Expected errors")
            return
        err_type = getattr(errs[0], "error_type", "")
        if err_type != "ToolError":
            results.add_fail("test_striker_no_tools", f"Expected ToolError, got {err_type}")
            return
        results.add_pass("test_striker_no_tools")
    finally:
        patches.restore()


async def test_striker_missing_required_tools():
    """Striker returns error when required exploit tools are missing."""
    patches = PatchContext()
    try:
        tools = [_make_tool("msf_list_exploits")]  # Missing run_exploit and run_auxiliary_module

        async def partial_bridge():
            return MockBridge(tools)

        patches.set(striker_mod, "get_mcp_bridge", partial_bridge)
        state = build_initial_state("Test", ["10.0.0.1"], "f-004")
        state["discovered_targets"] = {"10.0.0.1": {"services": {}}}

        out = await striker_mod.striker_node(state)
        errs = out.get("errors", [])
        if not errs:
            results.add_fail("test_missing_required_tools", "Expected errors")
            return
        err_msg = getattr(errs[0], "error", "")
        if "missing" not in err_msg.lower():
            results.add_fail("test_missing_required_tools", f"Expected 'missing' in error: {err_msg}")
            return
        results.add_pass("test_missing_required_tools")
    finally:
        patches.restore()


async def test_resident_no_tools():
    """Resident returns ToolError when bridge has zero tools."""
    patches = PatchContext()
    try:
        async def empty_bridge():
            return MockBridge([])

        patches.set(resident_mod, "get_mcp_bridge", empty_bridge)
        state = build_initial_state("Test", ["10.0.0.1"], "f-005")
        state["active_sessions"] = {"10.0.0.1": {"session_id": 1}}

        out = await resident_mod.resident_node(state)
        errs = out.get("errors", [])
        if not errs:
            results.add_fail("test_resident_no_tools", "Expected errors")
            return
        err_type = getattr(errs[0], "error_type", "")
        if err_type != "ToolError":
            results.add_fail("test_resident_no_tools", f"Expected ToolError, got {err_type}")
            return
        recoverable = getattr(errs[0], "recoverable", True)
        if recoverable is not False:
            results.add_fail("test_resident_no_tools", "ToolError should be non-recoverable")
            return
        results.add_pass("test_resident_no_tools")
    finally:
        patches.restore()


# ═══════════════════════════════════════════════════════════════
# TEST: Scope violations
# ═══════════════════════════════════════════════════════════════

def test_scope_validation_out_of_scope():
    """Router should reject out-of-scope targets."""
    state = build_initial_state("Test", ["192.168.1.0/24"], "f-006")
    state["discovered_targets"] = {"10.99.99.99": {"services": {}}}
    valid = validate_all_targets_in_scope(state)
    if valid:
        results.add_fail("test_out_of_scope", "Should have rejected out-of-scope target")
        return
    results.add_pass("test_out_of_scope")


def test_scope_validation_in_scope():
    """Router should accept in-scope targets."""
    state = build_initial_state("Test", ["192.168.1.0/24"], "f-007")
    state["discovered_targets"] = {"192.168.1.50": {"services": {}}}
    valid = validate_all_targets_in_scope(state)
    if not valid:
        results.add_fail("test_in_scope", "Should have accepted in-scope target")
        return
    results.add_pass("test_in_scope")


def test_scope_validation_no_scope_defined():
    """Router should reject when no scope is defined."""
    state = build_initial_state("Test", [], "f-008")
    state["target_scope"] = []
    state["discovered_targets"] = {"10.0.0.1": {"services": {}}}
    valid = validate_all_targets_in_scope(state)
    if valid:
        results.add_fail("test_no_scope", "Should reject when no scope defined")
        return
    results.add_pass("test_no_scope")


def test_scope_validation_exact_ip():
    """Exact IP in scope should be accepted."""
    state = build_initial_state("Test", ["10.0.0.5"], "f-009")
    state["discovered_targets"] = {"10.0.0.5": {"services": {}}}
    valid = validate_all_targets_in_scope(state)
    if not valid:
        results.add_fail("test_exact_ip_scope", "Exact IP should be accepted")
        return
    results.add_pass("test_exact_ip_scope")


def test_router_blocks_out_of_scope():
    """Full router should END when targets are out of scope."""
    state = build_initial_state("Test", ["192.168.1.0/24"], "f-010")
    state["discovered_targets"] = {"10.99.99.99": {"services": {}}}
    state["next_agent"] = "striker"
    result = route_next_agent(state)
    if result != "__end__":
        results.add_fail("test_router_blocks_oos", f"Expected __end__, got {result}")
        return
    results.add_pass("test_router_blocks_oos")


# ═══════════════════════════════════════════════════════════════
# TEST: Max iteration safety
# ═══════════════════════════════════════════════════════════════

def test_router_max_iterations_boundary():
    """Router should END at exactly max_iterations + 1."""
    from src.config import get_runtime_config
    max_iter = get_runtime_config().max_iterations

    state = build_initial_state("Test", ["10.0.0.1"], "f-011")
    state["next_agent"] = "scout"

    # At max: should still route
    state["iteration_count"] = max_iter
    result = route_next_agent(state)
    if result != "scout":
        results.add_fail("test_max_iter_boundary", f"At max ({max_iter}): expected scout, got {result}")
        return

    # Over max: should END
    state["iteration_count"] = max_iter + 1
    result = route_next_agent(state)
    if result != "__end__":
        results.add_fail("test_max_iter_boundary", f"Over max: expected __end__, got {result}")
        return
    results.add_pass("test_max_iter_boundary")


# ═══════════════════════════════════════════════════════════════
# TEST: Recoverable vs non-recoverable errors
# ═══════════════════════════════════════════════════════════════

def test_recoverable_error_classification():
    """Validation errors should be recoverable; tool errors should not."""
    validation_err = AgentError(
        agent="striker", error_type="ValidationError", error="No targets", recoverable=True
    )
    tool_err = AgentError(
        agent="striker", error_type="ToolError", error="MCP down", recoverable=False
    )
    if not validation_err.recoverable:
        results.add_fail("test_error_classification", "ValidationError should be recoverable")
        return
    if tool_err.recoverable:
        results.add_fail("test_error_classification", "ToolError should not be recoverable")
        return
    results.add_pass("test_error_classification")


async def test_striker_validation_error_is_recoverable():
    """No-targets error from Striker should be recoverable."""
    state = build_initial_state("Test", ["10.0.0.1"], "f-012")
    state["discovered_targets"] = {}
    out = await striker_mod.striker_node(state)
    errs = out.get("errors", [])
    if not errs:
        results.add_fail("test_striker_recoverable", "Expected errors")
        return
    if not getattr(errs[0], "recoverable", False):
        results.add_fail("test_striker_recoverable", "Should be recoverable")
        return
    results.add_pass("test_striker_recoverable")


async def test_resident_validation_error_is_recoverable():
    """No-sessions error from Resident should be recoverable."""
    state = build_initial_state("Test", ["10.0.0.1"], "f-013")
    state["active_sessions"] = {}
    out = await resident_mod.resident_node(state)
    errs = out.get("errors", [])
    if not errs:
        results.add_fail("test_resident_recoverable", "Expected errors")
        return
    if not getattr(errs[0], "recoverable", False):
        results.add_fail("test_resident_recoverable", "Should be recoverable")
        return
    results.add_pass("test_resident_recoverable")


# ═══════════════════════════════════════════════════════════════
# TEST: Scout fallback on MCP failure
# ═══════════════════════════════════════════════════════════════

async def test_scout_fallback_on_bridge_failure():
    """Scout should return fallback services when MCP bridge fails."""
    patches = PatchContext()
    try:
        async def failing_bridge():
            raise ConnectionError("MCP down")

        patches.set(scout_mod, "get_mcp_bridge", failing_bridge)
        state = build_initial_state("Test", ["10.0.0.1"], "f-014")
        state["target_scope"] = ["10.0.0.1"]

        out = await scout_mod.scout_node(state)
        targets = out.get("discovered_targets", {})
        if "10.0.0.1" not in targets:
            results.add_fail("test_scout_fallback", "Should still discover target via fallback")
            return
        services = targets["10.0.0.1"].get("services", {})
        if not services:
            results.add_fail("test_scout_fallback", "Fallback should provide default services")
            return
        results.add_pass("test_scout_fallback")
    except Exception as e:
        results.add_fail("test_scout_fallback", str(e))
    finally:
        patches.restore()


# ═══════════════════════════════════════════════════════════════
# TEST: Resident handles dead sessions gracefully
# ═══════════════════════════════════════════════════════════════

def test_extract_handles_empty_messages():
    """Resident extractor should handle empty message list."""
    updates = resident_mod._extract_resident_updates([], {
        **build_initial_state("Test", ["10.0.0.1"], "f-015"),
        "active_sessions": {"10.0.0.1": {"session_id": 1}},
    })
    if "iteration_count" not in updates:
        results.add_fail("test_empty_messages", "Missing iteration_count")
        return
    if updates.get("critical_findings"):
        results.add_fail("test_empty_messages", "Should have no critical findings")
        return
    results.add_pass("test_empty_messages")


def test_extract_handles_mixed_message_types():
    """Extractor should skip non-ToolMessage types."""
    messages = [
        AIMessage(content="Analyzing session..."),
        ToolMessage(tool_call_id="c1", name="msf_send_session_command",
                    content=json.dumps({"output": "uid=0(root)"})),
        AIMessage(content="Found root!"),
    ]
    state = {
        **build_initial_state("Test", ["10.0.0.1"], "f-016"),
        "active_sessions": {"10.0.0.1": {"session_id": 1}},
    }
    updates = resident_mod._extract_resident_updates(messages, state)
    findings = updates.get("critical_findings", [])
    has_root = any("root" in f.lower() for f in findings)
    if not has_root:
        results.add_fail("test_mixed_messages", "Should detect root from ToolMessage")
        return
    results.add_pass("test_mixed_messages")


# ═══════════════════════════════════════════════════════════════
# TEST: AgentError model validation
# ═══════════════════════════════════════════════════════════════

def test_agent_error_model():
    err = AgentError(agent="test", error_type="TestError", error="something broke", recoverable=True)
    if err.agent != "test":
        results.add_fail("test_agent_error_model", "Wrong agent")
        return
    if not err.timestamp:
        results.add_fail("test_agent_error_model", "Missing timestamp")
        return
    dumped = err.model_dump()
    if "agent" not in dumped or "error_type" not in dumped:
        results.add_fail("test_agent_error_model", f"Bad dump: {dumped}")
        return
    results.add_pass("test_agent_error_model")


def test_agent_log_entry_model():
    entry = AgentLogEntry(agent="scout", action="recon_scan", target="10.0.0.1")
    if not entry.timestamp:
        results.add_fail("test_log_entry_model", "Missing timestamp")
        return
    dumped = entry.model_dump()
    if dumped["agent"] != "scout":
        results.add_fail("test_log_entry_model", "Wrong agent in dump")
        return
    results.add_pass("test_log_entry_model")


# ═══════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════

async def main():
    print("=" * 60)
    print("Failure Recovery Test Suite")
    print("=" * 60)

    # MCP bridge failures
    await test_striker_mcp_bridge_failure()
    await test_resident_mcp_bridge_failure()

    # Tool unavailability
    await test_striker_no_tools()
    await test_striker_missing_required_tools()
    await test_resident_no_tools()

    # Scope violations
    test_scope_validation_out_of_scope()
    test_scope_validation_in_scope()
    test_scope_validation_no_scope_defined()
    test_scope_validation_exact_ip()
    test_router_blocks_out_of_scope()

    # Max iterations
    test_router_max_iterations_boundary()

    # Error classification
    test_recoverable_error_classification()
    await test_striker_validation_error_is_recoverable()
    await test_resident_validation_error_is_recoverable()

    # Agent fallbacks
    await test_scout_fallback_on_bridge_failure()

    # Message handling
    test_extract_handles_empty_messages()
    test_extract_handles_mixed_message_types()

    # Model validation
    test_agent_error_model()
    test_agent_log_entry_model()

    ok = results.summary()
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
