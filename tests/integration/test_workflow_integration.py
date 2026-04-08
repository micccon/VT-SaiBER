#!/usr/bin/env python3
"""
Full Workflow Integration Test
==============================
Validates the complete supervisor → scout → striker → resident pipeline
with mocked MCP tools and LLM. Tests state propagation between agents.

Run inside agents container:
    docker exec vt-saiber-agents python tests/integration/test_workflow_integration.py
"""

import asyncio
import json
import sys
import traceback

sys.path.insert(0, "/app")

from langchain_core.messages import ToolMessage
from langchain_core.tools import StructuredTool

import src.agents.scout as scout_mod
import src.agents.striker as striker_mod
import src.agents.resident as resident_mod
from src.graph.router import route_next_agent, VALID_AGENTS
from src.state.cyber_state import CyberState
from src.main import build_initial_state


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
        print(f"Workflow Integration Tests: {self.passed}/{total} passed")
        if self.errors:
            print("Failed:")
            for name, err in self.errors:
                print(f"  - {name}: {err}")
        print(f"{'='*60}")
        return self.failed == 0


results = Results()


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
# TEST: build_initial_state produces valid CyberState
# ═══════════════════════════════════════════════════════════════

def test_build_initial_state():
    state = build_initial_state(
        mission_goal="Exploit 192.168.1.50",
        target_scope=["192.168.1.0/24"],
        mission_id="test-workflow-001",
    )
    required_keys = [
        "current_agent", "next_agent", "iteration_count", "mission_status",
        "mission_goal", "target_scope", "mission_id", "discovered_targets",
        "active_sessions", "agent_log", "critical_findings", "errors",
    ]
    missing = [k for k in required_keys if k not in state]
    if missing:
        results.add_fail("test_build_initial_state", f"Missing keys: {missing}")
        return
    if state["mission_status"] != "active":
        results.add_fail("test_build_initial_state", f"Expected active, got {state['mission_status']}")
        return
    if state["current_agent"] != "supervisor":
        results.add_fail("test_build_initial_state", f"Expected supervisor, got {state['current_agent']}")
        return
    results.add_pass("test_build_initial_state")


# ═══════════════════════════════════════════════════════════════
# TEST: Router safety checks
# ═══════════════════════════════════════════════════════════════

def test_router_max_iterations():
    state = build_initial_state("test", ["192.168.1.0/24"], "test-001")
    state["iteration_count"] = 999
    state["next_agent"] = "scout"
    result = route_next_agent(state)
    if result != "__end__":
        results.add_fail("test_router_max_iterations", f"Expected __end__, got {result}")
        return
    results.add_pass("test_router_max_iterations")


def test_router_terminal_status():
    for status in ["success", "failed", "wait_for_human"]:
        state = build_initial_state("test", ["192.168.1.0/24"], "test-001")
        state["mission_status"] = status
        state["next_agent"] = "scout"
        result = route_next_agent(state)
        if result != "__end__":
            results.add_fail("test_router_terminal_status", f"Status {status}: expected __end__, got {result}")
            return
    results.add_pass("test_router_terminal_status")


def test_router_invalid_agent():
    state = build_initial_state("test", ["192.168.1.0/24"], "test-001")
    state["next_agent"] = "nonexistent_agent"
    result = route_next_agent(state)
    if result != "__end__":
        results.add_fail("test_router_invalid_agent", f"Expected __end__, got {result}")
        return
    results.add_pass("test_router_invalid_agent")


def test_router_valid_agents():
    for agent in VALID_AGENTS:
        state = build_initial_state("test", ["192.168.1.0/24"], "test-001")
        state["next_agent"] = agent
        result = route_next_agent(state)
        if result != agent:
            results.add_fail("test_router_valid_agents", f"Agent {agent}: expected {agent}, got {result}")
            return
    results.add_pass("test_router_valid_agents")


def test_router_end_request():
    state = build_initial_state("test", ["192.168.1.0/24"], "test-001")
    state["next_agent"] = "end"
    result = route_next_agent(state)
    if result != "__end__":
        results.add_fail("test_router_end_request", f"Expected __end__, got {result}")
        return
    results.add_pass("test_router_end_request")


# ═══════════════════════════════════════════════════════════════
# TEST: Scout → Striker state propagation
# ═══════════════════════════════════════════════════════════════

async def test_scout_output_feeds_striker():
    """Verify Scout's discovered_targets output is consumed by Striker's context builder."""
    patches = PatchContext()
    try:
        nmap_tool = _make_tool("kali_nmap_scan")

        async def fake_nmap(**kwargs):
            return json.dumps({
                "output": (
                    "22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu\n"
                    "80/tcp   open  http    Apache httpd 2.4.41\n"
                    "3306/tcp open  mysql   MySQL 5.7.33\n"
                )
            })

        nmap_tool_patched = StructuredTool.from_function(
            func=lambda **kw: "{}",
            coroutine=fake_nmap,
            name="kali_nmap_scan",
            description="Mock nmap",
        )

        class NmapBridge:
            def get_tools_for_agent(self, allowed):
                return [nmap_tool_patched]

        async def fake_get_bridge():
            return NmapBridge()

        patches.set(scout_mod, "get_mcp_bridge", fake_get_bridge)

        initial = build_initial_state("Exploit target", ["192.168.1.0/24"], "test-002")
        initial["target_scope"] = ["192.168.1.50"]
        scout_output = await scout_mod.scout_node(initial)

        targets = scout_output.get("discovered_targets", {})
        if "192.168.1.50" not in targets:
            results.add_fail("test_scout_feeds_striker", f"Scout did not discover target: {targets.keys()}")
            return

        target_data = targets["192.168.1.50"]
        services = target_data.get("services", {})
        if not services:
            results.add_fail("test_scout_feeds_striker", "Scout discovered no services")
            return

        merged_state = {**initial, **scout_output}
        ctx = striker_mod._build_striker_context(merged_state)
        if "192.168.1.50" not in ctx:
            results.add_fail("test_scout_feeds_striker", "Target IP not in Striker context")
            return
        if "ssh" not in ctx.lower():
            results.add_fail("test_scout_feeds_striker", "SSH service not in Striker context")
            return

        results.add_pass("test_scout_feeds_striker")
    except Exception as e:
        traceback.print_exc()
        results.add_fail("test_scout_feeds_striker", str(e))
    finally:
        patches.restore()


# ═══════════════════════════════════════════════════════════════
# TEST: Striker → Resident state propagation
# ═══════════════════════════════════════════════════════════════

async def test_striker_output_feeds_resident():
    """Verify Striker session output feeds into Resident context."""
    patches = PatchContext()
    try:
        msf_tools = [
            _make_tool("msf_list_exploits"),
            _make_tool("msf_get_module_options"),
            _make_tool("msf_list_payloads"),
            _make_tool("msf_run_exploit"),
            _make_tool("msf_run_auxiliary_module"),
            _make_tool("msf_list_active_sessions"),
        ]

        async def fake_get_bridge():
            return MockBridge(msf_tools)

        def fake_build_llm():
            return object()

        def fake_create_react_agent_striker(model, tools, **kwargs):
            class FakeAgent:
                async def ainvoke(self, payload):
                    return {
                        "messages": [
                            ToolMessage(
                                tool_call_id="call-1",
                                name="msf_run_auxiliary_module",
                                content=json.dumps({
                                    "status": "success",
                                    "module": "auxiliary/scanner/ssh/ssh_login",
                                    "session_id": 3,
                                    "options": {"RHOSTS": "192.168.1.50"},
                                }),
                            ),
                        ]
                    }
            return FakeAgent()

        patches.set(striker_mod, "get_mcp_bridge", fake_get_bridge)
        patches.set(striker_mod, "_build_llm", fake_build_llm)
        patches.set(striker_mod, "create_react_agent", fake_create_react_agent_striker)
        patches.set(striker_mod, "STRIKER_REQUIRE_CONFIRMATION", False)

        pre_state = build_initial_state("Exploit target", ["192.168.1.0/24"], "test-003")
        pre_state["discovered_targets"] = {
            "192.168.1.50": {
                "ip_address": "192.168.1.50",
                "os_guess": "Linux",
                "services": {"22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"}},
            }
        }

        striker_output = await striker_mod.striker_node(pre_state)

        sessions = striker_output.get("active_sessions", {})
        if "192.168.1.50" not in sessions:
            results.add_fail("test_striker_feeds_resident", f"No session for target: {sessions}")
            return

        session_info = sessions["192.168.1.50"]
        if session_info.get("session_id") != 3:
            results.add_fail("test_striker_feeds_resident", f"Expected session_id=3: {session_info}")
            return

        merged = {**pre_state, **striker_output}
        resident_ctx = resident_mod._build_resident_context(merged)
        if "session_id=3" not in resident_ctx:
            results.add_fail("test_striker_feeds_resident", "Session not in Resident context")
            return
        if "192.168.1.50" not in resident_ctx:
            results.add_fail("test_striker_feeds_resident", "Target IP not in Resident context")
            return

        results.add_pass("test_striker_feeds_resident")
    except Exception as e:
        traceback.print_exc()
        results.add_fail("test_striker_feeds_resident", str(e))
    finally:
        patches.restore()


# ═══════════════════════════════════════════════════════════════
# TEST: Full pipeline (Scout → Striker → Resident)
# ═══════════════════════════════════════════════════════════════

async def test_full_pipeline_state_propagation():
    """End-to-end: scout discovers → striker exploits → resident enumerates."""
    patches = PatchContext()
    try:
        # Mock Scout's MCP bridge
        async def fake_nmap(**kwargs):
            return json.dumps({
                "output": "22/tcp open ssh OpenSSH 8.2p1 Ubuntu\n80/tcp open http Apache 2.4.41\n"
            })

        nmap_tool = StructuredTool.from_function(
            func=lambda **kw: "{}",
            coroutine=fake_nmap,
            name="kali_nmap_scan",
            description="Mock nmap",
        )

        class ScoutBridge:
            def get_tools_for_agent(self, allowed):
                return [nmap_tool]

        # Mock Striker's full chain
        msf_tools = [
            _make_tool("msf_list_exploits"),
            _make_tool("msf_get_module_options"),
            _make_tool("msf_list_payloads"),
            _make_tool("msf_run_exploit"),
            _make_tool("msf_run_auxiliary_module"),
            _make_tool("msf_list_active_sessions"),
        ]

        class StrikerBridge:
            def get_tools_for_agent(self, allowed):
                return msf_tools

        # Mock Resident's tools
        resident_tools = [
            _make_tool("msf_list_active_sessions"),
            _make_tool("msf_send_session_command"),
            _make_tool("msf_run_post_module"),
            _make_tool("msf_list_exploits"),
            _make_tool("msf_terminate_session"),
        ]

        class ResidentBridge:
            def get_tools_for_agent(self, allowed):
                return resident_tools

        # Phase tracking
        phase = {"current": "scout"}

        async def phased_bridge():
            if phase["current"] == "scout":
                return ScoutBridge()
            if phase["current"] == "striker":
                return StrikerBridge()
            return ResidentBridge()

        def fake_build_llm():
            return object()

        def fake_create_react_striker(model, tools, **kwargs):
            class FakeAgent:
                async def ainvoke(self, payload):
                    return {
                        "messages": [
                            ToolMessage(
                                tool_call_id="c1",
                                name="msf_run_auxiliary_module",
                                content=json.dumps({
                                    "status": "success",
                                    "module": "auxiliary/scanner/ssh/ssh_login",
                                    "session_id": 5,
                                    "options": {"RHOSTS": "10.0.0.1"},
                                }),
                            ),
                        ]
                    }
            return FakeAgent()

        def fake_create_react_resident(model, tools, **kwargs):
            class FakeAgent:
                async def ainvoke(self, payload):
                    return {
                        "messages": [
                            ToolMessage(
                                tool_call_id="c1",
                                name="msf_send_session_command",
                                content=json.dumps({
                                    "output": "uid=0(root) gid=0(root)",
                                    "status": "success",
                                }),
                            ),
                            ToolMessage(
                                tool_call_id="c2",
                                name="msf_run_post_module",
                                content=json.dumps({
                                    "status": "success",
                                    "module": "post/linux/gather/enum_system",
                                    "module_output": "Linux box 5.4.0-91-generic",
                                }),
                            ),
                        ]
                    }
            return FakeAgent()

        # --- Phase 1: Scout ---
        phase["current"] = "scout"
        patches.set(scout_mod, "get_mcp_bridge", phased_bridge)

        state = build_initial_state("Full pipeline test", ["10.0.0.0/24"], "test-pipeline-001")
        state["target_scope"] = ["10.0.0.1"]
        scout_out = await scout_mod.scout_node(state)
        state = {**state, **scout_out}

        if "10.0.0.1" not in state.get("discovered_targets", {}):
            results.add_fail("test_full_pipeline", "Scout did not discover target")
            return

        # --- Phase 2: Striker ---
        phase["current"] = "striker"
        patches.set(striker_mod, "get_mcp_bridge", phased_bridge)
        patches.set(striker_mod, "_build_llm", fake_build_llm)
        patches.set(striker_mod, "create_react_agent", fake_create_react_striker)
        patches.set(striker_mod, "STRIKER_REQUIRE_CONFIRMATION", False)

        striker_out = await striker_mod.striker_node(state)
        state = {**state, **striker_out}

        sessions = state.get("active_sessions", {})
        if "10.0.0.1" not in sessions:
            results.add_fail("test_full_pipeline", f"Striker did not open session: {sessions}")
            return
        if sessions["10.0.0.1"].get("session_id") != 5:
            results.add_fail("test_full_pipeline", f"Wrong session_id: {sessions}")
            return

        # --- Phase 3: Resident ---
        phase["current"] = "resident"
        patches.set(resident_mod, "get_mcp_bridge", phased_bridge)
        patches.set(resident_mod, "_build_llm", fake_build_llm)
        patches.set(resident_mod, "create_react_agent", fake_create_react_resident)

        resident_out = await resident_mod.resident_node(state)
        state = {**state, **resident_out}

        enriched_session = state.get("active_sessions", {}).get("10.0.0.1", {})
        if enriched_session.get("privilege") != "root":
            results.add_fail("test_full_pipeline", f"Resident did not detect root: {enriched_session}")
            return

        findings = state.get("critical_findings", [])
        if len(findings) < 2:
            results.add_fail("test_full_pipeline", f"Expected >=2 critical findings: {findings}")
            return

        if not enriched_session.get("post_exploitation_at"):
            results.add_fail("test_full_pipeline", "Missing post_exploitation_at")
            return

        results.add_pass("test_full_pipeline")
    except Exception as e:
        traceback.print_exc()
        results.add_fail("test_full_pipeline", str(e))
    finally:
        patches.restore()


# ═══════════════════════════════════════════════════════════════
# TEST: State merge semantics
# ═══════════════════════════════════════════════════════════════

def test_cyberstate_list_merge():
    """CyberState annotated lists should append, not overwrite."""
    from src.state.cyber_state import _merge_lists
    left = [{"a": 1}]
    right = [{"b": 2}]
    merged = _merge_lists(left, right)
    if len(merged) != 2:
        results.add_fail("test_list_merge", f"Expected 2 items, got {len(merged)}")
        return
    results.add_pass("test_list_merge")


def test_cyberstate_dict_merge():
    """CyberState annotated dicts should merge keys."""
    from src.state.cyber_state import _merge_dicts
    left = {"a": {"x": 1}}
    right = {"b": {"y": 2}}
    merged = _merge_dicts(left, right)
    if "a" not in merged or "b" not in merged:
        results.add_fail("test_dict_merge", f"Expected both keys: {merged}")
        return
    results.add_pass("test_dict_merge")


def test_cyberstate_dict_merge_overwrite():
    """Later dict values overwrite earlier ones for same key."""
    from src.state.cyber_state import _merge_dicts
    left = {"target": {"privilege": "user"}}
    right = {"target": {"privilege": "root", "os": "linux"}}
    merged = _merge_dicts(left, right)
    if merged["target"]["privilege"] != "root":
        results.add_fail("test_dict_merge_overwrite", f"Expected root: {merged}")
        return
    results.add_pass("test_dict_merge_overwrite")


# ═══════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════

async def main():
    print("=" * 60)
    print("Workflow Integration Test Suite")
    print("=" * 60)

    # Initial state
    test_build_initial_state()

    # Router tests
    test_router_max_iterations()
    test_router_terminal_status()
    test_router_invalid_agent()
    test_router_valid_agents()
    test_router_end_request()

    # State propagation
    await test_scout_output_feeds_striker()
    await test_striker_output_feeds_resident()
    await test_full_pipeline_state_propagation()

    # Merge semantics
    test_cyberstate_list_merge()
    test_cyberstate_dict_merge()
    test_cyberstate_dict_merge_overwrite()

    ok = results.summary()
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
