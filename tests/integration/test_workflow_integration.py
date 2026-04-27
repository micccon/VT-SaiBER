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
from types import SimpleNamespace

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


def _make_msf_search_tool(results_by_term: dict[str, list[str]]) -> StructuredTool:
    async def _async_tool(**kwargs):
        term = str(kwargs.get("search_term", "") or "").strip().lower()
        return results_by_term.get(term, [])

    return StructuredTool.from_function(
        func=lambda **kwargs: results_by_term.get(str(kwargs.get("search_term", "") or "").strip().lower(), []),
        coroutine=_async_tool,
        name="msf_search_modules",
        description="Mock Metasploit search",
    )


def _make_msf_options_tool(results_by_module: dict[tuple[str, str], dict[str, object]]) -> StructuredTool:
    async def _async_tool(**kwargs):
        key = (
            str(kwargs.get("module_type", "") or ""),
            str(kwargs.get("module_name", "") or ""),
        )
        return results_by_module[key]

    return StructuredTool.from_function(
        func=lambda **kwargs: results_by_module[
            (
                str(kwargs.get("module_type", "") or ""),
                str(kwargs.get("module_name", "") or ""),
            )
        ],
        coroutine=_async_tool,
        name="msf_get_module_options",
        description="Mock Metasploit option lookup",
    )


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
        async def fake_probe(**kwargs):
            return json.dumps({
                "status": "success",
                "evidence": {
                    "services": [
                        {"port": 22, "protocol": "tcp", "service_name": "ssh", "version": "OpenSSH 8.2p1 Ubuntu"},
                        {"port": 80, "protocol": "tcp", "service_name": "http", "version": "Apache httpd 2.4.41"},
                        {"port": 3306, "protocol": "tcp", "service_name": "mysql", "version": "MySQL 5.7.33"},
                    ]
                },
            })

        probe_tool = StructuredTool.from_function(
            func=lambda **kw: "{}",
            coroutine=fake_probe,
            name="recon_service_probe",
            description="Mock service probe",
        )

        async def fake_load_filtered_tools(_allowed):
            return [probe_tool]

        patches.set(scout_mod, "load_filtered_tools", fake_load_filtered_tools)

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
        striker_context = striker_mod._build_striker_context(merged_state)
        if "192.168.1.50" not in striker_context:
            results.add_fail("test_scout_feeds_striker", "Target IP not in Striker context")
            return
        if "ssh" not in striker_context.lower():
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
            _make_msf_search_tool({"apache": ["exploit/multi/http/apache_demo"]}),
            _make_msf_options_tool(
                {
                    ("exploit", "multi/http/apache_demo"): {
                        "status": "success",
                        "options": [
                            {"name": "RHOSTS", "required": True},
                            {"name": "RPORT", "required": True},
                        ],
                    }
                }
            ),
            _make_tool("msf_get_module_info"),
            StructuredTool.from_function(
                func=lambda **kwargs: json.dumps(
                    {
                        "status": "success",
                        "module": "exploit/multi/http/apache_demo",
                        "session_id": 3,
                    }
                ),
                coroutine=lambda **kwargs: asyncio.sleep(
                    0,
                    result=json.dumps(
                        {
                            "status": "success",
                            "module": "exploit/multi/http/apache_demo",
                            "session_id": 3,
                        }
                    ),
                ),
                name="msf_run_exploit",
                description="Mock exploit execution",
            ),
            _make_tool("msf_run_auxiliary"),
            StructuredTool.from_function(
                func=lambda **kwargs: json.dumps(
                    {"status": "success", "sessions": {"3": {"target_host": "192.168.1.50"}}}
                ),
                coroutine=lambda **kwargs: asyncio.sleep(
                    0,
                    result=json.dumps(
                        {"status": "success", "sessions": {"3": {"target_host": "192.168.1.50"}}}
                    ),
                ),
                name="msf_list_sessions",
                description="Mock session listing",
            ),
        ]

        async def fake_load_filtered_tools(_allowed):
            return msf_tools

        async def fake_run_agent_tool_loop(**kwargs):
            return SimpleNamespace(
                messages=[
                    ToolMessage(
                        tool_call_id="c1",
                        name="msf_search_modules",
                        content=json.dumps(
                            {
                                "status": "success",
                                "result": ["exploit/multi/http/apache_demo"],
                                "invocation": {"search_term": "apache"},
                            }
                        ),
                    ),
                    ToolMessage(
                        tool_call_id="c2",
                        name="msf_get_module_options",
                        content=json.dumps(
                            {
                                "status": "success",
                                "options": [
                                    {"name": "RHOSTS", "required": True},
                                    {"name": "RPORT", "required": True},
                                ],
                                "invocation": {
                                    "module_type": "exploit",
                                    "module_name": "multi/http/apache_demo",
                                },
                            }
                        ),
                    ),
                    ToolMessage(
                        tool_call_id="c3",
                        name="msf_run_exploit",
                        content=json.dumps(
                            {
                                "status": "success",
                                "module": "exploit/multi/http/apache_demo",
                                "session_id": 3,
                                "invocation": {
                                    "module_name": "multi/http/apache_demo",
                                    "options": {"RHOSTS": "192.168.1.50", "RPORT": 80},
                                },
                            }
                        ),
                    ),
                    ToolMessage(
                        tool_call_id="c4",
                        name="msf_list_sessions",
                        content=json.dumps(
                            {
                                "status": "success",
                                "sessions": {"3": {"target_host": "192.168.1.50"}},
                            }
                        ),
                    ),
                ]
            )

        patches.set(striker_mod, "load_filtered_tools", fake_load_filtered_tools)
        patches.set(striker_mod, "run_agent_tool_loop", fake_run_agent_tool_loop)

        pre_state = build_initial_state("Exploit target", ["192.168.1.0/24"], "test-003")
        pre_state["discovered_targets"] = {
            "192.168.1.50": {
                "ip_address": "192.168.1.50",
                "os_guess": "Linux",
                "ports": [80],
                "services": {"80": {"service_name": "http", "version": "Apache 2.4.41"}},
            }
        }

        agent = striker_mod.StrikerAgent()
        agent.require_confirmation = False

        striker_output = await agent.call_llm(pre_state)

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
            name="recon_service_probe",
            description="Mock service probe",
        )

        # Mock Striker's full chain
        msf_tools = [
            _make_msf_search_tool({"apache": ["exploit/multi/http/apache_demo"]}),
            _make_msf_options_tool(
                {
                    ("exploit", "multi/http/apache_demo"): {
                        "status": "success",
                        "options": [
                            {"name": "RHOSTS", "required": True},
                            {"name": "RPORT", "required": True},
                        ],
                    }
                }
            ),
            _make_tool("msf_get_module_info"),
            StructuredTool.from_function(
                func=lambda **kwargs: json.dumps(
                    {
                        "status": "success",
                        "module": "exploit/multi/http/apache_demo",
                        "session_id": 5,
                    }
                ),
                coroutine=lambda **kwargs: asyncio.sleep(
                    0,
                    result=json.dumps(
                        {
                            "status": "success",
                            "module": "exploit/multi/http/apache_demo",
                            "session_id": 5,
                        }
                    ),
                ),
                name="msf_run_exploit",
                description="Mock exploit execution",
            ),
            _make_tool("msf_run_auxiliary"),
            StructuredTool.from_function(
                func=lambda **kwargs: json.dumps(
                    {"status": "success", "sessions": {"5": {"target_host": "10.0.0.1"}}}
                ),
                coroutine=lambda **kwargs: asyncio.sleep(
                    0,
                    result=json.dumps(
                        {"status": "success", "sessions": {"5": {"target_host": "10.0.0.1"}}}
                    ),
                ),
                name="msf_list_sessions",
                description="Mock session listing",
            ),
        ]

        # Mock Resident's tools
        resident_tools = [
            _make_tool("msf_list_sessions"),
            _make_tool("msf_session_command"),
            _make_tool("msf_run_post"),
            _make_tool("msf_search_modules"),
            _make_tool("msf_terminate_session"),
        ]

        # Phase tracking
        phase = {"current": "scout"}

        async def phased_tools(_allowed):
            if phase["current"] == "scout":
                return [nmap_tool]
            if phase["current"] == "striker":
                return msf_tools
            return resident_tools

        async def fake_run_striker_tool_loop(**kwargs):
            return SimpleNamespace(
                messages=[
                    ToolMessage(
                        tool_call_id="c1",
                        name="msf_search_modules",
                        content=json.dumps(
                            {
                                "status": "success",
                                "result": ["exploit/multi/http/apache_demo"],
                                "invocation": {"search_term": "apache"},
                            }
                        ),
                    ),
                    ToolMessage(
                        tool_call_id="c2",
                        name="msf_get_module_options",
                        content=json.dumps(
                            {
                                "status": "success",
                                "options": [
                                    {"name": "RHOSTS", "required": True},
                                    {"name": "RPORT", "required": True},
                                ],
                                "invocation": {
                                    "module_type": "exploit",
                                    "module_name": "multi/http/apache_demo",
                                },
                            }
                        ),
                    ),
                    ToolMessage(
                        tool_call_id="c3",
                        name="msf_run_exploit",
                        content=json.dumps(
                            {
                                "status": "success",
                                "module": "exploit/multi/http/apache_demo",
                                "session_id": 5,
                                "invocation": {
                                    "module_name": "multi/http/apache_demo",
                                    "options": {"RHOSTS": "10.0.0.1", "RPORT": 80},
                                },
                            }
                        ),
                    ),
                    ToolMessage(
                        tool_call_id="c4",
                        name="msf_list_sessions",
                        content=json.dumps(
                            {
                                "status": "success",
                                "sessions": {"5": {"target_host": "10.0.0.1"}},
                            }
                        ),
                    ),
                ]
            )

        def fake_resolve_openrouter_runtime(**kwargs):
            return SimpleNamespace(client=object(), model="test-model")

        async def fake_run_resident_tool_loop(**kwargs):
            return SimpleNamespace(
                messages=[
                    ToolMessage(
                        tool_call_id="c1",
                        name="msf_session_command",
                        content=json.dumps({
                            "output": "uid=0(root) gid=0(root)",
                            "status": "success",
                        }),
                    ),
                    ToolMessage(
                        tool_call_id="c2",
                        name="msf_run_post",
                        content=json.dumps({
                            "status": "success",
                            "module": "post/linux/gather/enum_system",
                            "module_output": "Linux box 5.4.0-91-generic",
                        }),
                    ),
                ]
            )

        # --- Phase 1: Scout ---
        phase["current"] = "scout"
        patches.set(scout_mod, "load_filtered_tools", phased_tools)

        state = build_initial_state("Full pipeline test", ["10.0.0.0/24"], "test-pipeline-001")
        state["target_scope"] = ["10.0.0.1"]
        scout_out = await scout_mod.scout_node(state)
        state = {**state, **scout_out}

        if "10.0.0.1" not in state.get("discovered_targets", {}):
            results.add_fail("test_full_pipeline", "Scout did not discover target")
            return

        # --- Phase 2: Striker ---
        phase["current"] = "striker"
        patches.set(striker_mod, "load_filtered_tools", phased_tools)
        patches.set(striker_mod, "run_agent_tool_loop", fake_run_striker_tool_loop)
        striker_agent = striker_mod.StrikerAgent()
        striker_agent.require_confirmation = False

        striker_out = await striker_agent.call_llm(state)
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
        patches.set(resident_mod, "load_filtered_tools", phased_tools)
        patches.set(resident_mod, "resolve_openrouter_runtime", fake_resolve_openrouter_runtime)
        patches.set(resident_mod, "run_agent_tool_loop", fake_run_resident_tool_loop)

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
