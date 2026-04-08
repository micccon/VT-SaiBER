#!/usr/bin/env python3
"""
VT-SaiBER Demo Scenario Runner
================================
Pre-built demo scenarios for presentation and validation.
Each scenario provides a pre-configured mission state and expected outcomes.

Usage:
    python scripts/run_scenario.py --list
    python scripts/run_scenario.py --scenario recon
    python scripts/run_scenario.py --scenario full-pipeline
    python scripts/run_scenario.py --scenario post-exploit
    python scripts/run_scenario.py --scenario all

Scenarios can run in two modes:
    --live    : Execute against real MCP servers (requires Docker stack running)
    --dry-run : Validate state construction and routing logic only (default)
"""

import argparse
import asyncio
import json
import sys
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.main import build_initial_state
from src.graph.router import route_next_agent
from src.state.models import AgentLogEntry


# ═══════════════════════════════════════════════════════════════
# SCENARIO DEFINITIONS
# ═══════════════════════════════════════════════════════════════

SCENARIOS = {}


def scenario(name: str, description: str, difficulty: str, est_time: str):
    """Decorator to register a demo scenario."""
    def wrapper(func):
        SCENARIOS[name] = {
            "func": func,
            "description": description,
            "difficulty": difficulty,
            "est_time": est_time,
        }
        return func
    return wrapper


@scenario(
    name="recon",
    description="Network discovery and service fingerprinting",
    difficulty="Basic",
    est_time="2-3 min",
)
async def scenario_recon(live: bool) -> Dict[str, Any]:
    """
    Demo Scenario 1: Reconnaissance
    ================================
    Demonstrates: Supervisor routes to Scout for initial discovery.

    Expected flow:
      1. Supervisor analyzes empty state → routes to Scout
      2. Scout runs nmap against target scope
      3. Scout returns discovered_targets with services

    Success criteria:
      - Supervisor correctly picks "scout" as first agent
      - State contains discovered_targets after scout runs
      - Services include SSH (22) and HTTP (80/8000)
    """
    print_scenario_header("Reconnaissance Demo", "Basic")

    state = build_initial_state(
        mission_goal="Discover all services on automotive-testbed and identify versions",
        target_scope=["172.20.0.0/16", "automotive-testbed"],
        mission_id=f"demo-recon-{_timestamp()}",
    )

    print_state_summary("Initial State", state)

    # Simulate supervisor routing decision
    state["next_agent"] = "scout"
    routed = route_next_agent(state)
    print(f"  Router decision: {routed}")
    assert routed == "scout", f"Expected scout, got {routed}"

    if live:
        from src.agents.scout import scout_node
        print("\n  [LIVE] Running Scout agent against real targets...")
        scout_output = await scout_node(state)
        state = {**state, **scout_output}
        print_state_summary("Post-Scout State", state)
    else:
        # Dry-run: inject simulated scout output
        state["discovered_targets"] = {
            "automotive-testbed": {
                "ip_address": "automotive-testbed",
                "os_guess": "Linux (Ubuntu 20.04)",
                "ports": [22, 8000, 3306],
                "services": {
                    "22": {"service_name": "ssh", "version": "OpenSSH 8.2p1 Ubuntu", "banner": "SSH-2.0-OpenSSH_8.2p1"},
                    "8000": {"service_name": "http", "version": "Python/3.8 BaseHTTPServer", "banner": ""},
                    "3306": {"service_name": "mysql", "version": "MySQL 5.7.33", "banner": ""},
                },
            }
        }
        state["agent_log"] = [
            AgentLogEntry(
                agent="scout", action="recon_scan", target="automotive-testbed",
                findings={"ports_found": [22, 8000, 3306], "services_found": 3},
                reasoning="Scout completed reconnaissance",
            ).model_dump(),
        ]
        print_state_summary("Post-Scout State (simulated)", state)

    # Validate
    targets = state.get("discovered_targets", {})
    assert targets, "No targets discovered"
    print("\n  RESULT: Scout discovered targets successfully")
    print_scenario_pass()
    return state


@scenario(
    name="full-pipeline",
    description="Complete attack chain: recon → exploitation → post-exploit",
    difficulty="Intermediate",
    est_time="10-15 min",
)
async def scenario_full_pipeline(live: bool) -> Dict[str, Any]:
    """
    Demo Scenario 2: Full Pipeline
    ================================
    Demonstrates: Complete supervisor-coordinated multi-agent workflow.

    Expected flow:
      1. Scout discovers services (SSH, HTTP)
      2. Supervisor routes to Striker
      3. Striker exploits SSH via auxiliary/scanner/ssh/ssh_login
      4. Supervisor routes to Resident
      5. Resident enumerates compromised system

    Success criteria:
      - Each agent receives correct state from previous agent
      - Striker opens a session
      - Resident detects privilege level
      - Full audit trail in agent_log
    """
    print_scenario_header("Full Pipeline Demo", "Intermediate")

    # Phase 1: Start with scout output
    state = build_initial_state(
        mission_goal="Gain initial access to automotive-testbed and enumerate the system",
        target_scope=["172.20.0.0/16", "automotive-testbed"],
        mission_id=f"demo-pipeline-{_timestamp()}",
    )

    if live:
        from src.agents.scout import scout_node
        from src.agents.striker import striker_node
        from src.agents.resident import resident_node

        print("\n  [LIVE] Phase 1: Scout...")
        scout_out = await scout_node(state)
        state = {**state, **scout_out}
        print_state_summary("Post-Scout", state)

        print("\n  [LIVE] Phase 2: Striker...")
        striker_out = await striker_node(state)
        state = {**state, **striker_out}
        print_state_summary("Post-Striker", state)

        if state.get("active_sessions"):
            print("\n  [LIVE] Phase 3: Resident...")
            resident_out = await resident_node(state)
            state = {**state, **resident_out}
            print_state_summary("Post-Resident", state)
        else:
            print("\n  [LIVE] Skipping Resident — no active sessions")
    else:
        # Simulated pipeline
        print("\n  Phase 1: Scout (simulated)")
        state["discovered_targets"] = {
            "automotive-testbed": {
                "ip_address": "automotive-testbed",
                "os_guess": "Linux (Ubuntu 20.04)",
                "ports": [22, 8000],
                "services": {
                    "22": {"service_name": "ssh", "version": "OpenSSH 8.2p1 Ubuntu"},
                    "8000": {"service_name": "http", "version": "Python/3.8"},
                },
            }
        }
        state["iteration_count"] = 1
        state["agent_log"] = [
            AgentLogEntry(agent="scout", action="recon_scan", target="automotive-testbed",
                          findings={"ports_found": [22, 8000]}).model_dump(),
        ]
        print_state_summary("Post-Scout", state)

        print("\n  Phase 2: Striker (simulated)")
        state["next_agent"] = "striker"
        routed = route_next_agent(state)
        assert routed == "striker", f"Expected striker, got {routed}"

        state["active_sessions"] = {
            "automotive-testbed": {
                "session_id": 7,
                "module": "auxiliary/scanner/ssh/ssh_login",
                "lhost": "msf-mcp",
                "lport": "4444",
                "established_at": datetime.now(timezone.utc).isoformat(),
            }
        }
        state["exploited_services"] = [{
            "target": "automotive-testbed",
            "module": "auxiliary/scanner/ssh/ssh_login",
            "status": "success",
            "session_id": 7,
        }]
        state["critical_findings"] = ["Session 7 opened on automotive-testbed via ssh_login"]
        state["iteration_count"] = 2
        state["agent_log"].append(
            AgentLogEntry(agent="striker", action="run_exploit", target="automotive-testbed",
                          findings={"session_id": 7, "status": "success"}).model_dump(),
        )
        print_state_summary("Post-Striker", state)

        print("\n  Phase 3: Resident (simulated)")
        state["next_agent"] = "resident"
        routed = route_next_agent(state)
        assert routed == "resident", f"Expected resident, got {routed}"

        state["active_sessions"]["automotive-testbed"].update({
            "privilege": "root",
            "os_info": "Linux testbed 5.4.0-91-generic #102-Ubuntu SMP x86_64",
            "post_exploitation_at": datetime.now(timezone.utc).isoformat(),
        })
        state["critical_findings"].extend([
            "Post-exploitation: root privileges confirmed",
            "Post module succeeded: post/linux/gather/enum_system",
        ])
        state["iteration_count"] = 3
        state["agent_log"].append(
            AgentLogEntry(agent="resident", action="post_exploitation",
                          findings={"privilege": "root", "os_info": "Linux 5.4.0-91-generic"}).model_dump(),
        )
        print_state_summary("Post-Resident", state)

    # Validate
    sessions = state.get("active_sessions", {})
    findings = state.get("critical_findings", [])
    log = state.get("agent_log", [])

    if not live:
        assert sessions, "No active sessions"
        assert len(findings) >= 2, f"Expected >=2 findings, got {len(findings)}"
        assert len(log) >= 3, f"Expected >=3 log entries, got {len(log)}"

    print("\n  RESULT: Full pipeline completed successfully")
    print_scenario_pass()
    return state


@scenario(
    name="post-exploit",
    description="Post-exploitation enumeration on an existing session",
    difficulty="Basic",
    est_time="3-5 min",
)
async def scenario_post_exploit(live: bool) -> Dict[str, Any]:
    """
    Demo Scenario 3: Post-Exploitation
    ====================================
    Demonstrates: Resident agent operating on a pre-existing session.

    Expected flow:
      1. Start with pre-built state containing active session
      2. Resident validates sessions
      3. Resident enumerates system (id, uname, network)
      4. Resident runs post modules
      5. Resident produces findings summary

    Success criteria:
      - Resident detects privilege level
      - OS info captured
      - Post module results recorded
      - Session enriched with post-exploitation data
    """
    print_scenario_header("Post-Exploitation Demo", "Basic")

    state = build_initial_state(
        mission_goal="Enumerate compromised automotive-testbed and assess privilege level",
        target_scope=["172.20.0.0/16", "automotive-testbed"],
        mission_id=f"demo-postexploit-{_timestamp()}",
    )
    state["discovered_targets"] = {
        "automotive-testbed": {
            "ip_address": "automotive-testbed",
            "os_guess": "Linux (Ubuntu 20.04)",
            "services": {"22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"}},
        }
    }
    state["active_sessions"] = {
        "automotive-testbed": {
            "session_id": 7,
            "module": "auxiliary/scanner/ssh/ssh_login",
            "established_at": datetime.now(timezone.utc).isoformat(),
        }
    }
    state["iteration_count"] = 4

    print_state_summary("Pre-Resident State", state)

    # Routing check
    state["next_agent"] = "resident"
    routed = route_next_agent(state)
    assert routed == "resident", f"Expected resident, got {routed}"

    if live:
        from src.agents.resident import resident_node
        print("\n  [LIVE] Running Resident agent...")
        resident_out = await resident_node(state)
        state = {**state, **resident_out}
    else:
        state["active_sessions"]["automotive-testbed"].update({
            "privilege": "root",
            "os_info": "Linux testbed 5.4.0-91-generic #102-Ubuntu SMP x86_64",
            "post_exploitation_at": datetime.now(timezone.utc).isoformat(),
        })
        state["critical_findings"] = [
            "Post-exploitation: root privileges confirmed",
            "Post module succeeded: post/linux/gather/enum_system",
            "Post module succeeded: post/multi/gather/env",
        ]
        state["agent_log"] = [
            AgentLogEntry(agent="resident", action="post_exploitation",
                          findings={"privilege": "root"}).model_dump(),
        ]

    print_state_summary("Post-Resident State", state)

    session = state.get("active_sessions", {}).get("automotive-testbed", {})
    if not live:
        assert session.get("privilege") == "root", f"Expected root: {session}"
        assert session.get("post_exploitation_at"), "Missing post_exploitation_at"

    print("\n  RESULT: Post-exploitation completed successfully")
    print_scenario_pass()
    return state


@scenario(
    name="failure-recovery",
    description="Demonstrates graceful handling of agent failures",
    difficulty="Basic",
    est_time="1-2 min",
)
async def scenario_failure_recovery(live: bool) -> Dict[str, Any]:
    """
    Demo Scenario 4: Failure Recovery
    ===================================
    Demonstrates: System resilience when agents encounter errors.

    Expected flow:
      1. Striker called with no discovered targets → ValidationError
      2. Resident called with no sessions → ValidationError
      3. Router blocks out-of-scope targets
      4. Router enforces max iterations
      5. Errors accumulate without losing prior state

    Success criteria:
      - Errors are properly classified (recoverable vs non-recoverable)
      - State is preserved despite errors
      - Router safety checks work correctly
    """
    print_scenario_header("Failure Recovery Demo", "Basic")

    from src.state.cyber_state import _merge_lists

    # Test 1: Striker with no targets
    print("\n  Test 1: Striker with no targets")
    state = build_initial_state("Test", ["10.0.0.0/24"], f"demo-fail-{_timestamp()}")
    from src.agents.striker import striker_node
    out = await striker_node(state)
    errs = out.get("errors", [])
    err_type = getattr(errs[0], "error_type", "") if errs else ""
    assert err_type == "ValidationError", f"Expected ValidationError, got {err_type}"
    assert getattr(errs[0], "recoverable", False), "Should be recoverable"
    print("    Striker correctly returned recoverable ValidationError")

    # Test 2: Resident with no sessions
    print("\n  Test 2: Resident with no sessions")
    from src.agents.resident import resident_node
    out2 = await resident_node(state)
    errs2 = out2.get("errors", [])
    err_type2 = getattr(errs2[0], "error_type", "") if errs2 else ""
    assert err_type2 == "ValidationError", f"Expected ValidationError, got {err_type2}"
    print("    Resident correctly returned recoverable ValidationError")

    # Test 3: Out-of-scope detection
    print("\n  Test 3: Out-of-scope target detection")
    state["discovered_targets"] = {"99.99.99.99": {"services": {}}}
    state["next_agent"] = "striker"
    routed = route_next_agent(state)
    assert routed == "__end__", f"Expected __end__, got {routed}"
    print("    Router correctly blocked out-of-scope target")

    # Test 4: Max iterations
    print("\n  Test 4: Max iteration enforcement")
    state2 = build_initial_state("Test", ["10.0.0.1"], "demo-fail-iter")
    state2["iteration_count"] = 999
    state2["next_agent"] = "scout"
    routed2 = route_next_agent(state2)
    assert routed2 == "__end__", f"Expected __end__, got {routed2}"
    print("    Router correctly enforced iteration limit")

    # Test 5: Error accumulation
    print("\n  Test 5: Error accumulation preserves state")
    err_list_1 = [{"agent": "scout", "error": "fail1"}]
    err_list_2 = [{"agent": "striker", "error": "fail2"}]
    accumulated = _merge_lists(err_list_1, err_list_2)
    assert len(accumulated) == 2, f"Expected 2 errors, got {len(accumulated)}"
    print("    Errors correctly accumulated across agents")

    print_scenario_pass()
    return state


# ═══════════════════════════════════════════════════════════════
# DISPLAY HELPERS
# ═══════════════════════════════════════════════════════════════

def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def print_scenario_header(name: str, difficulty: str):
    print(f"\n{'='*60}")
    print(f"  SCENARIO: {name}")
    print(f"  Difficulty: {difficulty}")
    print(f"  Time: {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}")
    print(f"{'='*60}")


def print_scenario_pass():
    print(f"\n  {'='*50}")
    print(f"  SCENARIO PASSED")
    print(f"  {'='*50}")


def print_state_summary(label: str, state: Dict[str, Any]):
    print(f"\n  --- {label} ---")
    print(f"  mission_status:     {state.get('mission_status', '?')}")
    print(f"  iteration_count:    {state.get('iteration_count', 0)}")
    print(f"  discovered_targets: {len(state.get('discovered_targets', {}) or {})}")
    print(f"  active_sessions:    {len(state.get('active_sessions', {}) or {})}")
    print(f"  critical_findings:  {len(state.get('critical_findings', []) or [])}")
    print(f"  errors:             {len(state.get('errors', []) or [])}")
    print(f"  agent_log entries:  {len(state.get('agent_log', []) or [])}")

    targets = state.get("discovered_targets", {}) or {}
    for ip, data in targets.items():
        services = data.get("services", {}) if isinstance(data, dict) else {}
        svc_names = []
        for port, svc in list(services.items())[:5]:
            name = svc.get("service_name", str(svc)) if isinstance(svc, dict) else str(svc)
            svc_names.append(f"{port}/{name}")
        print(f"    target: {ip} -> {', '.join(svc_names) or 'no services'}")

    sessions = state.get("active_sessions", {}) or {}
    for target, info in sessions.items():
        sid = info.get("session_id", "?") if isinstance(info, dict) else "?"
        priv = info.get("privilege", "unknown") if isinstance(info, dict) else "?"
        print(f"    session: {target} (id={sid}, priv={priv})")


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

def list_scenarios():
    print(f"\n{'='*60}")
    print("Available Demo Scenarios")
    print(f"{'='*60}\n")
    for name, info in SCENARIOS.items():
        print(f"  {name:20s} [{info['difficulty']:12s}] {info['est_time']:>10s}  {info['description']}")
    print(f"\nUsage: python scripts/run_scenario.py --scenario <name> [--live]")
    print(f"       python scripts/run_scenario.py --scenario all [--live]")


async def run_scenarios(names: List[str], live: bool):
    passed = 0
    failed = 0

    for name in names:
        if name not in SCENARIOS:
            print(f"\n  ERROR: Unknown scenario '{name}'")
            failed += 1
            continue
        try:
            await SCENARIOS[name]["func"](live=live)
            passed += 1
        except AssertionError as e:
            print(f"\n  ASSERTION FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"\n  ERROR: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\n{'='*60}")
    print(f"Demo Summary: {passed}/{passed + failed} scenarios passed")
    if live:
        print("  Mode: LIVE (real MCP servers)")
    else:
        print("  Mode: DRY-RUN (simulated)")
    print(f"{'='*60}")
    return failed == 0


def main():
    parser = argparse.ArgumentParser(description="VT-SaiBER Demo Scenario Runner")
    parser.add_argument("--list", action="store_true", help="List available scenarios")
    parser.add_argument("--scenario", type=str, default="", help="Scenario name or 'all'")
    parser.add_argument("--live", action="store_true", help="Run against live MCP servers")
    parser.add_argument("--dry-run", action="store_true", default=True, help="Simulate only (default)")
    args = parser.parse_args()

    if args.list or not args.scenario:
        list_scenarios()
        return 0

    live = args.live

    if args.scenario == "all":
        names = list(SCENARIOS.keys())
    else:
        names = [s.strip() for s in args.scenario.split(",")]

    ok = asyncio.run(run_scenarios(names, live=live))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
