#!/usr/bin/env python3
"""
Session Persistence & Recovery Tests
=====================================
Tests checkpointing, resume, state reconstruction, and graceful fallbacks.

Run inside agents container:
    docker exec vt-saiber-agents python tests/integration/test_persistence_recovery.py
"""

import asyncio
import json
import os
import sys
import traceback

sys.path.insert(0, "/app")

from src.main import build_initial_state, build_arg_parser, maybe_checkpointer
from src.config import RuntimeConfig
from src.state.cyber_state import CyberState
from src.state.models import AgentError, AgentLogEntry, MissionStatus


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
        print(f"Persistence & Recovery Tests: {self.passed}/{total} passed")
        if self.errors:
            print("Failed:")
            for name, err in self.errors:
                print(f"  - {name}: {err}")
        print(f"{'='*60}")
        return self.failed == 0


results = Results()


# ═══════════════════════════════════════════════════════════════
# TEST: Initial state construction
# ═══════════════════════════════════════════════════════════════

def test_build_initial_state_defaults():
    state = build_initial_state("Test mission", ["10.0.0.0/24"], "mission-001")
    checks = {
        "current_agent": "supervisor",
        "mission_status": "active",
        "iteration_count": 0,
        "mission_goal": "Test mission",
        "mission_id": "mission-001",
    }
    for key, expected in checks.items():
        if state.get(key) != expected:
            results.add_fail("test_initial_state_defaults", f"{key}: expected {expected}, got {state.get(key)}")
            return

    empty_collections = ["discovered_targets", "active_sessions", "agent_log", "critical_findings", "errors"]
    for key in empty_collections:
        val = state.get(key)
        if val is None:
            results.add_fail("test_initial_state_defaults", f"{key} is None, expected empty collection")
            return
        if isinstance(val, (dict, list)) and len(val) != 0:
            results.add_fail("test_initial_state_defaults", f"{key} should be empty, has {len(val)} items")
            return

    results.add_pass("test_initial_state_defaults")


def test_build_initial_state_scope_preserved():
    scope = ["192.168.1.0/24", "10.0.0.0/8", "target-host"]
    state = build_initial_state("Mission", scope, "m-002")
    if state["target_scope"] != scope:
        results.add_fail("test_scope_preserved", f"Scope mismatch: {state['target_scope']}")
        return
    results.add_pass("test_scope_preserved")


# ═══════════════════════════════════════════════════════════════
# TEST: State serialization round-trip
# ═══════════════════════════════════════════════════════════════

def test_state_json_serializable():
    """CyberState must survive JSON round-trip for checkpoint persistence."""
    state = build_initial_state("Test", ["10.0.0.1"], "m-003")
    state["discovered_targets"] = {
        "10.0.0.1": {
            "ip_address": "10.0.0.1",
            "os_guess": "Linux",
            "services": {"22": {"service_name": "ssh", "version": "OpenSSH 8.2"}},
        }
    }
    state["active_sessions"] = {
        "10.0.0.1": {"session_id": 5, "module": "ssh_login", "established_at": "2025-01-01T00:00:00"},
    }
    state["agent_log"] = [
        AgentLogEntry(agent="scout", action="recon_scan", target="10.0.0.1").model_dump(),
    ]
    state["errors"] = [
        AgentError(agent="striker", error_type="ToolError", error="MCP down", recoverable=True).model_dump(),
    ]
    state["critical_findings"] = ["Session 5 opened on 10.0.0.1"]

    try:
        serialized = json.dumps(state, default=str)
        restored = json.loads(serialized)
    except Exception as e:
        results.add_fail("test_json_serializable", f"Serialization failed: {e}")
        return

    if restored["mission_goal"] != "Test":
        results.add_fail("test_json_serializable", "mission_goal lost")
        return
    if "10.0.0.1" not in restored["discovered_targets"]:
        results.add_fail("test_json_serializable", "discovered_targets lost")
        return
    if restored["active_sessions"]["10.0.0.1"]["session_id"] != 5:
        results.add_fail("test_json_serializable", "session_id lost")
        return
    if len(restored["agent_log"]) != 1:
        results.add_fail("test_json_serializable", "agent_log lost")
        return
    results.add_pass("test_json_serializable")


def test_state_reconstruction_from_checkpoint_data():
    """Simulate reconstructing state from checkpoint-like JSON."""
    checkpoint_json = json.dumps({
        "current_agent": "striker",
        "next_agent": "resident",
        "iteration_count": 5,
        "mission_status": "active",
        "mission_goal": "Exploit target",
        "target_scope": ["10.0.0.0/24"],
        "mission_id": "resumed-001",
        "discovered_targets": {
            "10.0.0.1": {"ip_address": "10.0.0.1", "os_guess": "Linux", "services": {}}
        },
        "ot_discovery": {},
        "web_findings": [],
        "active_sessions": {
            "10.0.0.1": {"session_id": 3, "module": "ssh_login"},
        },
        "exploited_services": [{"target": "10.0.0.1", "module": "ssh_login", "status": "success"}],
        "research_cache": {},
        "osint_findings": [],
        "supervisor_messages": [],
        "supervisor_expectations": {},
        "agent_log": [],
        "critical_findings": ["Session 3 opened"],
        "errors": [],
    })

    restored = json.loads(checkpoint_json)

    if restored["iteration_count"] != 5:
        results.add_fail("test_state_reconstruction", "iteration_count wrong")
        return
    if restored["next_agent"] != "resident":
        results.add_fail("test_state_reconstruction", "next_agent wrong")
        return
    if restored["active_sessions"]["10.0.0.1"]["session_id"] != 3:
        results.add_fail("test_state_reconstruction", "session_id wrong")
        return
    results.add_pass("test_state_reconstruction")


# ═══════════════════════════════════════════════════════════════
# TEST: Checkpointer graceful fallback
# ═══════════════════════════════════════════════════════════════

async def test_checkpointer_fallback_no_db_url():
    """When no database URL is configured, checkpointer should yield None."""
    import src.config as config_mod

    original = config_mod.get_runtime_config

    def mock_config():
        return RuntimeConfig(
            openrouter_api_key="test",
            openrouter_base_url="https://openrouter.ai/api/v1",
            supervisor_model="test-model",
            supervisor_timeout_seconds=30,
            supervisor_reasoning_enabled=False,
            supervisor_max_reasoning_messages=4,
            max_iterations=10,
            checkpoint_enabled=True,
            checkpoint_database_url=None,
            default_thread_prefix="test",
        )

    config_mod.get_runtime_config = mock_config
    try:
        async with maybe_checkpointer() as cp:
            if cp is not None:
                results.add_fail("test_checkpointer_no_db", f"Expected None, got {type(cp)}")
                return
        results.add_pass("test_checkpointer_no_db")
    except Exception as e:
        results.add_fail("test_checkpointer_no_db", str(e))
    finally:
        config_mod.get_runtime_config = original


async def test_checkpointer_fallback_disabled():
    """When checkpointing is disabled, should yield None."""
    import src.config as config_mod

    original = config_mod.get_runtime_config

    def mock_config():
        return RuntimeConfig(
            openrouter_api_key="test",
            openrouter_base_url="https://openrouter.ai/api/v1",
            supervisor_model="test-model",
            supervisor_timeout_seconds=30,
            supervisor_reasoning_enabled=False,
            supervisor_max_reasoning_messages=4,
            max_iterations=10,
            checkpoint_enabled=False,
            checkpoint_database_url="postgresql://test:test@localhost/test",
            default_thread_prefix="test",
        )

    config_mod.get_runtime_config = mock_config
    try:
        async with maybe_checkpointer() as cp:
            if cp is not None:
                results.add_fail("test_checkpointer_disabled", f"Expected None, got {type(cp)}")
                return
        results.add_pass("test_checkpointer_disabled")
    except Exception as e:
        results.add_fail("test_checkpointer_disabled", str(e))
    finally:
        config_mod.get_runtime_config = original


async def test_checkpointer_fallback_bad_url():
    """When database URL is invalid, should fall back to None gracefully."""
    import src.config as config_mod

    original = config_mod.get_runtime_config

    def mock_config():
        return RuntimeConfig(
            openrouter_api_key="test",
            openrouter_base_url="https://openrouter.ai/api/v1",
            supervisor_model="test-model",
            supervisor_timeout_seconds=30,
            supervisor_reasoning_enabled=False,
            supervisor_max_reasoning_messages=4,
            max_iterations=10,
            checkpoint_enabled=True,
            checkpoint_database_url="postgresql://invalid:invalid@nonexistent-host:5432/noexist",
            default_thread_prefix="test",
        )

    config_mod.get_runtime_config = mock_config
    try:
        async with maybe_checkpointer() as cp:
            # Should either yield None or a saver (depends on lib availability)
            # The key is it should NOT raise an exception
            pass
        results.add_pass("test_checkpointer_bad_url")
    except Exception as e:
        results.add_fail("test_checkpointer_bad_url", f"Should not raise: {e}")
    finally:
        config_mod.get_runtime_config = original


# ═══════════════════════════════════════════════════════════════
# TEST: CLI argument parsing for resume
# ═══════════════════════════════════════════════════════════════

def test_arg_parser_resume_flag():
    parser = build_arg_parser()
    args = parser.parse_args(["--resume", "--thread-id", "mission-abc"])
    if not args.resume:
        results.add_fail("test_resume_flag", "Expected resume=True")
        return
    if args.thread_id != "mission-abc":
        results.add_fail("test_resume_flag", f"Expected thread_id=mission-abc, got {args.thread_id}")
        return
    results.add_pass("test_resume_flag")


def test_arg_parser_checkpoint_id():
    parser = build_arg_parser()
    args = parser.parse_args(["--resume", "--checkpoint-id", "cp-123"])
    if args.checkpoint_id != "cp-123":
        results.add_fail("test_checkpoint_id", f"Expected cp-123, got {args.checkpoint_id}")
        return
    results.add_pass("test_checkpoint_id")


def test_arg_parser_new_mission():
    parser = build_arg_parser()
    args = parser.parse_args([
        "--mission-goal", "Exploit target",
        "--target-scope", "10.0.0.0/24,192.168.1.0/24",
        "--mission-id", "m-new-001",
    ])
    if args.mission_goal != "Exploit target":
        results.add_fail("test_new_mission_args", f"goal: {args.mission_goal}")
        return
    if args.mission_id != "m-new-001":
        results.add_fail("test_new_mission_args", f"id: {args.mission_id}")
        return
    results.add_pass("test_new_mission_args")


# ═══════════════════════════════════════════════════════════════
# TEST: State continuity after agent errors
# ═══════════════════════════════════════════════════════════════

def test_error_state_preserves_prior_data():
    """When an agent returns an error, prior state data must survive merge."""
    from src.state.cyber_state import _merge_lists, _merge_dicts

    prior_state = build_initial_state("Test", ["10.0.0.1"], "m-004")
    prior_state["discovered_targets"] = {
        "10.0.0.1": {"ip_address": "10.0.0.1", "services": {"22": {"service_name": "ssh"}}}
    }
    prior_state["critical_findings"] = ["Scout found SSH on 10.0.0.1"]

    error_update = {
        "errors": [AgentError(
            agent="striker",
            error_type="ToolError",
            error="MCP bridge unavailable",
            recoverable=True,
        ).model_dump()],
        "iteration_count": prior_state["iteration_count"] + 1,
    }

    merged_errors = _merge_lists(prior_state.get("errors", []), error_update.get("errors", []))
    merged_findings = _merge_lists(prior_state.get("critical_findings", []), error_update.get("critical_findings", []))
    merged_targets = _merge_dicts(
        prior_state.get("discovered_targets", {}),
        error_update.get("discovered_targets", {}),
    )

    if len(merged_errors) != 1:
        results.add_fail("test_error_preserves_data", f"Expected 1 error, got {len(merged_errors)}")
        return
    if len(merged_findings) != 1:
        results.add_fail("test_error_preserves_data", f"Findings lost: {merged_findings}")
        return
    if "10.0.0.1" not in merged_targets:
        results.add_fail("test_error_preserves_data", "Targets lost after error")
        return
    results.add_pass("test_error_preserves_data")


def test_multiple_errors_accumulate():
    """Errors from multiple agents should accumulate, not overwrite."""
    from src.state.cyber_state import _merge_lists

    errors_round1 = [AgentError(agent="scout", error_type="ScopeError", error="bad", recoverable=True).model_dump()]
    errors_round2 = [AgentError(agent="striker", error_type="ToolError", error="down", recoverable=False).model_dump()]
    errors_round3 = [AgentError(agent="resident", error_type="ValidationError", error="no sessions", recoverable=True).model_dump()]

    accumulated = _merge_lists(errors_round1, errors_round2)
    accumulated = _merge_lists(accumulated, errors_round3)

    if len(accumulated) != 3:
        results.add_fail("test_errors_accumulate", f"Expected 3, got {len(accumulated)}")
        return

    agents = [e.get("agent") if isinstance(e, dict) else getattr(e, "agent", None) for e in accumulated]
    if agents != ["scout", "striker", "resident"]:
        results.add_fail("test_errors_accumulate", f"Wrong agents: {agents}")
        return
    results.add_pass("test_errors_accumulate")


# ═══════════════════════════════════════════════════════════════
# TEST: Mission status model
# ═══════════════════════════════════════════════════════════════

def test_mission_status_enum():
    expected = {"active", "success", "failed", "wait_for_human"}
    actual = {s.value for s in MissionStatus}
    if actual != expected:
        results.add_fail("test_mission_status_enum", f"Expected {expected}, got {actual}")
        return
    results.add_pass("test_mission_status_enum")


# ═══════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════

async def main():
    print("=" * 60)
    print("Persistence & Recovery Test Suite")
    print("=" * 60)

    # State construction
    test_build_initial_state_defaults()
    test_build_initial_state_scope_preserved()

    # Serialization
    test_state_json_serializable()
    test_state_reconstruction_from_checkpoint_data()

    # Checkpointer fallbacks
    await test_checkpointer_fallback_no_db_url()
    await test_checkpointer_fallback_disabled()
    await test_checkpointer_fallback_bad_url()

    # CLI args
    test_arg_parser_resume_flag()
    test_arg_parser_checkpoint_id()
    test_arg_parser_new_mission()

    # Error state handling
    test_error_state_preserves_prior_data()
    test_multiple_errors_accumulate()

    # Models
    test_mission_status_enum()

    ok = results.summary()
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
