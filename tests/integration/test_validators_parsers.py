#!/usr/bin/env python3
"""
Validators & Parsers Tests
===========================
Tests utility functions: scope validation, agent history tracking,
service version detection, JSON extraction, and serialization helpers.

Run inside agents container:
    docker exec vt-saiber-agents python tests/integration/test_validators_parsers.py
"""

import asyncio
import json
import sys

sys.path.insert(0, "/app")

from src.utils.validators import (
    target_in_scope,
    has_service_version_intel,
    list_recent_agent_names,
    has_agent_run,
)
from src.utils.parsers import extract_json_payload, to_jsonable
from src.state.models import AgentLogEntry, AgentError


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
        print(f"Validators & Parsers Tests: {self.passed}/{total} passed")
        if self.errors:
            print("Failed:")
            for name, err in self.errors:
                print(f"  - {name}: {err}")
        print(f"{'='*60}")
        return self.failed == 0


results = Results()


# ═══════════════════════════════════════════════════════════════
# TEST: target_in_scope
# ═══════════════════════════════════════════════════════════════

def test_scope_cidr():
    if not target_in_scope("192.168.1.50", ["192.168.1.0/24"]):
        results.add_fail("test_scope_cidr", "Should be in scope")
        return
    results.add_pass("test_scope_cidr")


def test_scope_cidr_out():
    if target_in_scope("10.0.0.1", ["192.168.1.0/24"]):
        results.add_fail("test_scope_cidr_out", "Should be out of scope")
        return
    results.add_pass("test_scope_cidr_out")


def test_scope_exact_ip():
    if not target_in_scope("10.0.0.5", ["10.0.0.5"]):
        results.add_fail("test_scope_exact_ip", "Exact IP should match")
        return
    results.add_pass("test_scope_exact_ip")


def test_scope_hostname():
    if not target_in_scope("automotive-testbed", ["automotive-testbed"]):
        results.add_fail("test_scope_hostname", "Hostname should match")
        return
    results.add_pass("test_scope_hostname")


def test_scope_hostname_not_in():
    if target_in_scope("evil-host", ["automotive-testbed"]):
        results.add_fail("test_scope_hostname_not", "Should not match")
        return
    results.add_pass("test_scope_hostname_not")


def test_scope_empty():
    if target_in_scope("10.0.0.1", []):
        results.add_fail("test_scope_empty", "Empty scope should reject all")
        return
    results.add_pass("test_scope_empty")


def test_scope_wide_cidr():
    if not target_in_scope("172.20.5.10", ["172.20.0.0/16"]):
        results.add_fail("test_scope_wide", "Should be in /16 scope")
        return
    results.add_pass("test_scope_wide")


def test_scope_multiple_entries():
    scope = ["192.168.1.0/24", "10.0.0.0/8"]
    if not target_in_scope("10.5.5.5", scope):
        results.add_fail("test_scope_multi", "Should match second entry")
        return
    results.add_pass("test_scope_multi")


# ═══════════════════════════════════════════════════════════════
# TEST: has_service_version_intel
# ═══════════════════════════════════════════════════════════════

def test_version_intel_present():
    targets = {"10.0.0.1": {"services": {"22": {"service_name": "ssh", "version": "OpenSSH 8.2"}}}}
    if not has_service_version_intel(targets):
        results.add_fail("test_version_present", "Should detect version")
        return
    results.add_pass("test_version_present")


def test_version_intel_absent():
    targets = {"10.0.0.1": {"services": {"22": {"service_name": "ssh"}}}}
    if has_service_version_intel(targets):
        results.add_fail("test_version_absent", "No version should return False")
        return
    results.add_pass("test_version_absent")


def test_version_intel_empty():
    if has_service_version_intel({}):
        results.add_fail("test_version_empty", "Empty targets should return False")
        return
    results.add_pass("test_version_empty")


def test_version_intel_empty_string():
    targets = {"10.0.0.1": {"services": {"22": {"service_name": "ssh", "version": ""}}}}
    if has_service_version_intel(targets):
        results.add_fail("test_version_empty_str", "Empty string version should return False")
        return
    results.add_pass("test_version_empty_str")


# ═══════════════════════════════════════════════════════════════
# TEST: list_recent_agent_names / has_agent_run
# ═══════════════════════════════════════════════════════════════

def test_recent_agents():
    log = [
        {"agent": "scout", "action": "scan"},
        {"agent": "fuzzer", "action": "enum"},
        {"agent": "librarian", "action": "research"},
    ]
    names = list_recent_agent_names(log)
    if names != ["scout", "fuzzer", "librarian"]:
        results.add_fail("test_recent_agents", f"Got {names}")
        return
    results.add_pass("test_recent_agents")


def test_recent_agents_limit():
    log = [{"agent": f"agent{i}", "action": "x"} for i in range(10)]
    names = list_recent_agent_names(log, n=3)
    if len(names) != 3:
        results.add_fail("test_recent_limit", f"Expected 3, got {len(names)}")
        return
    results.add_pass("test_recent_limit")


def test_recent_agents_empty():
    names = list_recent_agent_names([])
    if names:
        results.add_fail("test_recent_empty", f"Expected empty, got {names}")
        return
    results.add_pass("test_recent_empty")


def test_has_agent_run_true():
    log = [{"agent": "librarian", "action": "research"}]
    if not has_agent_run(log, "librarian"):
        results.add_fail("test_has_run_true", "Should detect librarian")
        return
    results.add_pass("test_has_run_true")


def test_has_agent_run_false():
    log = [{"agent": "scout", "action": "scan"}]
    if has_agent_run(log, "librarian"):
        results.add_fail("test_has_run_false", "Librarian didn't run")
        return
    results.add_pass("test_has_run_false")


def test_has_agent_run_case_insensitive():
    log = [{"agent": "Librarian", "action": "research"}]
    if not has_agent_run(log, "librarian"):
        results.add_fail("test_has_run_case", "Should be case insensitive")
        return
    results.add_pass("test_has_run_case")


def test_recent_agents_pydantic():
    """Should handle both dict and Pydantic entries."""
    log = [AgentLogEntry(agent="scout", action="scan").model_dump()]
    names = list_recent_agent_names(log)
    if names != ["scout"]:
        results.add_fail("test_recent_pydantic", f"Got {names}")
        return
    results.add_pass("test_recent_pydantic")


# ═══════════════════════════════════════════════════════════════
# TEST: extract_json_payload
# ═══════════════════════════════════════════════════════════════

def test_extract_clean_json():
    result = extract_json_payload('{"key": "value"}')
    if result != {"key": "value"}:
        results.add_fail("test_extract_clean", f"Got {result}")
        return
    results.add_pass("test_extract_clean")


def test_extract_fenced_json():
    text = """Here's the result:
```json
{"next_agent": "scout", "rationale": "need recon"}
```
That's my decision."""
    result = extract_json_payload(text)
    if result.get("next_agent") != "scout":
        results.add_fail("test_extract_fenced", f"Got {result}")
        return
    results.add_pass("test_extract_fenced")


def test_extract_embedded_json():
    text = 'I think {"action": "scan", "target": "10.0.0.1"} is best.'
    result = extract_json_payload(text)
    if result.get("action") != "scan":
        results.add_fail("test_extract_embedded", f"Got {result}")
        return
    results.add_pass("test_extract_embedded")


def test_extract_empty():
    try:
        extract_json_payload("")
        results.add_fail("test_extract_empty", "Should raise ValueError")
    except ValueError:
        results.add_pass("test_extract_empty")


def test_extract_no_json():
    try:
        extract_json_payload("no json here at all")
        results.add_fail("test_extract_no_json", "Should raise ValueError")
    except ValueError:
        results.add_pass("test_extract_no_json")


# ═══════════════════════════════════════════════════════════════
# TEST: to_jsonable
# ═══════════════════════════════════════════════════════════════

def test_to_jsonable_pydantic():
    entry = AgentLogEntry(agent="scout", action="scan")
    result = to_jsonable(entry)
    if not isinstance(result, dict):
        results.add_fail("test_jsonable_pydantic", f"Expected dict, got {type(result)}")
        return
    if result["agent"] != "scout":
        results.add_fail("test_jsonable_pydantic", f"Wrong agent: {result}")
        return
    results.add_pass("test_jsonable_pydantic")


def test_to_jsonable_list():
    entries = [AgentLogEntry(agent="scout", action="scan")]
    result = to_jsonable(entries)
    if not isinstance(result, list) or len(result) != 1:
        results.add_fail("test_jsonable_list", f"Got {result}")
        return
    results.add_pass("test_jsonable_list")


def test_to_jsonable_nested_dict():
    data = {"logs": [AgentLogEntry(agent="test", action="x")], "count": 1}
    result = to_jsonable(data)
    if not isinstance(result["logs"][0], dict):
        results.add_fail("test_jsonable_nested", "Nested Pydantic not converted")
        return
    results.add_pass("test_jsonable_nested")


def test_to_jsonable_plain():
    if to_jsonable(42) != 42:
        results.add_fail("test_jsonable_plain", "Plain values should pass through")
        return
    if to_jsonable("hello") != "hello":
        results.add_fail("test_jsonable_plain", "String should pass through")
        return
    results.add_pass("test_jsonable_plain")


# ═══════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════

async def main():
    print("=" * 60)
    print("Validators & Parsers Test Suite")
    print("=" * 60)

    # Scope validation
    test_scope_cidr()
    test_scope_cidr_out()
    test_scope_exact_ip()
    test_scope_hostname()
    test_scope_hostname_not_in()
    test_scope_empty()
    test_scope_wide_cidr()
    test_scope_multiple_entries()

    # Version intel
    test_version_intel_present()
    test_version_intel_absent()
    test_version_intel_empty()
    test_version_intel_empty_string()

    # Agent tracking
    test_recent_agents()
    test_recent_agents_limit()
    test_recent_agents_empty()
    test_has_agent_run_true()
    test_has_agent_run_false()
    test_has_agent_run_case_insensitive()
    test_recent_agents_pydantic()

    # JSON extraction
    test_extract_clean_json()
    test_extract_fenced_json()
    test_extract_embedded_json()
    test_extract_empty()
    test_extract_no_json()

    # to_jsonable
    test_to_jsonable_pydantic()
    test_to_jsonable_list()
    test_to_jsonable_nested_dict()
    test_to_jsonable_plain()

    ok = results.summary()
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
