#!/usr/bin/env python3
"""
Librarian Agent Tests
======================
Validates research query building, fallback briefs, cache key generation,
state output structure, and LLM error handling.

Run inside agents container:
    docker exec vt-saiber-agents python tests/agent_tests/test_librarian.py
"""

import asyncio
import json
import sys
import traceback

sys.path.insert(0, "/app")

from src.agents.librarian import LibrarianAgent, librarian_node
from src.main import build_initial_state
from src.state.models import IntelligenceBrief


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
        print(f"Librarian Tests: {self.passed}/{total} passed")
        if self.errors:
            print("Failed:")
            for name, err in self.errors:
                print(f"  - {name}: {err}")
        print(f"{'='*60}")
        return self.failed == 0


results = Results()


def _base_state(**overrides):
    state = build_initial_state("Exploit target via SSH", ["10.0.0.0/24"], "test-lib-001")
    state.update(overrides)
    return state


# ═══════════════════════════════════════════════════════════════
# TEST: Research query building
# ═══════════════════════════════════════════════════════════════

def test_build_query_includes_mission():
    agent = LibrarianAgent()
    state = _base_state()
    query = agent._build_research_query(state)
    if "Exploit target via SSH" not in query:
        results.add_fail("test_query_mission", f"Mission not in query: {query}")
        return
    results.add_pass("test_query_mission")


def test_build_query_includes_services():
    agent = LibrarianAgent()
    state = _base_state(
        discovered_targets={
            "10.0.0.1": {
                "services": {
                    "22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"},
                    "80": {"service_name": "http", "version": "Apache 2.4.41"},
                }
            }
        }
    )
    query = agent._build_research_query(state)
    if "ssh" not in query.lower():
        results.add_fail("test_query_services", f"SSH not in query: {query}")
        return
    if "OpenSSH 8.2p1" not in query:
        results.add_fail("test_query_services", f"Version not in query: {query}")
        return
    results.add_pass("test_query_services")


def test_build_query_includes_web_findings():
    agent = LibrarianAgent()
    state = _base_state(
        web_findings=[
            {"path": "/admin", "status_code": 200},
            {"path": "/api/v1", "status_code": 301},
        ]
    )
    query = agent._build_research_query(state)
    if "/admin" not in query:
        results.add_fail("test_query_web", f"Web path not in query: {query}")
        return
    results.add_pass("test_query_web")


def test_build_query_sanitized():
    """Query should strip newlines and backticks (prompt injection hygiene)."""
    agent = LibrarianAgent()
    state = _base_state(mission_goal="Test\nwith\n`backticks`")
    query = agent._build_research_query(state)
    if "\n" in query:
        results.add_fail("test_query_sanitized", "Newlines not stripped")
        return
    if "`" in query:
        results.add_fail("test_query_sanitized", "Backticks not stripped")
        return
    results.add_pass("test_query_sanitized")


def test_build_query_empty_state():
    agent = LibrarianAgent()
    state = _base_state(discovered_targets={}, web_findings=[])
    query = agent._build_research_query(state)
    if "mission=" not in query:
        results.add_fail("test_query_empty", f"Expected mission= prefix: {query}")
        return
    results.add_pass("test_query_empty")


# ═══════════════════════════════════════════════════════════════
# TEST: Cache key generation
# ═══════════════════════════════════════════════════════════════

def test_cache_key_deterministic():
    agent = LibrarianAgent()
    key1 = agent._cache_key("same query text")
    key2 = agent._cache_key("same query text")
    if key1 != key2:
        results.add_fail("test_cache_deterministic", f"Keys differ: {key1} vs {key2}")
        return
    results.add_pass("test_cache_deterministic")


def test_cache_key_different_queries():
    agent = LibrarianAgent()
    key1 = agent._cache_key("query A")
    key2 = agent._cache_key("query B")
    if key1 == key2:
        results.add_fail("test_cache_different", "Different queries should produce different keys")
        return
    results.add_pass("test_cache_different")


def test_cache_key_prefix():
    agent = LibrarianAgent()
    key = agent._cache_key("any query")
    if not key.startswith("research_"):
        results.add_fail("test_cache_prefix", f"Expected research_ prefix: {key}")
        return
    results.add_pass("test_cache_prefix")


# ═══════════════════════════════════════════════════════════════
# TEST: Fallback brief (no LLM client)
# ═══════════════════════════════════════════════════════════════

async def test_fallback_brief_no_client():
    """Without API key, librarian should produce a fallback brief."""
    agent = LibrarianAgent()
    agent._client = None
    brief = await agent._research_brief("test query")
    if not isinstance(brief, IntelligenceBrief):
        results.add_fail("test_fallback_brief", f"Expected IntelligenceBrief, got {type(brief)}")
        return
    if brief.confidence > 0.5:
        results.add_fail("test_fallback_brief", f"Fallback confidence should be low: {brief.confidence}")
        return
    if "test query" not in brief.summary:
        results.add_fail("test_fallback_brief", f"Query not in summary: {brief.summary}")
        return
    results.add_pass("test_fallback_brief")


# ═══════════════════════════════════════════════════════════════
# TEST: Full node output structure
# ═══════════════════════════════════════════════════════════════

async def test_librarian_node_output_structure():
    """Librarian node should produce research_cache and osint_findings."""
    state = _base_state(
        discovered_targets={
            "10.0.0.1": {"services": {"22": {"service_name": "ssh", "version": "OpenSSH 8.2"}}}
        }
    )
    out = await librarian_node(state)

    if out.get("current_agent") != "librarian":
        results.add_fail("test_node_output", f"Expected current_agent=librarian: {out.get('current_agent')}")
        return

    cache = out.get("research_cache", {})
    if not cache:
        results.add_fail("test_node_output", "Expected non-empty research_cache")
        return

    osint = out.get("osint_findings", [])
    if not osint:
        results.add_fail("test_node_output", "Expected non-empty osint_findings")
        return

    first_osint = osint[0]
    if first_osint.get("source") != "librarian":
        results.add_fail("test_node_output", f"Expected source=librarian: {first_osint}")
        return

    log = out.get("agent_log", [])
    if not log:
        results.add_fail("test_node_output", "Expected agent_log entry")
        return

    results.add_pass("test_node_output")


async def test_librarian_cache_key_in_output():
    """Research cache should use a hash-based key."""
    state = _base_state()
    out = await librarian_node(state)
    cache = out.get("research_cache", {})
    keys = list(cache.keys())
    if not keys:
        results.add_fail("test_cache_in_output", "No cache keys")
        return
    if not keys[0].startswith("research_"):
        results.add_fail("test_cache_in_output", f"Expected research_ prefix: {keys[0]}")
        return
    results.add_pass("test_cache_in_output")


async def test_librarian_osint_finding_structure():
    """OSINT findings should have required fields."""
    state = _base_state()
    out = await librarian_node(state)
    osint = out.get("osint_findings", [])
    if not osint:
        results.add_fail("test_osint_structure", "No osint findings")
        return
    finding = osint[0]
    required = ["source", "description", "data"]
    missing = [k for k in required if k not in finding]
    if missing:
        results.add_fail("test_osint_structure", f"Missing fields: {missing}")
        return
    data = finding.get("data", {})
    if "confidence" not in data:
        results.add_fail("test_osint_structure", f"Missing confidence in data: {data.keys()}")
        return
    results.add_pass("test_osint_structure")


# ═══════════════════════════════════════════════════════════════
# TEST: IntelligenceBrief model
# ═══════════════════════════════════════════════════════════════

def test_intelligence_brief_model():
    brief = IntelligenceBrief(
        summary="Test brief",
        technical_params={"exploit_module": "exploit/linux/ssh/test"},
        is_osint_derived=True,
        confidence=0.85,
        citations=["https://cve.mitre.org/test"],
        conflicting_sources=["Source A disagrees"],
    )
    dumped = brief.model_dump()
    if dumped["confidence"] != 0.85:
        results.add_fail("test_brief_model", f"Wrong confidence: {dumped['confidence']}")
        return
    if not dumped["is_osint_derived"]:
        results.add_fail("test_brief_model", "Expected is_osint_derived=True")
        return
    results.add_pass("test_brief_model")


def test_intelligence_brief_defaults():
    brief = IntelligenceBrief(summary="Minimal")
    if brief.confidence != 0.0:
        results.add_fail("test_brief_defaults", f"Default confidence should be 0.0: {brief.confidence}")
        return
    if brief.citations:
        results.add_fail("test_brief_defaults", "Default citations should be empty")
        return
    results.add_pass("test_brief_defaults")


# ═══════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════

async def main():
    print("=" * 60)
    print("Librarian Agent Test Suite")
    print("=" * 60)

    # Query building
    test_build_query_includes_mission()
    test_build_query_includes_services()
    test_build_query_includes_web_findings()
    test_build_query_sanitized()
    test_build_query_empty_state()

    # Cache keys
    test_cache_key_deterministic()
    test_cache_key_different_queries()
    test_cache_key_prefix()

    # Fallback
    await test_fallback_brief_no_client()

    # Node output
    await test_librarian_node_output_structure()
    await test_librarian_cache_key_in_output()
    await test_librarian_osint_finding_structure()

    # Models
    test_intelligence_brief_model()
    test_intelligence_brief_defaults()

    ok = results.summary()
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
