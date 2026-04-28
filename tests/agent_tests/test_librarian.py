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

import pytest

sys.path.insert(0, "/app")

from src.agents.librarian import LibrarianAgent, librarian_node
from src.database.librarian.models import ResearchEvidence
from src.main import build_initial_state
from src.state.models import IntelligenceBrief

pytestmark = pytest.mark.asyncio

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


def _seed_cached_brief(state):
    agent = LibrarianAgent()
    query = agent._build_research_query(state)
    cache_key = agent._cache_key(query)
    state["research_cache"] = {
        cache_key: IntelligenceBrief(
            summary=f"Cached intelligence brief for: {query}",
            technical_params={"exploit_module": "auxiliary/scanner/ssh/ssh_login"},
            is_osint_derived=False,
            confidence=0.72,
            citations=["local-test-cache"],
            conflicting_sources=None,
        ).model_dump()
    }
    return state


class EmptyRag:
    async def retrieve(self, query: str, source: str = "both", top_k: int = 5, filters=None):
        return {"kb_results": [], "findings_results": [], "combined": []}


class OSINTWithCVE:
    def is_configured(self):
        return True

    async def search(self, query: str, *, max_results=None):
        return [
            {
                "title": "NVD record for CVE-2011-2523",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
                "snippet": "Official reference mentions CVE-2011-2523 for vsftpd 2.3.4.",
                "score": 0.9,
            }
        ]


class FailingBroadThenExactCVE:
    def __init__(self):
        self.known_cve_calls = []

    async def search(self, *, query: str, service_clues=None, known_cves=None, max_results: int = 5):
        self.known_cve_calls.append(list(known_cves or []))
        if "CVE-2011-2523" not in set(known_cves or []):
            raise RuntimeError("broad keyword lookup failed")
        return [
            ResearchEvidence(
                source_type="cve",
                identifier="CVE-2011-2523",
                title="CVE-2011-2523",
                reference="https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
                snippet="vsftpd 2.3.4 backdoor command execution vulnerability.",
                score=0.88,
                metadata={"cve": "CVE-2011-2523", "severity": "CRITICAL"},
            )
        ]


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
    """Librarian node should produce research_cache and intelligence_findings."""
    state = _seed_cached_brief(
        _base_state(
            discovered_targets={
                "10.0.0.1": {"services": {"22": {"service_name": "ssh", "version": "OpenSSH 8.2"}}}
            }
        )
    )
    out = await librarian_node(state)

    if out.get("current_agent") != "librarian":
        results.add_fail("test_node_output", f"Expected current_agent=librarian: {out.get('current_agent')}")
        return

    cache = out.get("research_cache", {})
    if not cache:
        results.add_fail("test_node_output", "Expected non-empty research_cache")
        return

    osint = out.get("intelligence_findings", [])
    if not osint:
        results.add_fail("test_node_output", "Expected non-empty intelligence_findings")
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
    state = _seed_cached_brief(_base_state())
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
    """Intelligence findings should use the current flat brief-derived shape."""
    state = _seed_cached_brief(_base_state())
    out = await librarian_node(state)
    osint = out.get("intelligence_findings", [])
    if not osint:
        results.add_fail("test_osint_structure", "No osint findings")
        return
    finding = osint[0]
    required = ["source", "description", "confidence", "source_types", "citations", "technical_params"]
    missing = [k for k in required if k not in finding]
    if missing:
        results.add_fail("test_osint_structure", f"Missing fields: {missing}")
        return
    if finding.get("source") != "librarian":
        results.add_fail("test_osint_structure", f"Unexpected source: {finding.get('source')}")
        return
    results.add_pass("test_osint_structure")


async def test_librarian_retries_cve_lookup_from_osint_cve_ids():
    """Explicit CVEs found in OSINT should be verified through the CVE client."""

    cve_client = FailingBroadThenExactCVE()
    agent = LibrarianAgent(
        rag_orchestrator=EmptyRag(),
        osint_client=OSINTWithCVE(),
        cve_client=cve_client,
        llm_client=None,
    )
    state = _base_state(
        mission_goal="Research exploit path for vsftpd 2.3.4",
        discovered_targets={
            "10.0.0.1": {
                "services": {
                    "21": {
                        "service_name": "ftp",
                        "version": "vsftpd 2.3.4",
                        "banner": "vsFTPd 2.3.4",
                    }
                }
            }
        },
    )

    out = await agent.call_llm(state)
    cache_entry = next(iter(out["research_cache"].values()))

    assert "osint" in cache_entry["source_types"]
    assert "cve" in cache_entry["source_types"]
    assert "cve_lookup_failed" not in cache_entry["degraded_reasons"]
    assert cve_client.known_cve_calls[0] == []
    assert "CVE-2011-2523" in cve_client.known_cve_calls[-1]


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
    await test_librarian_retries_cve_lookup_from_osint_cve_ids()

    # Models
    test_intelligence_brief_model()
    test_intelligence_brief_defaults()

    ok = results.summary()
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
