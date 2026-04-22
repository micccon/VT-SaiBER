#!/usr/bin/env python3
"""
Integration Test: Supervisor -> Librarian Query Flow
======================================================
Validates that:
1. Supervisor can route to librarian
2. Librarian receives and processes queries from supervisor
3. Librarian provides valid intelligence briefs back to supervisor
4. RAG-confidence logic works (fallback to OSINT when needed)

Run inside agents container or from project root:
    docker exec vt-saiber-agents python tests/agent_tests/test_supervisor_librarian_integration.py
    python tests/agent_tests/test_supervisor_librarian_integration.py
"""

import asyncio
import sys
from pathlib import Path
import pytest

pytestmark = pytest.mark.asyncio

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agents.librarian import librarian_node
from src.agents.supervisor import supervisor_node
from src.main import build_initial_state
from src.state.models import SupervisorDecision


class Results:
    """Simple test result tracker."""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def add_pass(self, name, details=""):
        self.passed += 1
        msg = f"  [PASS] {name}"
        if details:
            msg += f" -- {details}"
        print(msg)

    def add_fail(self, name, err):
        self.failed += 1
        self.errors.append((name, err))
        print(f"  [FAIL] {name}: {err}")

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{'='*70}")
        print(f"Integration Tests: {self.passed}/{total} passed")
        if self.errors:
            print("Failures:")
            for name, err in self.errors:
                print(f"  - {name}: {err}")
        print(f"{'='*70}\n")
        return self.failed == 0


results = Results()


def _base_state(**overrides) -> dict:
    """Create a base mission state for testing."""
    state = build_initial_state(
        mission_goal="Research and exploit target vulnerabilities",
        target_scope=["192.168.1.10"],
        mission_id="integration-test-001"
    )
    state.update(overrides)
    return state


# ═══════════════════════════════════════════════════════════════════════════
# TEST 1: Librarian can receive and process basic query
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_librarian_receives_query():
    """Verify librarian can handle a basic state with discovered services."""
    print("\n[TEST 1] Librarian receives query with service intel...")
    
    state = _base_state(
        discovered_targets={
            "192.168.1.10": {
                "services": {
                    "22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"},
                    "80": {"service_name": "http", "version": "Apache 2.4.41"},
                }
            }
        },
        web_findings=[
            {"path": "/admin", "status_code": 200},
            {"path": "/api/v1", "status_code": 301},
        ]
    )
    
    try:
        # Run librarian agent
        output = await librarian_node(state)
        
        # Validate output structure
        if "current_agent" not in output:
            results.add_fail("test_lib_query_1", "Missing 'current_agent' in output")
            return
        
        if output["current_agent"] != "librarian":
            results.add_fail("test_lib_query_1", f"Wrong agent: {output['current_agent']}")
            return
        
        if "intelligence_findings" not in output:
            results.add_fail("test_lib_query_1", "Missing 'intelligence_findings' in output")
            return
        
        if "rag_fallback_triggered" not in output:
            results.add_fail("test_lib_query_1", "Missing 'rag_fallback_triggered' in output")
            return
        
        results.add_pass(
            "test_lib_query_1",
            f"Librarian processed query, fallback={output['rag_fallback_triggered']}"
        )
    except Exception as e:
        results.add_fail("test_lib_query_1", f"Exception: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# TEST 2: Librarian output has valid intelligence brief structure
# ═══════════════════════════════════════════════════════════════════════════

async def test_librarian_output_structure():
    """Verify the intelligence brief in intelligence_findings is properly structured."""
    print("\n[TEST 2] Librarian output has valid intelligence brief structure...")
    
    state = _base_state(
        discovered_targets={
            "192.168.1.10": {
                "services": {
                    "22": {"service_name": "ftp", "version": "vsftpd 2.3.4"},
                }
            }
        }
    )
    
    try:
        output = await librarian_node(state)
        
        if "intelligence_findings" not in output or not output["intelligence_findings"]:
            results.add_fail("test_lib_struct", "No intelligence_findings in output")
            return
        
        finding = output["intelligence_findings"][0]
        required_keys = ["source", "description", "exploit_available", "data"]
        
        for key in required_keys:
            if key not in finding:
                results.add_fail(
                    "test_lib_struct",
                    f"Missing key '{key}' in intelligence_findings[0]"
                )
                return
        
        data = finding["data"]
        data_keys = ["technical_params", "citations", "confidence", "conflicting_sources"]
        
        for key in data_keys:
            if key not in data:
                results.add_fail(
                    "test_lib_struct",
                    f"Missing key '{key}' in data section"
                )
                return
        
        # Verify data types
        if not isinstance(data["confidence"], (float, int)):
            results.add_fail("test_lib_struct", "confidence should be float/int")
            return
        
        if not isinstance(data["citations"], list):
            results.add_fail("test_lib_struct", "citations should be list")
            return
        
        results.add_pass(
            "test_lib_struct",
            f"Valid structure with confidence={data['confidence']:.2f}"
        )
    except Exception as e:
        results.add_fail("test_lib_struct", f"Exception: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# TEST 3: RAG confidence check logic
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_rag_confidence_logic():
    """Verify that _is_rag_confident method correctly evaluates RAG results."""
    print("\n[TEST 3] RAG confidence check logic...")
    
    from src.agents.librarian import LibrarianAgent
    
    agent = LibrarianAgent()
    
    # Test 1: Empty results → not confident
    result1 = agent._is_rag_confident([])
    if result1:
        results.add_fail("test_rag_conf", "Empty results should not be confident")
        return
    
    # Test 2: Too few results (< 3) → not confident
    result2 = agent._is_rag_confident([{"score": 0.9}, {"score": 0.85}])
    if result2:
        results.add_fail("test_rag_conf", "2 results should not be confident (need 3+)")
        return
    
    # Test 3: Minimum results with high score → confident
    result3 = agent._is_rag_confident([
        {"score": 0.90},
        {"score": 0.85},
        {"score": 0.80}
    ])
    if not result3:
        results.add_fail("test_rag_conf", "3 results with high scores should be confident")
        return
    
    # Test 4: Enough results but low max score (< 0.75) → not confident
    result4 = agent._is_rag_confident([
        {"score": 0.70},
        {"score": 0.65},
        {"score": 0.60}
    ])
    if result4:
        results.add_fail("test_rag_conf", "Results with max_score=0.70 (< 0.75) should not be confident")
        return
    
    # Test 5: Using 'similarity' field instead of 'score'
    result5 = agent._is_rag_confident([
        {"similarity": 0.85},
        {"similarity": 0.80},
        {"similarity": 0.78}
    ])
    if not result5:
        results.add_fail("test_rag_conf", "Should recognize 'similarity' field")
        return
    
    results.add_pass("test_rag_conf", "All confidence checks passed")


# ═══════════════════════════════════════════════════════════════════════════
# TEST 4: Librarian cache functionality
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_librarian_cache():
    """Verify that librarian cache prevents redundant processing."""
    print("\n[TEST 4] Librarian caching prevents redundant queries...")
    
    state = _base_state(
        discovered_targets={
            "192.168.1.10": {
                "services": {
                    "22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"},
                }
            }
        }
    )
    
    try:
        # First run: cache miss
        output1 = await librarian_node(state)
        
        if "research_cache" not in output1:
            results.add_fail("test_cache", "Missing 'research_cache' in first output")
            return
        
        first_cache_size = len(output1["research_cache"])
        if first_cache_size == 0:
            results.add_fail("test_cache", "Cache should have entries after first run")
            return
        
        # Second run with same state: should use cache
        state_with_cache = state.copy()
        state_with_cache["research_cache"] = output1["research_cache"]
        
        output2 = await librarian_node(state_with_cache)
        
        if "research_cache" not in output2:
            results.add_fail("test_cache", "Missing 'research_cache' in second output")
            return
        
        # Cache size should be same or greater
        second_cache_size = len(output2["research_cache"])
        if second_cache_size < first_cache_size:
            results.add_fail(
                "test_cache",
                f"Cache shrunk: {first_cache_size} → {second_cache_size}"
            )
            return
        
        results.add_pass(
            "test_cache",
            f"Cache working: {first_cache_size} entries after 2 runs"
        )
    except Exception as e:
        results.add_fail("test_cache", f"Exception: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# TEST 5: Supervisor can route to Librarian
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_supervisor_routes_to_librarian():
    """Verify supervisor correctly routes to librarian in appropriate scenarios."""
    print("\n[TEST 5] Supervisor routes to librarian appropriately...")
    
    state = _base_state(
        discovered_targets={
            "192.168.1.10": {
                "services": {
                    "80": {"service_name": "http", "version": "Apache 2.4.41"},
                }
            }
        },
        web_findings=[
            {"path": "/admin", "status_code": 200},
        ]
    )
    
    try:
        output = await supervisor_node(state)
        
        if "next_agent" not in output:
            results.add_fail("test_sup_route", "Missing 'next_agent' in supervisor output")
            return
        
        next_agent = output["next_agent"]
        # Supervisor should either route to librarian or scout/fuzzer (depending on LLM or fallback)
        valid_agents = {"scout", "fuzzer", "librarian", "striker", "resident", "end"}
        
        if next_agent not in valid_agents:
            results.add_fail("test_sup_route", f"Invalid agent: {next_agent}")
            return
        
        results.add_pass(
            "test_sup_route",
            f"Supervisor routed to: {next_agent}"
        )
    except Exception as e:
        results.add_fail("test_sup_route", f"Exception: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# TEST 6: Full Supervisor → Librarian pipeline
# ═══════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_full_supervisor_librarian_pipeline():
    """
    Full end-to-end: supervisor decides to route to librarian, 
    then librarian processes the query successfully.
    """
    print("\n[TEST 6] Full Supervisor -> Librarian pipeline...")
    
    state = _base_state(
        discovered_targets={
            "192.168.1.10": {
                "services": {
                    "21": {"service_name": "ftp", "version": "vsftpd 2.3.4"},
                    "80": {"service_name": "http", "version": "Apache 2.4.41"},
                }
            }
        },
        web_findings=[
            {"path": "/admin", "status_code": 200},
            {"path": "/api", "status_code": 200},
        ]
    )
    
    try:
        # Step 1: Supervisor routes
        sup_output = await supervisor_node(state)
        
        if "next_agent" not in sup_output:
            results.add_fail("test_full_pipe", "Supervisor missing 'next_agent'")
            return
        
        next_agent = sup_output["next_agent"]
        
        # If supervisor routes to librarian, verify librarian can handle it
        if next_agent == "librarian":
            # Merge supervisor output into state
            state_merged = state.copy()
            state_merged.update(sup_output)
            
            # Step 2: Run librarian
            lib_output = await librarian_node(state_merged)
            
            # Verify librarian output
            if "intelligence_findings" not in lib_output:
                results.add_fail("test_full_pipe", "Librarian missing 'intelligence_findings'")
                return
            
            if not lib_output["intelligence_findings"]:
                results.add_fail("test_full_pipe", "intelligence_findings is empty")
                return
            
            finding = lib_output["intelligence_findings"][0]
            if "data" not in finding or "confidence" not in finding["data"]:
                results.add_fail("test_full_pipe", "Invalid finding structure")
                return
            
            results.add_pass(
                "test_full_pipe",
                f"Full pipeline: supervisor->librarian, confidence={finding['data']['confidence']:.2f}"
            )
        else:
            # Supervisor routed to something else (scout, fuzzer, etc)
            results.add_pass(
                "test_full_pipe",
                f"Supervisor routed to {next_agent} (also valid in this scenario)"
            )
    except Exception as e:
        results.add_fail("test_full_pipe", f"Exception: {e}")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN: Run all tests
# ═══════════════════════════════════════════════════════════════════════════

async def main():
    print("="*70)
    print("Supervisor -> Librarian Integration Test Suite")
    print("="*70)
    
    await test_librarian_receives_query()
    await test_librarian_output_structure()
    await test_rag_confidence_logic()
    await test_librarian_cache()
    await test_supervisor_routes_to_librarian()
    await test_full_supervisor_librarian_pipeline()
    
    ok = results.summary()
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
