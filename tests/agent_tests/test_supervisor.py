#!/usr/bin/env python3
"""
Supervisor Agent Tests
=======================
Validates supervisor routing logic, guardrails, fallback decisions,
context building, and decision parsing without requiring a live LLM.

Run inside agents container:
    docker exec vt-saiber-agents python tests/agent_tests/test_supervisor.py
"""

import asyncio
import json
import sys
import traceback

sys.path.insert(0, "/app")

from src.agents.supervisor import SupervisorAgent, supervisor_node
from src.main import build_initial_state
from src.state.models import SupervisorDecision, AgentLogEntry


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
        print(f"Supervisor Tests: {self.passed}/{total} passed")
        if self.errors:
            print("Failed:")
            for name, err in self.errors:
                print(f"  - {name}: {err}")
        print(f"{'='*60}")
        return self.failed == 0


results = Results()


def _base_state(**overrides):
    state = build_initial_state("Exploit target", ["10.0.0.0/24"], "test-sup-001")
    state.update(overrides)
    return state


# ═══════════════════════════════════════════════════════════════
# TEST: Decision parsing
# ═══════════════════════════════════════════════════════════════

def test_parse_decision_clean_json():
    agent = SupervisorAgent()
    raw = json.dumps({
        "next_agent": "scout",
        "rationale": "Need recon first",
        "specific_goal": "Discover services",
        "confidence_score": 0.9,
    })
    decision = agent._parse_decision(raw)
    if decision.next_agent != "scout":
        results.add_fail("test_parse_clean_json", f"Expected scout, got {decision.next_agent}")
        return
    if decision.confidence_score != 0.9:
        results.add_fail("test_parse_clean_json", f"Expected 0.9, got {decision.confidence_score}")
        return
    results.add_pass("test_parse_clean_json")


def test_parse_decision_markdown_fenced():
    agent = SupervisorAgent()
    raw = """Here's my decision:
```json
{"next_agent": "striker", "rationale": "SSH found", "specific_goal": "Exploit SSH", "confidence_score": 0.85}
```"""
    decision = agent._parse_decision(raw)
    if decision.next_agent != "striker":
        results.add_fail("test_parse_fenced", f"Expected striker, got {decision.next_agent}")
        return
    results.add_pass("test_parse_fenced")


def test_parse_decision_embedded_json():
    agent = SupervisorAgent()
    raw = 'I think we should do {"next_agent": "fuzzer", "rationale": "web found", "specific_goal": "Enum web", "confidence_score": 0.7} based on the findings.'
    decision = agent._parse_decision(raw)
    if decision.next_agent != "fuzzer":
        results.add_fail("test_parse_embedded", f"Expected fuzzer, got {decision.next_agent}")
        return
    results.add_pass("test_parse_embedded")


def test_parse_decision_confidence_alias():
    """LLM might return 'confidence' instead of 'confidence_score'."""
    agent = SupervisorAgent()
    raw = json.dumps({
        "next_agent": "librarian",
        "rationale": "Need research",
        "specific_goal": "Research CVEs",
        "confidence": 0.6,
    })
    decision = agent._parse_decision(raw)
    if decision.confidence_score != 0.6:
        results.add_fail("test_confidence_alias", f"Expected 0.6, got {decision.confidence_score}")
        return
    results.add_pass("test_confidence_alias")


def test_parse_decision_expected_outcome_alias():
    """LLM might return 'expected_outcome' instead of 'specific_goal'."""
    agent = SupervisorAgent()
    raw = json.dumps({
        "next_agent": "scout",
        "rationale": "Start recon",
        "expected_outcome": "Find open ports",
        "confidence_score": 0.8,
    })
    decision = agent._parse_decision(raw)
    if decision.specific_goal != "Find open ports":
        results.add_fail("test_outcome_alias", f"Expected 'Find open ports', got {decision.specific_goal}")
        return
    results.add_pass("test_outcome_alias")


def test_parse_decision_invalid_json():
    agent = SupervisorAgent()
    try:
        agent._parse_decision("this is not json at all")
        results.add_fail("test_parse_invalid", "Should have raised ValueError")
    except ValueError:
        results.add_pass("test_parse_invalid")
    except Exception as e:
        results.add_fail("test_parse_invalid", f"Expected ValueError, got {type(e).__name__}: {e}")


# ═══════════════════════════════════════════════════════════════
# TEST: Fallback decisions
# ═══════════════════════════════════════════════════════════════

def test_fallback_no_targets():
    agent = SupervisorAgent()
    state = _base_state(discovered_targets={}, active_sessions={}, web_findings=[])
    decision = agent._fallback_decision(state, reason="LLM timeout")
    if decision.next_agent != "scout":
        results.add_fail("test_fallback_no_targets", f"Expected scout, got {decision.next_agent}")
        return
    results.add_pass("test_fallback_no_targets")


def test_fallback_has_sessions():
    agent = SupervisorAgent()
    state = _base_state(
        discovered_targets={"10.0.0.1": {"services": {}}},
        active_sessions={"10.0.0.1": {"session_id": 1}},
    )
    decision = agent._fallback_decision(state, reason="LLM error")
    if decision.next_agent != "resident":
        results.add_fail("test_fallback_sessions", f"Expected resident, got {decision.next_agent}")
        return
    results.add_pass("test_fallback_sessions")


def test_fallback_web_findings_no_librarian():
    agent = SupervisorAgent()
    state = _base_state(
        discovered_targets={"10.0.0.1": {"services": {}}},
        active_sessions={},
        web_findings=[{"path": "/admin", "status_code": 200}],
        agent_log=[],
    )
    decision = agent._fallback_decision(state, reason="LLM error")
    if decision.next_agent != "librarian":
        results.add_fail("test_fallback_web_no_lib", f"Expected librarian, got {decision.next_agent}")
        return
    results.add_pass("test_fallback_web_no_lib")


def test_fallback_web_findings_librarian_ran():
    agent = SupervisorAgent()
    state = _base_state(
        discovered_targets={"10.0.0.1": {"services": {}}},
        active_sessions={},
        web_findings=[{"path": "/admin", "status_code": 200}],
        agent_log=[AgentLogEntry(agent="librarian", action="research_brief").model_dump()],
    )
    decision = agent._fallback_decision(state, reason="LLM error")
    if decision.next_agent != "striker":
        results.add_fail("test_fallback_web_lib_ran", f"Expected striker, got {decision.next_agent}")
        return
    results.add_pass("test_fallback_web_lib_ran")


def test_fallback_targets_no_web():
    agent = SupervisorAgent()
    state = _base_state(
        discovered_targets={"10.0.0.1": {"services": {}}},
        active_sessions={},
        web_findings=[],
    )
    decision = agent._fallback_decision(state, reason="LLM error")
    if decision.next_agent != "fuzzer":
        results.add_fail("test_fallback_no_web", f"Expected fuzzer, got {decision.next_agent}")
        return
    results.add_pass("test_fallback_no_web")


def test_fallback_confidence_low():
    agent = SupervisorAgent()
    state = _base_state()
    decision = agent._fallback_decision(state, reason="test")
    if decision.confidence_score > 0.5:
        results.add_fail("test_fallback_confidence", f"Fallback confidence should be low, got {decision.confidence_score}")
        return
    results.add_pass("test_fallback_confidence")


# ═══════════════════════════════════════════════════════════════
# TEST: Guardrails
# ═══════════════════════════════════════════════════════════════

def test_guardrail_invalid_agent_corrected():
    agent = SupervisorAgent()
    state = _base_state(discovered_targets={})
    decision = SupervisorDecision(
        next_agent="INVALID_AGENT",
        rationale="test",
        specific_goal="test",
        confidence_score=0.5,
    )
    corrected, reason = agent._apply_guardrails(state, decision)
    if corrected.next_agent == "INVALID_AGENT":
        results.add_fail("test_guardrail_invalid", "Should have corrected invalid agent")
        return
    if not reason:
        results.add_fail("test_guardrail_invalid", "Should provide correction reason")
        return
    results.add_pass("test_guardrail_invalid")


def test_guardrail_force_librarian_before_striker():
    """When versions are available and librarian hasn't run, striker should be redirected to librarian."""
    agent = SupervisorAgent()
    state = _base_state(
        discovered_targets={
            "10.0.0.1": {"services": {"22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"}}}
        },
        agent_log=[],
    )
    decision = SupervisorDecision(
        next_agent="striker",
        rationale="try exploit",
        specific_goal="exploit ssh",
        confidence_score=0.8,
    )
    corrected, reason = agent._apply_guardrails(state, decision)
    if corrected.next_agent != "librarian":
        results.add_fail("test_guardrail_lib_before_striker", f"Expected librarian, got {corrected.next_agent}")
        return
    if "librarian" not in reason:
        results.add_fail("test_guardrail_lib_before_striker", f"Expected librarian in reason: {reason}")
        return
    results.add_pass("test_guardrail_lib_before_striker")


def test_guardrail_allows_striker_after_librarian():
    """When librarian has already run, striker should be allowed."""
    agent = SupervisorAgent()
    state = _base_state(
        discovered_targets={
            "10.0.0.1": {"services": {"22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"}}}
        },
        agent_log=[AgentLogEntry(agent="librarian", action="research_brief").model_dump()],
    )
    decision = SupervisorDecision(
        next_agent="striker",
        rationale="exploit ssh",
        specific_goal="use ssh_login",
        confidence_score=0.8,
    )
    corrected, reason = agent._apply_guardrails(state, decision)
    if corrected.next_agent != "striker":
        results.add_fail("test_guardrail_striker_ok", f"Expected striker, got {corrected.next_agent}")
        return
    results.add_pass("test_guardrail_striker_ok")


def test_guardrail_striker_failure_backtrack():
    """After striker fails, guardrail should redirect away from striker."""
    agent = SupervisorAgent()
    state = _base_state(
        discovered_targets={"10.0.0.1": {"services": {}}},
        active_sessions={},
        exploited_services=[{"status": "failed", "target": "10.0.0.1", "module": "exploit/test"}],
        agent_log=[
            AgentLogEntry(agent="librarian", action="research_brief").model_dump(),
            AgentLogEntry(agent="striker", action="run_exploit").model_dump(),
        ],
    )
    decision = SupervisorDecision(
        next_agent="striker",
        rationale="try again",
        specific_goal="retry",
        confidence_score=0.5,
    )
    corrected, reason = agent._apply_guardrails(state, decision)
    if corrected.next_agent == "striker":
        results.add_fail("test_guardrail_backtrack", "Should redirect away from striker after failure")
        return
    if corrected.next_agent not in {"librarian", "fuzzer"}:
        results.add_fail("test_guardrail_backtrack", f"Expected librarian or fuzzer, got {corrected.next_agent}")
        return
    results.add_pass("test_guardrail_backtrack")


# ═══════════════════════════════════════════════════════════════
# TEST: Context summary building
# ═══════════════════════════════════════════════════════════════

def test_context_summary_includes_key_data():
    agent = SupervisorAgent()
    state = _base_state(
        discovered_targets={
            "10.0.0.1": {"services": {"22": {"service_name": "ssh", "version": "OpenSSH 8.2"}}}
        },
        active_sessions={"10.0.0.1": {"session_id": 3}},
        critical_findings=["Session 3 opened"],
        agent_log=[AgentLogEntry(agent="scout", action="recon_scan").model_dump()],
    )
    summary = agent._build_context_summary(state)
    checks = [
        ("mission goal", "Exploit target" in summary),
        ("target IP", "10.0.0.1" in summary),
        ("service info", "ssh" in summary.lower()),
        ("critical findings", "Session 3" in summary),
        ("recent actions", "scout" in summary),
    ]
    for label, passed in checks:
        if not passed:
            results.add_fail("test_context_summary", f"Missing {label} in summary")
            return
    results.add_pass("test_context_summary")


def test_context_summary_empty_state():
    agent = SupervisorAgent()
    state = _base_state()
    summary = agent._build_context_summary(state)
    if "none" not in summary.lower():
        results.add_fail("test_context_empty", "Expected 'none' markers for empty state")
        return
    results.add_pass("test_context_empty")


# ═══════════════════════════════════════════════════════════════
# TEST: Terminal states
# ═══════════════════════════════════════════════════════════════

async def test_supervisor_terminal_success():
    state = _base_state(mission_status="success")
    out = await supervisor_node(state)
    if out.get("next_agent") != "end":
        results.add_fail("test_terminal_success", f"Expected end, got {out.get('next_agent')}")
        return
    results.add_pass("test_terminal_success")


async def test_supervisor_terminal_failed():
    state = _base_state(mission_status="failed")
    out = await supervisor_node(state)
    if out.get("next_agent") != "end":
        results.add_fail("test_terminal_failed", f"Expected end, got {out.get('next_agent')}")
        return
    results.add_pass("test_terminal_failed")


async def test_supervisor_max_iterations():
    state = _base_state(iteration_count=999)
    out = await supervisor_node(state)
    if out.get("next_agent") != "end":
        results.add_fail("test_sup_max_iter", f"Expected end, got {out.get('next_agent')}")
        return
    if out.get("mission_status") != "wait_for_human":
        results.add_fail("test_sup_max_iter", f"Expected wait_for_human, got {out.get('mission_status')}")
        return
    results.add_pass("test_sup_max_iter")


async def test_supervisor_scope_violation():
    state = _base_state(
        discovered_targets={"99.99.99.99": {"services": {}}},
    )
    out = await supervisor_node(state)
    if out.get("next_agent") != "end":
        results.add_fail("test_sup_scope", f"Expected end, got {out.get('next_agent')}")
        return
    if out.get("mission_status") != "failed":
        results.add_fail("test_sup_scope", f"Expected failed, got {out.get('mission_status')}")
        return
    errs = out.get("errors", [])
    if not errs:
        results.add_fail("test_sup_scope", "Expected scope violation error")
        return
    results.add_pass("test_sup_scope")


# ═══════════════════════════════════════════════════════════════
# TEST: History sanitization
# ═══════════════════════════════════════════════════════════════

def test_sanitize_history_filters_bad_roles():
    agent = SupervisorAgent()
    messages = [
        {"role": "system", "content": "should be filtered"},
        {"role": "user", "content": "good"},
        {"role": "assistant", "content": "good"},
        {"role": "tool", "content": "should be filtered"},
        "not a dict",
    ]
    sanitized = agent._sanitize_history(messages)
    roles = [m["role"] for m in sanitized]
    if "system" in roles or "tool" in roles:
        results.add_fail("test_sanitize_history", f"Bad roles not filtered: {roles}")
        return
    if len(sanitized) != 2:
        results.add_fail("test_sanitize_history", f"Expected 2, got {len(sanitized)}")
        return
    results.add_pass("test_sanitize_history")


# ═══════════════════════════════════════════════════════════════
# TEST: Striker failure detection
# ═══════════════════════════════════════════════════════════════

def test_striker_failed_recently_true():
    agent = SupervisorAgent()
    state = _base_state(
        exploited_services=[{"status": "failed", "target": "10.0.0.1"}],
    )
    if not agent._striker_failed_recently(state):
        results.add_fail("test_striker_failed_true", "Should detect failure")
        return
    results.add_pass("test_striker_failed_true")


def test_striker_failed_recently_false():
    agent = SupervisorAgent()
    state = _base_state(
        exploited_services=[{"status": "success", "target": "10.0.0.1"}],
    )
    if agent._striker_failed_recently(state):
        results.add_fail("test_striker_failed_false", "Should not detect failure on success")
        return
    results.add_pass("test_striker_failed_false")


def test_striker_failed_recently_no_session_heuristic():
    agent = SupervisorAgent()
    state = _base_state(
        exploited_services=[],
        active_sessions={},
        agent_log=[
            AgentLogEntry(agent="supervisor", action="route").model_dump(),
            AgentLogEntry(agent="striker", action="run_exploit").model_dump(),
        ],
    )
    if not agent._striker_failed_recently(state):
        results.add_fail("test_striker_no_session_heuristic", "Should detect failure via heuristic")
        return
    results.add_pass("test_striker_no_session_heuristic")


# ═══════════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════════

async def main():
    print("=" * 60)
    print("Supervisor Agent Test Suite")
    print("=" * 60)

    # Decision parsing
    test_parse_decision_clean_json()
    test_parse_decision_markdown_fenced()
    test_parse_decision_embedded_json()
    test_parse_decision_confidence_alias()
    test_parse_decision_expected_outcome_alias()
    test_parse_decision_invalid_json()

    # Fallback decisions
    test_fallback_no_targets()
    test_fallback_has_sessions()
    test_fallback_web_findings_no_librarian()
    test_fallback_web_findings_librarian_ran()
    test_fallback_targets_no_web()
    test_fallback_confidence_low()

    # Guardrails
    test_guardrail_invalid_agent_corrected()
    test_guardrail_force_librarian_before_striker()
    test_guardrail_allows_striker_after_librarian()
    test_guardrail_striker_failure_backtrack()

    # Context summary
    test_context_summary_includes_key_data()
    test_context_summary_empty_state()

    # Terminal states
    await test_supervisor_terminal_success()
    await test_supervisor_terminal_failed()
    await test_supervisor_max_iterations()
    await test_supervisor_scope_violation()

    # History
    test_sanitize_history_filters_bad_roles()

    # Striker failure detection
    test_striker_failed_recently_true()
    test_striker_failed_recently_false()
    test_striker_failed_recently_no_session_heuristic()

    ok = results.summary()
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())
