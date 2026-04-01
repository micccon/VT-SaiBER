"""
Supervisor routing integration tests.

Pytest tests exercise real SupervisorAgent LLM calls and real worker agent
nodes.  Tests that require OPENROUTER_API_KEY are skipped gracefully when
the key is absent so the unit-test suite stays green in CI.

Run unit (guardrail) tests only:
    ./saiber_env/bin/python -m pytest tests/agent_tests/test_supervisor_routing_demo.py -m "not live" -v

Run all tests including live LLM:
    ./saiber_env/bin/python -m pytest tests/agent_tests/test_supervisor_routing_demo.py -v -s

Interactive CLI demo (always live):
    PYTHONPATH=. ./saiber_env/bin/python tests/agent_tests/test_supervisor_routing_demo.py \\
        --query "Exploit the discovered Apache web service and gain a shell" \\
        --scenario web

    PYTHONPATH=. ./saiber_env/bin/python tests/agent_tests/test_supervisor_routing_demo.py \\
        --query "Enumerate the active session and assess privilege escalation paths" \\
        --scenario session --json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv

load_dotenv(ROOT / ".env")

from src.agents.fuzzer import fuzzer_node
from src.agents.librarian import librarian_node
from src.agents.resident import resident_node
from src.agents.scout import scout_node
from src.agents.striker import striker_node
from src.agents.supervisor import SupervisorAgent, supervisor_node
from src.config import get_runtime_config
from src.main import build_initial_state
from src.state.cyber_state import CyberState
from src.state.models import SupervisorDecision
from src.utils.parsers import extract_json_payload


TARGET_IP = "192.168.1.10"
VALID_SCENARIOS = {"bare", "discovered", "web", "researched", "session", "failed_striker"}
VALID_AGENTS = {"scout", "fuzzer", "librarian", "striker", "resident", "end"}

_requires_api_key = pytest.mark.skipif(
    not os.getenv("OPENROUTER_API_KEY", "").strip(),
    reason="OPENROUTER_API_KEY is not set",
)

# ---------------------------------------------------------------------------
# State builders
# ---------------------------------------------------------------------------


def build_scenario_state(query: str, scope: str, scenario: str) -> CyberState:
    if scenario not in VALID_SCENARIOS:
        raise ValueError(f"Unknown scenario '{scenario}'. Valid: {sorted(VALID_SCENARIOS)}")

    state = build_initial_state(
        mission_goal=query,
        target_scope=[scope],
        mission_id="test-supervisor-routing",
    )

    if scenario in {"discovered", "web", "researched", "session", "failed_striker"}:
        state["discovered_targets"] = {
            TARGET_IP: {
                "ip_address": TARGET_IP,
                "ports": [80],
                "services": {"80": {"service_name": "http", "version": "Apache 2.4.57"}},
                "os_guess": "Linux",
            }
        }

    if scenario in {"web", "researched", "failed_striker"}:
        state["web_findings"] = [
            {
                "url": f"http://{TARGET_IP}/admin",
                "path": "/admin",
                "status_code": 200,
                "is_api_endpoint": False,
                "is_interesting": True,
                "rationale": "Test web entry point",
            }
        ]

    if scenario == "researched":
        state["agent_log"] = [{"agent": "librarian", "action": "research_brief"}]
        state["research_cache"] = {
            "demo_apache_research": {
                "summary": "Prior research indicates a credible exploit path.",
                "citations": ["https://example.com/demo"],
                "confidence": 0.85,
                "is_fallback": False,
            }
        }

    if scenario == "session":
        # Realistic session context: discovered targets must already be present
        # so the LLM understands a prior exploitation phase completed.
        state["discovered_targets"] = {
            TARGET_IP: {
                "ip_address": TARGET_IP,
                "ports": [80],
                "services": {"80": {"service_name": "http", "version": "Apache 2.4.57"}},
                "os_guess": "Linux",
            }
        }
        state["agent_log"] = [
            {"agent": "librarian", "action": "research_brief"},
            {"agent": "striker", "action": "run_exploit"},
        ]
        state["active_sessions"] = {
            TARGET_IP: {
                "session_id": 7,
                "module": "exploit/linux/http/demo",
                "established_at": "2026-03-18T00:00:00",
            }
        }

    if scenario == "failed_striker":
        state["exploited_services"] = [
            {"target": TARGET_IP, "module": "exploit/demo", "status": "failed"}
        ]
        state["agent_log"] = [{"agent": "striker", "action": "run_exploit"}]

    return state


def merge_state(state: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
    merged = {**state, **update}
    for key in ("agent_log", "errors", "critical_findings", "web_findings", "osint_findings"):
        if isinstance(state.get(key), list) and isinstance(update.get(key), list):
            merged[key] = list(state[key]) + list(update[key])
    for key in ("discovered_targets", "active_sessions", "research_cache", "supervisor_expectations"):
        if isinstance(state.get(key), dict) and isinstance(update.get(key), dict):
            merged[key] = {**state[key], **update[key]}
    return merged


def extract_llm_suggestion(supervisor_update: Dict[str, Any]) -> str:
    messages = supervisor_update.get("supervisor_messages", []) or []
    if not messages:
        return ""
    last = messages[-1]
    if not isinstance(last, dict):
        return ""
    try:
        payload = extract_json_payload(last.get("content", ""))
    except Exception:
        return ""
    return str(payload.get("next_agent", ""))


# ---------------------------------------------------------------------------
# Guardrail unit tests — deterministic, no LLM call made
# ---------------------------------------------------------------------------


def test_supervisor_guardrail_forces_librarian_before_striker():
    """Guardrail fires deterministically: librarian must run before striker."""
    agent = SupervisorAgent()
    state = build_scenario_state("Exploit Apache", TARGET_IP, "web")

    decision, reason = agent._apply_guardrails(
        state,
        SupervisorDecision(
            next_agent="striker",
            rationale="go exploit",
            specific_goal="exploit http",
            confidence_score=0.9,
        ),
    )

    assert decision.next_agent == "librarian"
    assert reason == "forced-librarian-before-striker"


def test_supervisor_guardrail_backtracks_after_failed_striker():
    """Guardrail redirects away from scout/striker after a failed exploit attempt."""
    agent = SupervisorAgent()
    state = build_scenario_state("Exploit Apache", TARGET_IP, "failed_striker")

    decision, reason = agent._apply_guardrails(
        state,
        SupervisorDecision(
            next_agent="scout",
            rationale="retry",
            specific_goal="continue",
            confidence_score=0.4,
        ),
    )

    assert decision.next_agent == "librarian"
    assert reason == "striker-failure-backtrack"


def test_supervisor_terminal_success_shortcut():
    """With sessions + resident already run, supervisor shortcuts to end without LLM."""
    agent = SupervisorAgent()
    state = build_scenario_state("Gain access", TARGET_IP, "bare")
    state["active_sessions"] = {"192.168.1.10": {"session_id": 7}}
    state["agent_log"] = [{"agent": "resident", "action": "post_exploitation"}]

    out = asyncio.run(agent.call_llm(state))

    assert out["next_agent"] == "end"
    assert out["mission_status"] == "success"


# ---------------------------------------------------------------------------
# Live LLM integration tests — real SupervisorAgent + real ChatOpenAI call
# ---------------------------------------------------------------------------


@_requires_api_key
def test_supervisor_live_routes_bare_state_to_scout():
    """Real LLM: with no targets discovered, supervisor must route to scout."""
    get_runtime_config.cache_clear()
    state = build_scenario_state(
        "Gain initial access to the test target", TARGET_IP, "bare"
    )

    out = asyncio.run(supervisor_node(state))

    assert "next_agent" in out
    assert out["next_agent"] in VALID_AGENTS
    assert out["next_agent"] == "scout", (
        f"expected scout for bare state, LLM returned: {out['next_agent']}"
    )
    assert "supervisor_expectations" in out
    assert out["supervisor_expectations"].get("specific_goal"), "specific_goal must be non-empty"

    print(f"\n[live] supervisor → {out['next_agent']}")
    print(f"[live] goal: {out['supervisor_expectations'].get('specific_goal')}")
    print(f"[live] confidence: {out['supervisor_expectations'].get('confidence_score')}")


@_requires_api_key
def test_supervisor_live_never_routes_to_striker_before_librarian():
    """Real LLM: guardrail + LLM combined — striker must not be returned before librarian runs."""
    get_runtime_config.cache_clear()
    state = build_scenario_state(
        "Exploit the Apache web service and gain a shell", TARGET_IP, "web"
    )

    out = asyncio.run(supervisor_node(state))

    assert "next_agent" in out
    assert out["next_agent"] in VALID_AGENTS
    assert out["next_agent"] != "striker", (
        "supervisor must not jump to striker before librarian has run "
        f"(got: {out['next_agent']})"
    )

    llm_pick = extract_llm_suggestion(out)
    print(f"\n[live] LLM picked: {llm_pick or 'n/a'} → final routed: {out['next_agent']}")
    print(f"[live] goal: {out.get('supervisor_expectations', {}).get('specific_goal')}")


@_requires_api_key
def test_supervisor_live_session_state_returns_valid_response():
    """
    Real LLM: with an active session, supervisor must return a complete, valid response.

    We assert structure and guardrails — not a specific agent — because the
    correct routing (resident) requires a sufficiently capable model. The test
    prints what the model chose so you can validate quality during development.
    """
    get_runtime_config.cache_clear()
    state = build_scenario_state(
        "Enumerate the active session and assess privilege escalation paths",
        TARGET_IP,
        "session",
    )

    out = asyncio.run(supervisor_node(state))

    assert "next_agent" in out, "supervisor must always return next_agent"
    assert out["next_agent"] in VALID_AGENTS, (
        f"next_agent must be one of {VALID_AGENTS}, got: {out['next_agent']}"
    )
    assert "supervisor_expectations" in out
    assert out["supervisor_expectations"].get("specific_goal"), "specific_goal must not be empty"
    assert "supervisor_messages" in out, "supervisor must persist conversation history"

    # Ideal routing with a capable model is "resident"; log what we got.
    print(f"\n[live] supervisor → {out['next_agent']} (ideal: resident)")
    print(f"[live] goal: {out['supervisor_expectations'].get('specific_goal')}")
    print(f"[live] confidence: {out['supervisor_expectations'].get('confidence_score')}")


@_requires_api_key
def test_supervisor_live_full_routing_cycle():
    """Real LLM end-to-end: supervisor routes → real librarian runs → state is enriched."""
    get_runtime_config.cache_clear()
    state = build_scenario_state(
        "Research and exploit Apache 2.4.57 vulnerabilities", TARGET_IP, "web"
    )

    # Step 1: supervisor decides which agent to run
    supervisor_out = asyncio.run(supervisor_node(state))
    state = merge_state(state, supervisor_out)

    assert supervisor_out["next_agent"] in VALID_AGENTS
    routed_to = supervisor_out["next_agent"]
    print(f"\n[live] supervisor → {routed_to}")

    # Step 2: if routed to librarian, run the real librarian agent
    if routed_to == "librarian":
        librarian_out = asyncio.run(librarian_node(state))
        state = merge_state(state, librarian_out)

        assert "research_cache" in librarian_out
        assert len(librarian_out["research_cache"]) > 0
        cache_entry = next(iter(librarian_out["research_cache"].values()))
        assert "summary" in cache_entry

        print(f"[live] librarian summary: {cache_entry.get('summary', '')[:120]}")
        print(f"[live] librarian confidence: {cache_entry.get('confidence')}")

    # Whether librarian ran or not, state must always contain valid structure
    assert state.get("mission_status") in {"active", "success", "failed", "wait_for_human"}


# ---------------------------------------------------------------------------
# CLI demo harness — always uses real agents
# ---------------------------------------------------------------------------

_AGENT_NODES = {
    "scout": scout_node,
    "fuzzer": fuzzer_node,
    "librarian": librarian_node,
    "striker": striker_node,
    "resident": resident_node,
}


async def run_live_demo(query: str, scope: str, scenario: str) -> Dict[str, Any]:
    get_runtime_config.cache_clear()

    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "OPENROUTER_API_KEY is required. Set it in your environment or .env."
        )

    for proxy_key in (
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
        "http_proxy", "https_proxy", "all_proxy",
    ):
        os.environ.pop(proxy_key, None)

    state = build_scenario_state(query, scope, scenario)

    supervisor_out = await supervisor_node(state)
    state = merge_state(state, supervisor_out)

    final_agent = supervisor_out.get("next_agent", "end")
    worker_out: Dict[str, Any] = {}
    if final_agent in _AGENT_NODES:
        worker_out = await _AGENT_NODES[final_agent](state)
        state = merge_state(state, worker_out)

    return {
        "query": query,
        "scope": scope,
        "scenario": scenario,
        "llm_suggested_agent": extract_llm_suggestion(supervisor_out),
        "final_routed_agent": final_agent,
        "supervisor_expectations": supervisor_out.get("supervisor_expectations", {}),
        "mission_status": state.get("mission_status", "active"),
        "worker_output_keys": list(worker_out.keys()),
        "final_state": state,
    }


def _print_result(result: Dict[str, Any]) -> None:
    print("\nSupervisor Live Routing Result")
    print(f"  Query    : {result['query']}")
    print(f"  Scenario : {result['scenario']}")
    print(f"  LLM pick : {result['llm_suggested_agent'] or 'n/a'}")
    print(f"  Routed to: {result['final_routed_agent']}")
    exp = result.get("supervisor_expectations") or {}
    print(f"  Goal     : {exp.get('specific_goal', 'n/a')}")
    print(f"  Confidence: {exp.get('confidence_score', 'n/a')}")
    print(f"  Status   : {result['mission_status']}")
    if result.get("worker_output_keys"):
        print(f"  Worker keys: {result['worker_output_keys']}")


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Run a live supervisor + worker agent routing demo")
    p.add_argument("--query", required=True, help="Mission goal / stakeholder query")
    p.add_argument("--scope", default=TARGET_IP, help="Target scope entry")
    p.add_argument(
        "--scenario",
        choices=sorted(VALID_SCENARIOS),
        default="bare",
        help="Pre-seeded CyberState scenario",
    )
    p.add_argument("--json", action="store_true", help="Print full result as JSON")
    return p


async def _amain() -> int:
    load_dotenv(ROOT / ".env", override=True)
    get_runtime_config.cache_clear()
    args = _build_arg_parser().parse_args()
    result = await run_live_demo(args.query, args.scope, args.scenario)
    _print_result(result)
    if args.json:
        print("\nFull JSON:")
        print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_amain()))
