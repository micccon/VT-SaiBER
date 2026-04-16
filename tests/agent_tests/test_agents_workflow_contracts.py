"""
Agent workflow contract tests.

Unit tests validate deterministic agent logic — no LLM or MCP required.
Live tests validate real agent behaviour with an actual ChatOpenAI call and
are skipped gracefully when OPENROUTER_API_KEY is not set.

Run unit tests only:
    ./saiber_env/bin/python -m pytest tests/agent_tests/test_agents_workflow_contracts.py -m "not live" -v

Run all tests including live LLM:
    ./saiber_env/bin/python -m pytest tests/agent_tests/test_agents_workflow_contracts.py -v -s
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any, Dict

import pytest
from langchain_core.messages import AIMessage, ToolMessage

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.agents.fuzzer import FuzzerAgent
from src.agents.librarian import LibrarianAgent, librarian_node
from src.agents.resident import _extract_resident_updates, resident_node
from src.agents.scout import ScoutAgent
from src.agents.supervisor import SupervisorAgent, supervisor_node
from src.config import get_runtime_config
from src.state.models import ServiceInfo, SupervisorDecision

_requires_api_key = pytest.mark.skipif(
    not os.getenv("OPENROUTER_API_KEY", "").strip(),
    reason="OPENROUTER_API_KEY is not set",
)


def _run(coro):
    return asyncio.run(coro)


def _base_state() -> Dict[str, Any]:
    return {
        "mission_goal": "Exploit target and gain initial access",
        "mission_id": "test-mission",
        "mission_status": "active",
        "current_agent": "supervisor",
        "next_agent": None,
        "iteration_count": 0,
        "target_scope": ["192.168.1.10"],
        "discovered_targets": {},
        "ot_discovery": {},
        "web_findings": [],
        "active_sessions": {},
        "exploited_services": [],
        "research_cache": {},
        "intelligence_findings": [],
        "supervisor_messages": [],
        "supervisor_expectations": {},
        "agent_log": [],
        "critical_findings": [],
        "errors": [],
    }


# ---------------------------------------------------------------------------
# Scout — scope resolution (MCP stubbed, no LLM)
# ---------------------------------------------------------------------------


def test_scout_scans_direct_host_scope(monkeypatch):
    agent = ScoutAgent()
    state = _base_state()

    async def fake_discover_services(target):
        assert target == "192.168.1.10"
        return {22: ServiceInfo(port=22, service_name="ssh", version="OpenSSH 9.0")}

    monkeypatch.setattr(agent, "_discover_services", fake_discover_services)
    out = _run(agent.call_llm(state))

    assert "192.168.1.10" in out["discovered_targets"]
    assert "192.168.1.0/24" not in out["discovered_targets"]


def test_scout_discovers_hosts_from_cidr_scope(monkeypatch):
    agent = ScoutAgent()
    state = _base_state()
    state["target_scope"] = ["192.168.1.0/24"]

    async def fake_discover_hosts(scope_entry):
        assert scope_entry == "192.168.1.0/24"
        return ["192.168.1.20", "192.168.1.30"]

    async def fake_discover_services(target):
        return {80: ServiceInfo(port=80, service_name="http", version=f"Apache for {target}")}

    monkeypatch.setattr(agent, "_discover_hosts", fake_discover_hosts)
    monkeypatch.setattr(agent, "_discover_services", fake_discover_services)
    out = _run(agent.call_llm(state))

    assert sorted(out["discovered_targets"].keys()) == ["192.168.1.20", "192.168.1.30"]


def test_scout_returns_error_when_no_scope():
    agent = ScoutAgent()
    state = _base_state()
    state["target_scope"] = []
    out = _run(agent.call_llm(state))
    assert out.get("errors"), "scout must report an error when target_scope is empty"


# ---------------------------------------------------------------------------
# Supervisor — guardrail logic (no LLM call)
# ---------------------------------------------------------------------------


def test_supervisor_forces_librarian_before_striker():
    agent = SupervisorAgent()
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "services": {"80": {"service_name": "http", "version": "Apache 2.4.57"}}
        }
    }

    decision, reason = agent._apply_guardrails(
        state,
        SupervisorDecision(
            next_agent="striker",
            rationale="Go exploit now",
            specific_goal="Exploit the web service",
            confidence_score=0.9,
        ),
    )

    assert decision.next_agent == "librarian"
    assert reason == "forced-librarian-before-striker"


def test_supervisor_backtracks_after_failed_striker():
    agent = SupervisorAgent()
    state = _base_state()
    state["discovered_targets"] = {"192.168.1.10": {"services": {}}}
    state["exploited_services"] = [{"status": "failed"}]
    state["agent_log"] = [{"agent": "striker", "action": "run_exploit"}]

    decision, reason = agent._apply_guardrails(
        state,
        SupervisorDecision(
            next_agent="scout",
            rationale="Try something else",
            specific_goal="Continue mission",
            confidence_score=0.4,
        ),
    )

    assert decision.next_agent == "librarian"
    assert reason == "striker-failure-backtrack"


def test_supervisor_terminal_success_shortcut():
    """Active sessions + resident in log triggers end-state without an LLM call."""
    agent = SupervisorAgent()
    state = _base_state()
    state["active_sessions"] = {"192.168.1.10": {"session_id": 7}}
    state["agent_log"] = [{"agent": "resident", "action": "post_exploitation"}]

    out = _run(agent.call_llm(state))

    assert out["next_agent"] == "end"
    assert out["mission_status"] == "success"


def test_supervisor_caps_iterations():
    """Iteration cap must redirect to wait_for_human without calling LLM."""
    agent = SupervisorAgent()
    state = _base_state()
    state["iteration_count"] = agent.config.max_iterations + 1

    out = _run(agent.call_llm(state))

    assert out["next_agent"] == "end"
    assert out["mission_status"] == "wait_for_human"


# ---------------------------------------------------------------------------
# Fuzzer — output parser (no LLM, no MCP)
# ---------------------------------------------------------------------------


def test_fuzzer_parses_gobuster_findings():
    agent = FuzzerAgent()
    gobuster_raw = """\
/admin (Status: 301) [Size: 0]
/api/v1/users (Status: 200) [Size: 20]
/too/deep/path/here (Status: 200) [Size: 10]
/missing (Status: 404) [Size: 10]"""

    findings = agent._parse_gobuster_output(gobuster_raw, "http://example.com")

    assert any(f["path"] == "/admin" for f in findings)
    assert any(f["path"] == "/api/v1/users" and f["is_api_endpoint"] for f in findings)
    assert all(f["path"] != "/missing" for f in findings), "404 should be filtered"
    assert all(f["path"] != "/too/deep/path/here" for f in findings), "too-deep should be filtered"


def test_fuzzer_parses_nikto_findings():
    agent = FuzzerAgent()
    nikto_raw = """\
+ /server-status: Apache server-status page found
+ /config.php: Exposed configuration file"""

    findings = agent._parse_nikto_output(nikto_raw, "http://example.com")

    assert any(f["path"] == "/config.php" for f in findings)
    assert any(f["path"] == "/server-status" for f in findings)


# ---------------------------------------------------------------------------
# Resident — message-parsing logic (no LLM, no MCP)
# ---------------------------------------------------------------------------


def test_resident_keeps_session_findings_separate():
    state = _base_state()
    state["active_sessions"] = {
        "10.0.0.10": {"session_id": 1, "module": "exploit/a"},
        "10.0.0.20": {"session_id": 2, "module": "exploit/b"},
    }

    messages = [
        AIMessage(
            content="tool calls",
            tool_calls=[
                {"id": "call-1", "name": "msf_send_session_command", "args": {"session_id": 1, "command": "whoami"}},
                {"id": "call-2", "name": "msf_send_session_command", "args": {"session_id": 2, "command": "id"}},
                {"id": "call-3", "name": "msf_run_post_module", "args": {"session_id": 2, "module_name": "post/linux/gather/enum_system"}},
            ],
        ),
        ToolMessage(
            tool_call_id="call-1",
            name="msf_send_session_command",
            content='{"status":"success","output":"alice\\n"}',
        ),
        ToolMessage(
            tool_call_id="call-2",
            name="msf_send_session_command",
            content='{"status":"success","output":"uid=0(root) gid=0(root) groups=0(root)"}',
        ),
        ToolMessage(
            tool_call_id="call-3",
            name="msf_run_post_module",
            content='{"status":"success","module":"post/linux/gather/enum_system","options":{"SESSION":2}}',
        ),
    ]

    out = _extract_resident_updates(messages, state)
    sessions = out["active_sessions"]

    assert sessions["10.0.0.10"]["user_context"] == "alice"
    assert "privilege" not in sessions["10.0.0.10"]
    assert sessions["10.0.0.20"]["privilege"] == "root"
    assert sessions["10.0.0.20"]["successful_post_modules"] == ["post/linux/gather/enum_system"]


def test_resident_returns_error_when_no_sessions():
    state = _base_state()
    out = _run(resident_node(state))
    assert out.get("errors"), "resident must return errors when active_sessions is empty"
    assert out["errors"][0].error_type == "ValidationError"


# ---------------------------------------------------------------------------
# Live LLM integration tests — real ChatOpenAI calls
# ---------------------------------------------------------------------------


@_requires_api_key
def test_supervisor_live_routes_to_scout_with_no_targets():
    """Real LLM: without any discovered targets, supervisor must send scout first."""
    get_runtime_config.cache_clear()
    state = _base_state()

    out = _run(supervisor_node(state))

    valid_agents = {"scout", "fuzzer", "librarian", "striker", "resident", "end"}
    assert "next_agent" in out
    assert out["next_agent"] in valid_agents
    assert out["next_agent"] == "scout", (
        f"expected scout when discovered_targets is empty, got: {out['next_agent']}"
    )
    assert out["supervisor_expectations"].get("specific_goal"), "specific_goal must not be empty"

    print(f"\n[live] supervisor → {out['next_agent']}")
    print(f"[live] goal: {out['supervisor_expectations'].get('specific_goal')}")
    print(f"[live] confidence: {out['supervisor_expectations'].get('confidence_score')}")


@_requires_api_key
def test_librarian_live_produces_structured_brief():
    """Real LLM: librarian must return a populated research_cache and intelligence_findings."""
    get_runtime_config.cache_clear()
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "services": {"80": {"service_name": "http", "version": "Apache 2.4.57"}}
        }
    }

    out = _run(librarian_node(state))

    assert "research_cache" in out
    assert len(out["research_cache"]) > 0, "research_cache must not be empty"

    cache_entry = next(iter(out["research_cache"].values()))
    assert "summary" in cache_entry, "cache entry must have a summary"
    assert isinstance(cache_entry.get("confidence"), float), "confidence must be a float"

    assert "intelligence_findings" in out
    assert len(out["intelligence_findings"]) > 0
    finding = out["intelligence_findings"][0]
    assert "description" in finding

    print(f"\n[live] librarian summary  : {cache_entry.get('summary', '')[:120]}")
    print(f"[live] librarian confidence: {cache_entry.get('confidence')}")
    print(f"[live] is_fallback         : {cache_entry.get('is_fallback')}")
    print(f"[live] citations           : {cache_entry.get('citations', [])}")


@_requires_api_key
def test_librarian_live_llm_path_taken_when_api_key_present():
    """With a valid API key the librarian must use the LLM path, not the no-client fallback."""
    get_runtime_config.cache_clear()
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "services": {
                "22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"},
                "80": {"service_name": "http", "version": "Apache 2.4.57"},
            }
        }
    }

    agent = LibrarianAgent()

    # _llm must be wired up when the API key is set
    assert agent._llm is not None, "_llm must not be None when OPENROUTER_API_KEY is present"

    out = _run(agent.call_llm(state))
    cache_entry = next(iter(out["research_cache"].values()))

    # The two deterministic fallback strings are produced only when _llm is None or an
    # exception fires before the LLM responds.  Neither should appear on a live path.
    summary = cache_entry.get("summary", "")
    assert not summary.startswith("Fallback intelligence brief for:"), (
        "got the _llm=None fallback — API key may not have been picked up"
    )
    assert not summary.startswith("Research unavailable;"), (
        "got the exception-path fallback — LLM call likely failed"
    )
    assert summary, "summary must not be empty on the live path"

    print(f"\n[live] librarian summary: {summary[:120]}")
    print(f"[live] confidence: {cache_entry.get('confidence')}  citations: {cache_entry.get('citations', [])}")
