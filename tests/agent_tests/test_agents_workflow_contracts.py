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
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict

import pytest
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import src.agents.striker as striker_mod
from src.agents.fuzzer import FuzzerAgent
from src.agents.librarian import LibrarianAgent, librarian_node
from src.agents.resident import _extract_resident_updates, resident_node
from src.agents.scout import ScoutAgent
from src.agents.supervisor import SupervisorAgent, supervisor_node
from src.config import get_runtime_config
from src.database.rag.embedding import EmbeddingClient
from src.state.models import SupervisorDecision
from src.utils.agent_runtime import make_tool_message

_requires_api_key = pytest.mark.skipif(
    not os.getenv("OPENROUTER_API_KEY", "").strip(),
    reason="OPENROUTER_API_KEY is not set",
)


def _run(coro):
    return asyncio.run(coro)


def _tool_message(name: str, content: Dict[str, Any], tool_call_id: str = "call-1") -> Dict[str, Any]:
    return make_tool_message(name, tool_call_id, content)


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
        "credential_findings": [],
        "exploit_attempts": [],
        "protocol_observations": [],
        "fuzzing_runs": [],
        "crash_indicators": [],
        "artifacts": [],
        "validations": [],
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
    messages = [
        _tool_message(
            "recon_service_probe",
            {
                "status": "success",
                "invocation": {"target": "192.168.1.10"},
                "evidence": {
                    "services": [
                        {"port": 22, "protocol": "tcp", "service_name": "ssh", "version": "OpenSSH 9.0"}
                    ]
                },
            },
        )
    ]

    out = agent._extract_updates(messages, state)

    assert "192.168.1.10" in out["discovered_targets"]
    assert "192.168.1.0/24" not in out["discovered_targets"]
    services = out["discovered_targets"]["192.168.1.10"]["services"]
    service_22 = services.get("22") or services.get(22)
    assert service_22["service_name"] == "ssh"


def test_scout_discovers_hosts_from_cidr_scope(monkeypatch):
    agent = ScoutAgent()
    state = _base_state()
    state["target_scope"] = ["192.168.1.0/24"]
    messages = [
        _tool_message(
            "recon_host_discovery",
            {
                "status": "success",
                "invocation": {"targets": "192.168.1.0/24"},
                "evidence": {"hosts": ["192.168.1.20", "192.168.1.30", "10.0.0.5"]},
            },
        )
    ]

    out = agent._extract_updates(messages, state)

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
    """A completed resident objective triggers end-state without an LLM call."""
    agent = SupervisorAgent()
    state = _base_state()
    state["active_sessions"] = {"192.168.1.10": {"session_id": 7}}
    state["validations"] = [
        {
            "type": "resident_objective",
            "status": "completed",
            "objective_status": "completed",
            "objective": "Validate shell access",
            "session_id": 7,
        }
    ]

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

    findings = agent._extract_updates(
        [_tool_message("web_content_enum", {"status": "success", "output": gobuster_raw})],
        "http://example.com",
    )

    assert any(f["path"] == "/admin" for f in findings)
    assert any(f["path"] == "/api/v1/users" and f["is_api_endpoint"] for f in findings)
    assert all(f["path"] != "/missing" for f in findings), "404 should be filtered"
    assert all(f["path"] != "/too/deep/path/here" for f in findings), "too-deep should be filtered"


def test_fuzzer_parses_nikto_findings():
    agent = FuzzerAgent()
    nikto_raw = """\
+ /server-status: Apache server-status page found
+ /config.php: Exposed configuration file"""

    findings = agent._extract_updates(
        [_tool_message("web_nikto_scan", {"status": "success", "output": nikto_raw})],
        "http://example.com",
    )

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
        _tool_message(
            "msf_list_sessions",
            {"status": "success", "sessions": {"1": {"type": "shell"}, "2": {"type": "shell"}}},
            "call-0",
        ),
        _tool_message(
            "msf_session_command",
            {
                "status": "success",
                "output": "alice\n",
                "invocation": {"session_id": 1, "command": "whoami"},
            },
            "call-1",
        ),
        _tool_message(
            "msf_session_command",
            {
                "status": "success",
                "output": "uid=0(root) gid=0(root) groups=0(root)",
                "invocation": {"session_id": 2, "command": "id"},
            },
            "call-2",
        ),
        _tool_message(
            "msf_run_post",
            {
                "status": "success",
                "module": "post/linux/gather/enum_system",
                "invocation": {"module_name": "post/linux/gather/enum_system", "options": {"SESSION": 2}},
            },
            "call-3",
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


def test_striker_uses_shared_model_and_key(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "shared-key")
    monkeypatch.setenv("OPENROUTER_EMBEDDING_API_KEY", "embedding-key")
    monkeypatch.setenv("SUPERVISOR_MODEL", "shared-model")
    get_runtime_config.cache_clear()

    captured: Dict[str, Any] = {}

    def fake_try_resolve_openrouter_runtime(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(client=object(), model=kwargs["model"]), None

    monkeypatch.setattr("src.agents.base.try_resolve_openrouter_runtime", fake_try_resolve_openrouter_runtime)
    agent = striker_mod.StrikerAgent()

    assert agent._client is not None
    assert captured["api_key"] == "shared-key"
    assert captured["model"] == "shared-model"
    assert captured["base_url"] == get_runtime_config().openrouter_base_url
    get_runtime_config.cache_clear()


def test_embedding_client_prefers_embedding_specific_key(monkeypatch):
    cfg = replace(
        get_runtime_config(),
        openrouter_api_key="shared-key",
        openrouter_embedding_api_key="embedding-key",
        embedding_provider="openrouter",
    )
    captured: Dict[str, Any] = {}

    class FakeOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr("src.database.rag.embedding.OpenAI", FakeOpenAI)
    client = EmbeddingClient(config=cfg)
    client._get_sync_openrouter_client()

    assert captured["api_key"] == "embedding-key"


def test_embedding_client_falls_back_to_shared_key(monkeypatch):
    cfg = replace(
        get_runtime_config(),
        openrouter_api_key="shared-key",
        openrouter_embedding_api_key="",
        embedding_provider="openrouter",
    )
    captured: Dict[str, Any] = {}

    class FakeOpenAI:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr("src.database.rag.embedding.OpenAI", FakeOpenAI)
    client = EmbeddingClient(config=cfg)
    client._get_sync_openrouter_client()

    assert captured["api_key"] == "shared-key"


def test_striker_supports_llm_model_fallback(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "shared-key")
    monkeypatch.delenv("SUPERVISOR_MODEL", raising=False)
    monkeypatch.setenv("LLM_MODEL", "shared-model")
    get_runtime_config.cache_clear()

    captured: Dict[str, Any] = {}

    def fake_try_resolve_openrouter_runtime(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(client=object(), model=kwargs["model"]), None

    monkeypatch.setattr("src.agents.base.try_resolve_openrouter_runtime", fake_try_resolve_openrouter_runtime)
    agent = striker_mod.StrikerAgent()

    assert agent._client is not None
    assert captured["api_key"] == "shared-key"
    assert captured["model"] == "shared-model"
    get_runtime_config.cache_clear()


def test_striker_search_only_run_still_records_findings():
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "services": {"80": {"service_name": "http", "version": "Werkzeug 3.1.8"}}
        }
    }
    context = "TARGET INTELLIGENCE:\n- 80/tcp http\n\nCANDIDATE PATHS:\n- none"
    messages = [
        _tool_message(
            "msf_search_modules",
            {
                "status": "success",
                "result": ["multi/http/werkzeug_debug_rce"],
                "invocation": {"search_term": "werkzeug"},
            },
            "c1",
        )
    ]

    out = striker_mod.StrikerAgent()._extract_updates(messages, state, context)
    log_entry = out["agent_log"][0].model_dump()

    assert log_entry["findings"]["status"] == "no_candidate"
    assert log_entry["findings"]["candidate_modules"] == ["multi/http/werkzeug_debug_rce"]
    assert log_entry["findings"]["search_terms"] == ["werkzeug"]
    assert "TARGET INTELLIGENCE:" in log_entry["reasoning"]


def test_striker_aborted_execution_records_selected_module():
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "services": {"80": {"service_name": "http", "version": "Werkzeug 3.1.8"}}
        }
    }
    context = "TARGET INTELLIGENCE:\n- 80/tcp http\n\nCANDIDATE PATHS:\n- none"
    messages = [
        _tool_message(
            "msf_run_exploit",
            {
                "status": "aborted",
                "message": "Execution blocked pending manual approval.",
                "invocation": {
                    "module_name": "multi/http/werkzeug_debug_rce",
                    "options": {"RHOSTS": "192.168.1.10", "RPORT": 80},
                },
            },
            "c1",
        )
    ]

    out = striker_mod.StrikerAgent()._extract_updates(messages, state, context)
    log_entry = out["agent_log"][0].model_dump()

    assert log_entry["findings"]["status"] == "approval_blocked"
    assert log_entry["findings"]["module"] == "multi/http/werkzeug_debug_rce"
    assert log_entry["findings"]["selected_module"] == "multi/http/werkzeug_debug_rce"
    assert log_entry["findings"]["executed_tool"] == "msf_run_exploit"
    assert log_entry["findings"]["executed_module"] == "multi/http/werkzeug_debug_rce"
    assert log_entry["findings"]["session_opened"] is False
    assert "Execution blocked pending manual approval." in log_entry["reasoning"]


def test_striker_keeps_selected_module_separate_from_validation_tool():
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "services": {"80": {"service_name": "http", "version": "Werkzeug 3.1.8"}}
        }
    }
    context = "TARGET INTELLIGENCE:\n- 80/tcp http\n\nCANDIDATE PATHS:\n- none"
    messages = [
        _tool_message(
            "msf_get_module_options",
            {
                "status": "success",
                "options": [{"name": "RHOSTS", "required": True}],
                "invocation": {
                    "module_type": "exploit",
                    "module_name": "multi/http/werkzeug_debug_rce",
                },
            },
            "c1",
        ),
        _tool_message(
            "web_sqlmap_scan",
            {
                "status": "success",
                "summary": "web_sqlmap_scan completed with exit code 0",
                "validation": {
                    "outcome": "inconclusive",
                    "reason": "web_sqlmap_scan completed, but produced no structured validation claim.",
                },
                "invocation": {"url": "http://192.168.1.10/login"},
            },
            "c2",
        ),
    ]

    out = striker_mod.StrikerAgent()._extract_updates(messages, state, context)
    log_entry = out["agent_log"][0].model_dump()
    findings = log_entry["findings"]

    assert findings["selected_module"] == "multi/http/werkzeug_debug_rce"
    assert findings["module"] == "multi/http/werkzeug_debug_rce"
    assert findings["executed_tool"] == "web_sqlmap_scan"
    assert findings["executed_module"] is None
    assert findings["status"] == "no_candidate"
    assert findings["validation_outcome"] == "inconclusive"
    assert findings["session_opened"] is False
    assert not out.get("critical_findings")


def test_striker_fallback_without_positive_validation_is_not_promoted():
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "services": {"80": {"service_name": "http", "version": "Werkzeug 3.1.8"}}
        }
    }
    context = "TARGET INTELLIGENCE:\n- 80/tcp http\n\nCANDIDATE PATHS:\n- none"
    messages = [
        _tool_message(
            "system_execute_command",
            {
                "status": "success",
                "summary": "system_execute_command completed with exit code 0",
                "validation": {
                    "outcome": "inconclusive",
                    "reason": "system_execute_command completed, but produced no structured validation claim.",
                },
                "invocation": {"command": "curl -I http://192.168.1.10/login"},
            },
            "c1",
        )
    ]

    out = striker_mod.StrikerAgent()._extract_updates(messages, state, context)
    log_entry = out["agent_log"][0].model_dump()
    findings = log_entry["findings"]

    assert findings["status"] == "no_candidate"
    assert findings["executed_tool"] == "system_execute_command"
    assert findings["executed_module"] is None
    assert findings["validation_outcome"] == "inconclusive"
    assert findings["session_opened"] is False
    assert not out.get("active_sessions")
    assert not out.get("critical_findings")


def test_striker_positive_fallback_validation_uses_validated_no_session_status():
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "services": {"22": {"service_name": "ssh", "version": "OpenSSH 9.6"}}
        }
    }
    context = "TARGET INTELLIGENCE:\n- 22/tcp ssh\n\nCANDIDATE PATHS:\n- none"
    messages = [
        _tool_message(
            "access_hydra_attack",
            {
                "status": "success",
                "summary": "access_hydra_attack completed with exit code 0",
                "validation": {"outcome": "positive", "reason": "Hydra confirmed at least one valid credential."},
                "invocation": {"target": "192.168.1.10", "service": "ssh"},
            },
            "c1",
        )
    ]

    out = striker_mod.StrikerAgent()._extract_updates(messages, state, context)
    findings = out["agent_log"][0].model_dump()["findings"]

    assert findings["status"] == "validated_no_session"
    assert findings["validation_outcome"] == "positive"
    assert findings["executed_tool"] == "access_hydra_attack"
    assert findings["executed_module"] is None
    assert findings["session_opened"] is False
    assert out.get("critical_findings")


def test_striker_verified_session_sets_session_opened():
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "services": {"80": {"service_name": "http", "version": "Apache 2.4.57"}}
        }
    }
    context = "TARGET INTELLIGENCE:\n- 80/tcp http\n\nCANDIDATE PATHS:\n- none"
    messages = [
        _tool_message(
            "msf_run_exploit",
            {
                "status": "success",
                "module": "multi/http/apache_demo",
                "session_id": 7,
                "invocation": {
                    "module_name": "multi/http/apache_demo",
                    "options": {"RHOSTS": "192.168.1.10", "RPORT": 80},
                },
            },
            "c1",
        ),
        _tool_message(
            "msf_list_sessions",
            {
                "status": "success",
                "sessions": {"7": {"target_host": "192.168.1.10"}},
            },
            "c2",
        ),
    ]

    out = striker_mod.StrikerAgent()._extract_updates(messages, state, context)
    log_entry = out["agent_log"][0].model_dump()
    findings = log_entry["findings"]

    assert findings["status"] == "session_opened"
    assert findings["session_opened"] is True
    assert findings["executed_tool"] == "msf_run_exploit"
    assert findings["executed_module"] == "multi/http/apache_demo"
    assert out["active_sessions"]["192.168.1.10"]["session_id"] == 7


def test_striker_records_module_introspection_failure_before_validation_pivot():
    state = _base_state()
    state["discovered_targets"] = {
        "192.168.1.10": {
            "services": {"80": {"service_name": "http", "version": "Werkzeug 3.1.8"}}
        }
    }
    context = "TARGET INTELLIGENCE:\n- 80/tcp http\n\nCANDIDATE PATHS:\n- none"
    messages = [
        _tool_message(
            "msf_search_modules",
            {
                "status": "success",
                "result": ["multi/http/werkzeug_debug_rce"],
                "invocation": {"search_term": "werkzeug"},
            },
            "c1",
        ),
        _tool_message(
            "msf_get_module_info",
            {
                "status": "error",
                "message": "Unexpected error retrieving module info: 'bool' object is not subscriptable",
                "invocation": {
                    "module_type": "exploit",
                    "module_name": "multi/http/werkzeug_debug_rce",
                },
            },
            "c2",
        ),
        _tool_message(
            "web_sqlmap_scan",
            {
                "status": "success",
                "summary": "web_sqlmap_scan completed with exit code 0",
                "validation": {
                    "outcome": "inconclusive",
                    "reason": "web_sqlmap_scan completed, but produced no structured validation claim.",
                },
                "invocation": {"url": "http://192.168.1.10/login"},
            },
            "c3",
        ),
    ]

    out = striker_mod.StrikerAgent()._extract_updates(messages, state, context)
    log_entry = out["agent_log"][0].model_dump()
    findings = log_entry["findings"]

    assert findings["status"] == "execution_error"
    assert findings["module_inspection_failed"] is True
    assert "bool' object is not subscriptable" in findings["module_inspection_error"]
    assert "Pivoted to fallback validation" in log_entry["reasoning"]
    assert not out.get("critical_findings")


# ---------------------------------------------------------------------------
# Live LLM integration tests — real ChatOpenAI calls
# ---------------------------------------------------------------------------


@pytest.mark.live
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


@pytest.mark.live
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


@pytest.mark.live
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
