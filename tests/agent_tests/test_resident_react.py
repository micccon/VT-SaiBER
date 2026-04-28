#!/usr/bin/env python3
"""Resident agent contract tests for the shared OpenRouter/tool runtime."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import src.agents.base as base_mod
import src.agents.resident as resident_mod
from src.utils.agent_runtime import make_assistant_message, make_tool_message


MOCK_STATE: Dict[str, Any] = {
    "mission_goal": "Post-exploit automotive-testbed and enumerate",
    "mission_id": "test-resident-001",
    "mission_status": "active",
    "current_agent": "resident",
    "next_agent": None,
    "iteration_count": 6,
    "target_scope": ["172.20.0.0/16", "automotive-testbed"],
    "discovered_targets": {
        "automotive-testbed": {
            "ip_address": "automotive-testbed",
            "os_guess": "Linux (Ubuntu 20.04)",
            "ports": [22, 8000],
            "services": {
                "22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"},
                "8000": {"service_name": "http", "version": "Python/3.8"},
            },
        }
    },
    "active_sessions": {
        "automotive-testbed": {
            "session_id": 7,
            "module": "auxiliary/scanner/ssh/ssh_login",
            "lhost": "attackbox",
            "lport": "4444",
            "established_at": "2026-01-15T10:30:00",
        }
    },
    "research_cache": {
        "ssh privesc": "Check sudo -l and SUID binaries for escalation paths",
    },
    "intelligence_findings": [
        {
            "cve": "CVE-2021-4034",
            "description": "Polkit pkexec local privilege escalation",
            "data": {},
        }
    ],
    "web_findings": [],
    "exploited_services": [],
    "supervisor_messages": [],
    "supervisor_expectations": {},
    "agent_log": [],
    "critical_findings": [],
    "errors": [],
}


def _tool(name: str, payload: Dict[str, Any], call_id: str = "call-1") -> Dict[str, Any]:
    return make_tool_message(name, call_id, payload)


def _session_validation() -> Dict[str, Any]:
    return _tool(
        "msf_list_sessions",
        {"status": "success", "sessions": {"7": {"type": "shell", "info": "test shell"}}},
        "call-0",
    )


def _resident_agent_with_client() -> resident_mod.ResidentAgent:
    agent = resident_mod.ResidentAgent()
    agent._client = object()
    agent._model = "test-model"
    return agent


def test_build_context_includes_key_sections():
    ctx = resident_mod._build_resident_context(MOCK_STATE)

    assert "MISSION GOAL: Post-exploit automotive-testbed" in ctx
    assert "IMMEDIATE OBJECTIVE:" in ctx
    assert "ACTIVE SESSIONS:" in ctx
    assert "session_id=7" in ctx
    assert "TARGET CONTEXT:" in ctx
    assert "RESEARCH & OSINT INTELLIGENCE:" in ctx
    assert "ssh privesc" in ctx
    assert "OSINT: [CVE-2021-4034]" in ctx


def test_build_context_empty_sections():
    state = {**MOCK_STATE, "active_sessions": {}, "research_cache": {}, "intelligence_findings": []}
    ctx = resident_mod._build_resident_context(state)

    assert "ACTIVE SESSIONS:\n  (none)" in ctx
    assert "RESEARCH & OSINT INTELLIGENCE:\n  (none)" in ctx


async def test_resident_agent_no_sessions_returns_validation_error():
    agent = resident_mod.ResidentAgent()
    state = {**MOCK_STATE, "active_sessions": {}}

    out = await agent.call_llm(state)

    assert out["errors"][0].error_type == "ValidationError"
    assert out["errors"][0].recoverable is True


async def test_resident_agent_tool_loader_errors_are_reported(monkeypatch):
    async def fake_run_tool_worker(**kwargs):
        raise RuntimeError("No allowed tools were available from the MCP bridge")

    monkeypatch.setattr(base_mod, "run_tool_worker", fake_run_tool_worker)
    out = await _resident_agent_with_client().call_llm(MOCK_STATE)

    assert out["errors"][0].error_type == "LLMError"
    assert "No allowed tools" in out["errors"][0].error
    assert out["errors"][0].recoverable is False


async def test_resident_agent_missing_required_tool_is_reported(monkeypatch):
    async def fake_run_tool_worker(**kwargs):
        raise RuntimeError("Required tool(s) missing from bridge: msf_session_command")

    monkeypatch.setattr(base_mod, "run_tool_worker", fake_run_tool_worker)
    out = await _resident_agent_with_client().call_llm(MOCK_STATE)

    assert out["errors"][0].error_type == "LLMError"
    assert "msf_session_command" in out["errors"][0].error


def test_extract_root_privilege_detection():
    messages = [
        _session_validation(),
        _tool(
            "msf_session_command",
            {
                "status": "success",
                "output": "uid=0(root) gid=0(root) groups=0(root)",
                "invocation": {"session_id": 7, "command": "id"},
            },
        ),
    ]

    updates = resident_mod._extract_resident_updates(messages, MOCK_STATE)
    session = updates["active_sessions"]["automotive-testbed"]

    assert session["privilege"] == "root"
    assert any("root privileges" in item.lower() for item in updates.get("critical_findings", []))


def test_extract_user_privilege_detection():
    messages = [
        _session_validation(),
        _tool(
            "msf_session_command",
            {
                "status": "success",
                "output": "uid=1000(admin) gid=1000(admin) groups=1000(admin)",
                "invocation": {"session_id": 7, "command": "id"},
            },
        ),
    ]

    updates = resident_mod._extract_resident_updates(messages, MOCK_STATE)

    assert updates["active_sessions"]["automotive-testbed"]["privilege"] == "user"


def test_extract_os_info_from_uname():
    messages = [
        _session_validation(),
        _tool(
            "msf_session_command",
            {
                "status": "success",
                "output": "Linux testbed 5.4.0-91-generic #102-Ubuntu SMP x86_64 GNU/Linux",
                "invocation": {"session_id": 7, "command": "uname -a"},
            },
        ),
    ]

    updates = resident_mod._extract_resident_updates(messages, MOCK_STATE)

    assert "5.4.0-91" in updates["active_sessions"]["automotive-testbed"]["os_info"]


def test_extract_post_module_success_is_session_scoped():
    messages = [
        _session_validation(),
        _tool(
            "msf_run_post",
            {
                "status": "success",
                "module": "post/linux/gather/enum_system",
                "module_output": "Linux testbed 5.4.0",
                "invocation": {"module_name": "post/linux/gather/enum_system", "options": {"SESSION": 7}},
            },
        ),
    ]

    updates = resident_mod._extract_resident_updates(messages, MOCK_STATE)
    session = updates["active_sessions"]["automotive-testbed"]

    assert session["successful_post_modules"] == ["post/linux/gather/enum_system"]
    assert "msf_run_post" in session["resident_actions_taken"][0]


def test_extract_handles_malformed_json():
    messages = [
        _session_validation(),
        make_tool_message("msf_session_command", "call-1", "this is not valid json {{{"),
    ]

    updates = resident_mod._extract_resident_updates(messages, MOCK_STATE)

    assert updates["iteration_count"] == MOCK_STATE["iteration_count"] + 1
    findings = updates["agent_log"][0].findings
    assert findings["session_validation_performed"] is True


async def test_resident_agent_success_with_mocked_tool_loop(monkeypatch):
    async def fake_run_tool_worker(**kwargs):
        messages = [
            _session_validation(),
            _tool(
                "msf_session_command",
                {
                    "status": "success",
                    "output": "uid=0(root) gid=0(root) groups=0(root)",
                    "invocation": {"session_id": 7, "command": "id"},
                },
                "call-1",
            ),
            _tool(
                "msf_session_command",
                {
                    "status": "success",
                    "output": "Linux testbed 5.4.0-91-generic #102-Ubuntu SMP x86_64 GNU/Linux",
                    "invocation": {"session_id": 7, "command": "uname -a"},
                },
                "call-2",
            ),
            make_assistant_message(
                json.dumps(
                    {
                        "objective": "Enumerate the active session",
                        "objective_status": "completed",
                        "session_id": "7",
                        "actions_taken": ["id", "uname -a"],
                        "evidence_summary": ["root shell confirmed"],
                    }
                )
            ),
        ]
        return SimpleNamespace(messages=messages, final_text="", rounds=1)

    monkeypatch.setattr(base_mod, "run_tool_worker", fake_run_tool_worker)

    out = await _resident_agent_with_client().call_llm(MOCK_STATE)
    session = out["active_sessions"]["automotive-testbed"]

    assert not out.get("errors")
    assert session["privilege"] == "root"
    assert "5.4.0" in session["os_info"]
    assert out["validations"][0]["status"] == "completed"
    assert any("completed objective" in item.lower() for item in out.get("critical_findings", []))


def test_prompt_embeds_resident_doctrine():
    prompt = resident_mod.RESIDENT_SYSTEM_PROMPT

    assert len(prompt) > 500
    for snippet in (
        "Primary mission:",
        "Available tools:",
        "Operational rules:",
        "Automotive and interface-aware behavior:",
        '"objective_status": "completed|in_progress|blocked|needs_approval|failed"',
    ):
        assert snippet in prompt
