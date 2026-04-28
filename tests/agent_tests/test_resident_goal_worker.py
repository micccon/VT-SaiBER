from __future__ import annotations

import asyncio
import json
import sys
import types
from typing import Any, Dict

if "psycopg2" not in sys.modules:
    psycopg2_stub = types.ModuleType("psycopg2")
    psycopg2_stub.connect = lambda *args, **kwargs: None
    psycopg2_extras_stub = types.ModuleType("psycopg2.extras")
    psycopg2_extras_stub.RealDictCursor = object
    psycopg2_stub.extras = psycopg2_extras_stub
    sys.modules["psycopg2"] = psycopg2_stub
    sys.modules["psycopg2.extras"] = psycopg2_extras_stub

if "pgvector.psycopg2" not in sys.modules:
    pgvector_stub = types.ModuleType("pgvector")
    pgvector_psycopg2_stub = types.ModuleType("pgvector.psycopg2")
    pgvector_psycopg2_stub.register_vector = lambda *args, **kwargs: None
    pgvector_stub.psycopg2 = pgvector_psycopg2_stub
    sys.modules["pgvector"] = pgvector_stub
    sys.modules["pgvector.psycopg2"] = pgvector_psycopg2_stub

if "langgraph.graph" not in sys.modules:
    langgraph_stub = types.ModuleType("langgraph")
    langgraph_graph_stub = types.ModuleType("langgraph.graph")
    langgraph_graph_stub.END = "END"
    langgraph_stub.graph = langgraph_graph_stub
    sys.modules["langgraph"] = langgraph_stub
    sys.modules["langgraph.graph"] = langgraph_graph_stub

from src.agents.resident import (
    READ_ONLY_POST_MODULES,
    RESIDENT_ALLOWED_TOOLS,
    RESIDENT_SYSTEM_PROMPT,
    ResidentToolPolicy,
    _build_resident_context,
    _extract_resident_updates,
)
from src.agents.supervisor import SupervisorAgent
from src.utils.tools.models import RuntimeTool
from src.utils.tools.policy import ToolInterception


def _base_state() -> Dict[str, Any]:
    return {
        "mission_goal": "Open the car door via the vcan interface",
        "mission_id": "resident-test",
        "mission_status": "active",
        "current_agent": "resident",
        "next_agent": None,
        "iteration_count": 2,
        "target_scope": ["automotive-testbed"],
        "discovered_targets": {
            "automotive-testbed": {
                "ip_address": "automotive-testbed",
                "os_guess": "Linux",
                "services": {
                    "22": {"service_name": "ssh", "version": "OpenSSH 8.2p1"},
                    "8000": {"service_name": "http", "version": "Python/3.8"},
                },
            }
        },
        "ot_discovery": {},
        "web_findings": [],
        "active_sessions": {
            "automotive-testbed": {
                "session_id": 7,
                "module": "exploit/linux/http/demo",
                "user": "ubuntu",
                "established_at": "2026-04-27T12:00:00",
            }
        },
        "exploited_services": [],
        "credential_findings": [],
        "exploit_attempts": [],
        "protocol_observations": [],
        "fuzzing_runs": [],
        "crash_indicators": [],
        "artifacts": [],
        "validations": [],
        "research_cache": {"vcan note": "Use host-side can-utils when in-session tooling is insufficient."},
        "intelligence_findings": [{"description": "The objective requires interacting with the host-side virtual CAN interface."}],
        "supervisor_messages": [],
        "supervisor_expectations": {"specific_goal": "Use the live session to validate and trigger the vcan door action."},
        "agent_log": [],
        "critical_findings": [],
        "errors": [],
    }


def _tool(name: str) -> RuntimeTool:
    async def _executor(**_: Any) -> Any:
        return {"status": "success"}

    return RuntimeTool(
        name=name,
        description=name,
        input_schema={"type": "object", "properties": {}},
        executor=_executor,
    )


def _run(coro):
    return asyncio.run(coro)


def test_resident_context_prefers_specific_goal():
    context = _build_resident_context(_base_state())
    assert "IMMEDIATE OBJECTIVE: Use the live session to validate and trigger the vcan door action." in context
    assert "MISSION GOAL: Open the car door via the vcan interface" in context
    assert "ACTIVE SESSIONS:" in context


def test_read_only_session_command_does_not_require_approval(monkeypatch):
    called = {"count": 0}

    def fake_approval(**_: Any) -> bool:
        called["count"] += 1
        return False

    monkeypatch.setattr("src.agents.resident.require_manual_approval", fake_approval)
    policy = ResidentToolPolicy(require_confirmation=True)

    intercepted = _run(
        policy.before_call(
            _tool("msf_session_command"),
            {"session_id": 7, "command": "whoami"},
        )
    )

    assert intercepted is None
    assert called["count"] == 0


def test_system_execute_command_requires_approval(monkeypatch):
    monkeypatch.setattr("src.agents.resident.require_manual_approval", lambda **_: False)
    policy = ResidentToolPolicy(require_confirmation=True)

    intercepted = _run(
        policy.before_call(
            _tool("system_execute_command"),
            {"command": "cansend vcan0 123#DEADBEEF"},
        )
    )

    assert isinstance(intercepted, ToolInterception)
    assert intercepted.payload["objective_status"] == "needs_approval"


def test_mutating_session_command_requires_approval(monkeypatch):
    monkeypatch.setattr("src.agents.resident.require_manual_approval", lambda **_: False)
    policy = ResidentToolPolicy(require_confirmation=True)

    intercepted = _run(
        policy.before_call(
            _tool("msf_session_command"),
            {"session_id": 7, "command": "touch /tmp/door-opened"},
        )
    )

    assert isinstance(intercepted, ToolInterception)
    assert intercepted.payload["objective_status"] == "needs_approval"


def test_resident_extracts_completed_objective():
    state = _base_state()
    messages = [
        {"role": "assistant", "content": "", "tool_calls": [{"id": "1", "name": "msf_list_sessions", "args": {}}]},
        {
            "role": "tool",
            "name": "msf_list_sessions",
            "tool_call_id": "1",
            "content": {
                "status": "success",
                "evidence": {"sessions": {"7": {"type": "meterpreter", "session_host": "automotive-testbed"}}},
                "invocation": {},
            },
        },
        {"role": "assistant", "content": "", "tool_calls": [{"id": "2", "name": "msf_session_command", "args": {"session_id": 7, "command": "whoami"}}]},
        {
            "role": "tool",
            "name": "msf_session_command",
            "tool_call_id": "2",
            "content": {
                "status": "success",
                "output": "root\n",
                "invocation": {"session_id": 7, "command": "whoami"},
            },
        },
        {
            "role": "assistant",
            "content": json.dumps(
                {
                    "objective": "Trigger the vcan door action",
                    "objective_status": "completed",
                    "session_id": "7",
                    "actions_taken": ["Validated live session", "Confirmed root context", "Triggered bounded objective action"],
                    "evidence_summary": ["VCAN objective completed", "Root context confirmed"],
                }
            ),
        },
    ]

    updates = _extract_resident_updates(messages, state)

    assert updates["agent_log"][0].findings["objective_status"] == "completed"
    assert updates["validations"][0]["status"] == "completed"
    assert updates["active_sessions"]["automotive-testbed"]["resident_objective_status"] == "completed"


def test_resident_extracts_needs_approval_from_interception():
    state = _base_state()
    messages = [
        {"role": "assistant", "content": "", "tool_calls": [{"id": "1", "name": "msf_list_sessions", "args": {}}]},
        {
            "role": "tool",
            "name": "msf_list_sessions",
            "tool_call_id": "1",
            "content": {
                "status": "success",
                "evidence": {"sessions": {"7": {"type": "meterpreter"}}},
                "invocation": {},
            },
        },
        {
            "role": "tool",
            "name": "system_execute_command",
            "tool_call_id": "2",
            "content": {
                "status": "aborted",
                "objective_status": "needs_approval",
                "message": "Execution blocked pending manual approval.",
                "invocation": {"command": "cansend vcan0 123#DEADBEEF"},
            },
        },
    ]

    updates = _extract_resident_updates(messages, state)

    assert updates["agent_log"][0].findings["objective_status"] == "needs_approval"
    assert updates["validations"][0]["status"] == "needs_approval"


def test_supervisor_only_ends_on_completed_or_needs_approval():
    agent = SupervisorAgent()
    state = _base_state()
    state["agent_log"] = [
        {
            "agent": "resident",
            "action": "objective_worker",
            "findings": {
                "objective": "Open the car door via the vcan interface",
                "objective_status": "blocked",
                "session_id": "7",
                "actions_taken": ["Validated session", "Confirmed host context"],
                "evidence_summary": ["Need a new path"],
            },
        }
    ]

    decision, reason = agent._apply_guardrails(
        state,
        type("Decision", (), {
            "next_agent": "end",
            "rationale": "stop",
            "specific_goal": "done",
            "confidence_score": 0.9,
        })(),
    )

    assert decision.next_agent in {"resident", "librarian"}
    assert reason in {"resident-not-finished", "resident-needs-new-intel"}


def test_resident_prompt_mentions_json_status_contract():
    assert "objective_status" in RESIDENT_SYSTEM_PROMPT
    assert "system_execute_command" in RESIDENT_SYSTEM_PROMPT
    assert "msf_list_sessions" in RESIDENT_SYSTEM_PROMPT
    assert "post/linux/gather/enum_system" in READ_ONLY_POST_MODULES
    assert "system_execute_command" in RESIDENT_ALLOWED_TOOLS
