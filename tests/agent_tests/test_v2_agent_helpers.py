from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

from src.v2.agents import common as common_mod


def _base_state() -> dict[str, Any]:
    return {
        "mission_goal": "Helper test mission",
        "mission_id": "test-mission",
        "mission_status": "active",
        "current_agent": "supervisor",
        "next_agent": None,
        "iteration_count": 2,
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


def _run(coro):
    return asyncio.run(coro)


def test_build_single_mcp_execution_spec_uses_shared_runtime_config(monkeypatch):
    monkeypatch.setattr(
        common_mod,
        "get_runtime_config",
        lambda: SimpleNamespace(
            openrouter_model="test-model",
            openrouter_api_key="test-key",
            openrouter_base_url="https://example.invalid",
            supervisor_timeout_seconds=42,
        ),
    )

    spec = common_mod.build_single_mcp_execution_spec(
        agent_name="demo_v2",
        instructions="demo",
        output_type=dict,
        server_name="attackbox",
        server_url="http://attackbox.invalid/mcp",
        allowed_tools={"recon_ping"},
        approval_required_tools={"dangerous"},
        max_turns=3,
    )

    assert spec.agent_name == "demo_v2"
    assert spec.model.model == "test-model"
    assert spec.model.timeout_seconds == 42
    assert spec.mcp_servers[0].allowed_tools == {"recon_ping"}
    assert spec.mcp_servers[0].approval_required_tools == {"dangerous"}
    assert spec.max_turns == 3


def test_validation_error_update_uses_standard_shape():
    out = common_mod.validation_error_update(
        _base_state(),
        agent_name="resident_v2",
        message="No active sessions",
    )

    assert out["current_agent"] == "resident_v2"
    assert out["iteration_count"] == 3
    assert out["errors"][0].error_type == "ValidationError"
    assert out["errors"][0].recoverable is True


def test_execution_error_update_uses_standard_shape():
    out = common_mod.execution_error_update(
        _base_state(),
        agent_name="resident_v2",
        message="Resident v2 execution failed.",
        exc=RuntimeError("boom"),
    )

    assert out["current_agent"] == "resident_v2"
    assert out["errors"][0].error_type == "LLMError"
    assert "boom" in out["errors"][0].error
    assert out["errors"][0].recoverable is False


def test_run_v2_agent_node_persists_updates(monkeypatch):
    persisted: list[dict[str, Any]] = []

    class _FakeAgent:
        async def run(self, state):
            return {"current_agent": "demo_v2", "iteration_count": 3}

    monkeypatch.setattr(
        "src.database.persistence.persist_state_update",
        lambda state, updates: persisted.append(dict(updates)),
    )

    out = _run(common_mod.run_v2_agent_node(_base_state(), _FakeAgent))

    assert out["current_agent"] == "demo_v2"
    assert persisted == [{"current_agent": "demo_v2", "iteration_count": 3}]
