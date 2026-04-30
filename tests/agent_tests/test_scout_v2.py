from __future__ import annotations

import asyncio
from typing import Any

import pytest

from src.state.models import DiscoveredTarget, ServiceInfo
from src.v2.agents.scout.agent import ScoutV2Agent
from src.v2.agents.scout.outcome import ScoutOutcome
from src.v2.contracts.execution import ExecutionResult, ToolEvent


class _FakeExecutionRunner:
    def __init__(self, result: ExecutionResult[ScoutOutcome]):
        self.result = result
        self.last_spec = None
        self.last_input = None
        self.last_context = None

    async def run(self, spec, *, user_input: str, context=None, policy=None):
        self.last_spec = spec
        self.last_input = user_input
        self.last_context = context
        return self.result


def _tool_event(name: str = "recon_service_probe") -> ToolEvent:
    return ToolEvent(
        tool_name=name,
        invocation={"targets": "192.168.1.20"},
        source="mcp",
        status="success",
        result={"status": "success"},
    )


def _base_state() -> dict[str, Any]:
    return {
        "mission_goal": "Discover the live hosts and services",
        "mission_id": "test-mission",
        "mission_status": "active",
        "current_agent": "supervisor",
        "next_agent": None,
        "iteration_count": 0,
        "target_scope": ["192.168.1.0/24"],
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


def test_scout_v2_exposes_run_entrypoint():
    agent = ScoutV2Agent(execution_runner=_FakeExecutionRunner(ExecutionResult(outcome=ScoutOutcome())))
    assert hasattr(agent, "run")


@pytest.mark.asyncio
async def test_scout_v2_returns_validation_error_without_scope():
    state = _base_state()
    state["target_scope"] = []
    out = await ScoutV2Agent(
        execution_runner=_FakeExecutionRunner(ExecutionResult(outcome=ScoutOutcome()))
    ).run(state)
    assert out["errors"][0].error_type == "ValidationError"
    assert out["current_agent"] == "scout_v2"


@pytest.mark.asyncio
async def test_scout_v2_persists_in_scope_discovered_hosts():
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=ScoutOutcome(
                discovered_hosts=["192.168.1.20", "10.0.0.8"],
                operator_summary="Discovered one in-scope live host.",
            ),
            tool_events=[_tool_event("recon_host_discovery")],
        )
    )
    out = await ScoutV2Agent(execution_runner=runner).run(_base_state())
    assert sorted(out["discovered_targets"].keys()) == ["192.168.1.20"]
    assert out["agent_log"][0].action == "recon_scan"


@pytest.mark.asyncio
async def test_scout_v2_persists_service_probe_targets():
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=ScoutOutcome(
                targets=[
                    DiscoveredTarget(
                        ip_address="192.168.1.15",
                        ports=[22],
                        services={
                            22: ServiceInfo(
                                port=22,
                                protocol="tcp",
                                service_name="ssh",
                                version="OpenSSH 9.0",
                            )
                        },
                        os_guess="Unknown",
                    ),
                    DiscoveredTarget(
                        ip_address="10.0.0.5",
                        ports=[80],
                        services={80: ServiceInfo(port=80, protocol="tcp", service_name="http")},
                        os_guess="Unknown",
                    ),
                ],
                operator_summary="Probed one in-scope SSH service.",
            ),
            tool_events=[_tool_event()],
        )
    )
    out = await ScoutV2Agent(execution_runner=runner).run(_base_state())

    assert list(out["discovered_targets"].keys()) == ["192.168.1.15"]
    service_22 = out["discovered_targets"]["192.168.1.15"]["services"].get("22") or out["discovered_targets"]["192.168.1.15"]["services"].get(22)
    assert service_22["service_name"] == "ssh"
    assert out["agent_log"][0].findings["services_found"] == 1


@pytest.mark.asyncio
async def test_scout_v2_rejects_model_output_without_recon_tool_use():
    runner = _FakeExecutionRunner(
        ExecutionResult(
            outcome=ScoutOutcome(
                discovered_hosts=["192.168.1.20"],
                operator_summary="Claimed host without tool use.",
            )
        )
    )

    out = await ScoutV2Agent(execution_runner=runner).run(_base_state())

    assert out["errors"][0].error_type == "ValidationError"
    assert "did not execute" in out["errors"][0].error
