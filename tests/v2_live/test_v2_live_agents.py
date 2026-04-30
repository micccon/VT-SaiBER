from __future__ import annotations

import asyncio
import os
from dataclasses import replace
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest

from src.config import get_runtime_config
from src.main import CatalystRunner, MissionRequest
from src.state.models import IntelligenceBrief
from src.v2.agents.librarian.agent import LibrarianV2Agent
from src.v2.agents.scout.constants import ATTACKBOX_MCP_URL
from src.v2.agents.supervisor.agent import SupervisorV2Agent
from src.v2.agents.supervisor.constants import V2_VALID_NEXT_AGENTS

pytestmark = pytest.mark.live


def _require_live_openrouter():
    if os.getenv("RUN_V2_LIVE_TESTS") != "1":
        pytest.skip("Set RUN_V2_LIVE_TESTS=1 to run live v2 tests")
    if not os.getenv("OPENROUTER_API_KEY"):
        pytest.skip("OPENROUTER_API_KEY is required for live v2 tests")


def _require_live_mcp():
    if os.getenv("RUN_V2_LIVE_MCP_TESTS") != "1":
        pytest.skip("Set RUN_V2_LIVE_MCP_TESTS=1 to run live v2 MCP graph tests")
    try:
        with urlopen(Request(ATTACKBOX_MCP_URL, method="GET"), timeout=3):
            return
    except HTTPError:
        return
    except (OSError, URLError) as exc:
        pytest.skip(f"Attackbox MCP server is not reachable at {ATTACKBOX_MCP_URL}: {exc}")


def _base_state() -> dict[str, Any]:
    return {
        "mission_goal": "Research a safe next step for 127.0.0.1",
        "mission_id": "v2-live-test",
        "mission_status": "active",
        "current_agent": "supervisor",
        "next_agent": None,
        "iteration_count": 0,
        "target_scope": ["127.0.0.1"],
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


class _FakeRag:
    async def retrieve(self, query: str, source: str = "both", top_k: int = 5, filters=None):
        kb_item = {
            "doc_name": "live_v2_fixture.md",
            "score": 0.92,
            "chunk_text": "Use careful reconnaissance and cite evidence before exploitation.",
        }
        if source == "kb":
            return {"kb_results": [kb_item]}
        if source == "findings":
            return {"findings_results": []}
        return {"kb_results": [kb_item], "findings_results": []}


def _enable_live_llm(agent):
    cfg = get_runtime_config()
    agent._model_config = replace(
        agent._model_config,
        model=cfg.openrouter_model,
        api_key=cfg.openrouter_api_key,
        base_url=cfg.openrouter_base_url,
    )
    return agent


@pytest.mark.asyncio
async def test_supervisor_v2_live_openrouter_route_decision():
    _require_live_openrouter()

    out = await _enable_live_llm(SupervisorV2Agent()).run(_base_state())

    assert out["current_agent"] == "supervisor_v2"
    assert out["next_agent"] in V2_VALID_NEXT_AGENTS
    assert out["agent_log"]


@pytest.mark.asyncio
async def test_librarian_v2_live_synthesis_with_mocked_retrieval():
    _require_live_openrouter()

    state = _base_state()
    state["discovered_targets"] = {
        "127.0.0.1": {
            "ports": [80],
            "services": {"80": {"service_name": "http", "version": "test-service"}},
        }
    }
    agent = _enable_live_llm(LibrarianV2Agent(rag_orchestrator=_FakeRag()))

    out = await agent.run(state)

    assert out["current_agent"] == "librarian_v2"
    assert out["research_cache"]
    assert out["intelligence_findings"]
    assert out["agent_log"]
    assert IntelligenceBrief.model_validate(next(iter(out["research_cache"].values())))


@pytest.mark.asyncio
async def test_full_v2_graph_live_smoke_stays_on_v2_or_ends():
    _require_live_openrouter()
    _require_live_mcp()

    cfg = replace(get_runtime_config(), graph_version="v2", checkpoint_enabled=False)
    runner = CatalystRunner(config=cfg)
    request = MissionRequest(
        mission_goal="Run a bounded v2 live smoke route for localhost only",
        target_scope=["127.0.0.1"],
        mission_id="v2-live-graph-smoke",
        thread_id="v2-live-graph-smoke",
    )

    final_state = await asyncio.wait_for(runner.run(request), timeout=180)

    assert final_state["current_agent"].endswith("_v2")
    next_agent = final_state.get("next_agent")
    assert next_agent in set(V2_VALID_NEXT_AGENTS) | {None}
