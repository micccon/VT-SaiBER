from __future__ import annotations

import pytest

from src.state.models import IntelligenceBrief
from src.agents.librarian.agent import LibrarianAgent
from scripts.tests.helpers import FakeRag, discovered_http_state, require_live_openrouter, runtime_summary, step

pytestmark = pytest.mark.live


@pytest.mark.asyncio
async def test_librarian_live_synthesis_with_minimal_retrieval():
    require_live_openrouter()
    step(f"Running librarian live synthesis: {runtime_summary()}")

    state = discovered_http_state()
    agent = LibrarianAgent(rag_orchestrator=FakeRag())
    out = await agent.run(state)

    assert out["current_agent"] == "librarian"
    assert out["research_cache"]
    assert out["intelligence_findings"]
    assert out["agent_log"]
    IntelligenceBrief.model_validate(next(iter(out["research_cache"].values())))
