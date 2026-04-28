from __future__ import annotations

import pytest

from tests.db_tests.live_helpers import (
    make_librarian_with_empty_kb_live_osint,
    _first_agent_log_findings,
    print_librarian_output,
    require_tavily,
    state,
    step,
)


@pytest.mark.asyncio
@pytest.mark.live
@pytest.mark.osint
async def test_live_osint_client_returns_results() -> None:
    step("Querying Tavily live for OSINT results")
    client = require_tavily()
    results = await client.search("vsftpd 2.3.4 backdoor exploit guidance", max_results=3)
    assert results
    top = results[0]
    print(
        f"[live-osint] top={top.get('title')} score={top.get('score')} url={top.get('url')}"
    )
    assert top.get("url")
    assert top.get("title") or top.get("snippet")


@pytest.mark.asyncio
@pytest.mark.live
@pytest.mark.osint
@pytest.mark.librarian
async def test_live_librarian_uses_osint_pipeline() -> None:
    step("Running librarian with empty KB/CVE so the live OSINT path is forced")
    require_tavily()
    agent = make_librarian_with_empty_kb_live_osint()

    out = await agent.call_llm(state("How do I use enum4linux against samba shares?"))
    cache_entry = next(iter(out["research_cache"].values()))
    finding = out["intelligence_findings"][0]
    print_librarian_output("live-librarian-osint", out)
    trace = _first_agent_log_findings(out).get("retrieval_trace", {})

    assert cache_entry["is_osint_derived"] is True
    assert "osint" in cache_entry["source_types"]
    assert any(citation.startswith("osint:") for citation in cache_entry["citations"])
    assert finding["is_osint_derived"] is True
    assert trace["osint"]["status"] == "ready"
    assert trace["osint"]["count"] >= 1
    assert trace["osint"]["references"]
