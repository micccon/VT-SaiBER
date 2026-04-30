from __future__ import annotations

import uuid

import pytest
from scripts.tests.database.live_helpers import (
    make_librarian_with_empty_kb_and_osint,
    make_librarian_with_empty_kb_live_cve_osint,
    make_librarian_with_empty_sources,
    make_librarian_with_empty_sources_live_llm,
    make_librarian_with_real_kb_live_external,
    make_librarian_with_real_kb_empty_external,
    _first_agent_log_findings,
    print_librarian_output,
    insert_live_kb_chunk,
    require_live_llm_config,
    require_tavily,
    state,
    step,
)


@pytest.mark.asyncio
@pytest.mark.live
@pytest.mark.kb
@pytest.mark.librarian
async def test_live_librarian_uses_kb_evidence(kb_source_prefix: str) -> None:
    step("Preparing a KB-backed librarian run with deterministic empty CVE/OSINT fallbacks")
    unique_token = f"vt-saiber-lib-kb-{uuid.uuid4().hex[:8]}"
    chunk_text = (
        f"{unique_token} exploit note for a synthetic pytest KB record. "
        "Use this token to verify librarian KB retrieval."
    )
    await insert_live_kb_chunk(
        kb_source_prefix,
        "pytest-live-librarian-kb.md",
        chunk_text,
    )

    agent = make_librarian_with_real_kb_empty_external()
    out = await agent.call_llm(state(f"Research {unique_token} exploit note"))
    cache_entry = next(iter(out["research_cache"].values()))
    finding = out["intelligence_findings"][0]
    print_librarian_output("live-librarian-kb", out)
    trace = _first_agent_log_findings(out).get("retrieval_trace", {})

    assert "kb" in cache_entry["source_types"]
    assert any(citation.startswith("kb:") for citation in cache_entry["citations"])
    assert "kb" in finding["source_types"]
    assert trace["kb"]["status"] == "ready"
    assert trace["kb"]["count"] >= 1
    assert trace["kb"]["references"]


@pytest.mark.asyncio
@pytest.mark.live
@pytest.mark.cve
@pytest.mark.librarian
async def test_live_librarian_uses_cve_pipeline() -> None:
    step("Running librarian with empty KB/findings so the live CVE path is forced")
    agent = make_librarian_with_empty_kb_and_osint()

    test_state = state("Research an exploit path for vsftpd 2.3.4 on ftp service")
    test_state["discovered_targets"] = {
        "10.10.10.10": {
            "services": {
                "21": {
                    "service_name": "ftp",
                    "version": "vsftpd 2.3.4",
                    "banner": "vsFTPd 2.3.4",
                }
            }
        }
    }

    out = await agent.call_llm(test_state)
    cache_entry = next(iter(out["research_cache"].values()))
    finding = out["intelligence_findings"][0]
    print_librarian_output("live-librarian-cve", out)
    trace = _first_agent_log_findings(out).get("retrieval_trace", {})

    assert "cve" in cache_entry["source_types"]
    assert any(citation.startswith("cve:") for citation in cache_entry["citations"])
    assert finding["source_types"] == cache_entry["source_types"]
    assert trace["cve"]["status"] == "ready"
    assert trace["cve"]["count"] >= 1
    assert any(reference.startswith("CVE-") for reference in trace["cve"]["references"])


@pytest.mark.asyncio
@pytest.mark.live
@pytest.mark.kb
@pytest.mark.cve
@pytest.mark.osint
@pytest.mark.librarian
async def test_live_librarian_uses_kb_cve_osint_with_live_synthesis(kb_source_prefix: str) -> None:
    step("Running librarian with live KB, CVE, OSINT, and LLM synthesis")
    require_live_llm_config()
    require_tavily()
    unique_token = f"vt-saiber-lib-full-{uuid.uuid4().hex[:8]}"
    await insert_live_kb_chunk(
        kb_source_prefix,
        "pytest-live-librarian-full-pipeline.md",
        (
            f"{unique_token} vsftpd 2.3.4 exploit research note. "
            "The KB note cites CVE-2011-2523 as the candidate vulnerability. "
            "Use official CVE data and external tooling references before striker chooses an exploit path."
        ),
    )

    agent = make_librarian_with_real_kb_live_external()
    test_state = state(
        f"Research an exploit path for vsftpd 2.3.4 on FTP using {unique_token}. "
        "Find relevant CVEs and external exploit/tooling guidance."
    )
    test_state["discovered_targets"] = {
        "10.10.10.10": {
            "services": {
                "21": {
                    "service_name": "ftp",
                    "version": "vsftpd 2.3.4",
                    "banner": "vsFTPd 2.3.4",
                }
            }
        }
    }

    out = await agent.call_llm(test_state)
    cache_entry = next(iter(out["research_cache"].values()))
    trace = _first_agent_log_findings(out).get("retrieval_trace", {})
    print_librarian_output("live-librarian-kb-cve-osint", out)

    assert {"kb", "cve", "osint"}.issubset(set(cache_entry["source_types"]))
    assert cache_entry["source_status"]["llm"] in {"ready", "degraded"}
    if cache_entry["summary"].startswith("Fallback intelligence brief"):
        assert "llm_synthesis_failed" in cache_entry["degraded_reasons"]
    assert any(citation.startswith("kb:") for citation in cache_entry["citations"])
    assert any(citation.startswith("cve:") for citation in cache_entry["citations"])
    assert any(citation.startswith("osint:") for citation in cache_entry["citations"])
    assert trace["kb"]["count"] >= 1
    assert trace["cve"]["count"] >= 1
    assert trace["osint"]["count"] >= 1


@pytest.mark.asyncio
@pytest.mark.live
@pytest.mark.cve
@pytest.mark.osint
@pytest.mark.librarian
async def test_live_librarian_uses_supervisor_handoff_goal_for_cve_osint() -> None:
    """Simulate supervisor asking librarian for exploit-path research before striker."""

    step("Simulating supervisor handoff to librarian for vsftpd exploit-path research")
    require_live_llm_config()
    require_tavily()
    agent = make_librarian_with_empty_kb_live_cve_osint()

    test_state = state("Assess the FTP service and prepare the next striker action.")
    test_state["supervisor_expectations"] = {
        "next_agent": "librarian",
        "specific_goal": (
            "Research an exploit path for vsftpd 2.3.4 on FTP. "
            "Find relevant CVEs and external exploit/tooling guidance."
        ),
        "rationale": "Striker needs cited exploit-path intelligence before choosing a module.",
        "confidence_score": 0.9,
    }
    test_state["discovered_targets"] = {
        "10.10.10.10": {
            "services": {
                "21": {
                    "service_name": "ftp",
                    "version": "vsftpd 2.3.4",
                    "banner": "vsFTPd 2.3.4",
                }
            }
        }
    }

    out = await agent.call_llm(test_state)
    cache_entry = next(iter(out["research_cache"].values()))
    finding = out["intelligence_findings"][0]
    trace = _first_agent_log_findings(out).get("retrieval_trace", {})
    print_librarian_output("live-librarian-supervisor-handoff", out)

    assert {"cve", "osint"}.issubset(set(cache_entry["source_types"]))
    assert cache_entry["source_status"]["llm"] in {"ready", "degraded"}
    if cache_entry["summary"].startswith("Fallback intelligence brief"):
        assert "llm_synthesis_failed" in cache_entry["degraded_reasons"]
    assert any(citation.startswith("cve:") for citation in cache_entry["citations"])
    assert any(citation.startswith("osint:") for citation in cache_entry["citations"])
    assert finding["cve"] == "CVE-2011-2523"
    assert trace["cve"]["status"] == "ready"
    assert trace["cve"]["count"] >= 1
    assert trace["osint"]["status"] == "ready"
    assert trace["osint"]["count"] >= 1
    assert trace["osint"]["references"]


@pytest.mark.asyncio
@pytest.mark.live
@pytest.mark.librarian
async def test_live_librarian_llm_synthesis_outputs_structured_brief() -> None:
    step("Running a real librarian LLM synthesis pass with KB/CVE/OSINT disabled")
    require_live_llm_config()
    agent = make_librarian_with_empty_sources_live_llm()

    out = await agent.call_llm(state("Summarize basic SSH exploitation guidance for OpenSSH 8.2p1"))
    print_librarian_output("live-librarian-llm", out)
    trace = _first_agent_log_findings(out).get("retrieval_trace", {})

    cache_entry = next(iter(out["research_cache"].values()))
    assert cache_entry.get("summary")
    assert "source_status" in cache_entry
    assert cache_entry["confidence"] <= 0.35
    assert "no_supporting_evidence_confidence_capped" in cache_entry["degraded_reasons"]
    assert trace["kb"]["count"] == 0
    assert trace["cve"]["count"] == 0
