"""CyberState mapping for librarian results."""

from __future__ import annotations

from src.state.cyber_state import CyberState
from src.state.models import AgentLogEntry, IntelligenceBrief, RetrievalTrace


def map_brief_to_state(
    state: CyberState,
    *,
    agent_name: str,
    query: str,
    brief: IntelligenceBrief,
    retrieval_trace: RetrievalTrace,
    research_cache: dict[str, object],
    finding_from_brief,
) -> dict[str, object]:
    """Convert a librarian brief into downstream CyberState updates."""

    return {
        "current_agent": agent_name,
        "iteration_count": int(state.get("iteration_count", 0)) + 1,
        "research_cache": research_cache,
        "intelligence_findings": [finding_from_brief(brief)],
        "rag_fallback_triggered": bool(getattr(brief, "is_osint_derived", False)),
        "agent_log": [
            AgentLogEntry(
                agent=agent_name,
                action="research_brief",
                findings={
                    "query": query,
                    "citations": brief.citations,
                    "confidence": brief.confidence,
                    "is_osint_derived": brief.is_osint_derived,
                    "source_types": brief.source_types,
                    "degraded_reasons": brief.degraded_reasons,
                    "retrieval_trace": retrieval_trace.model_dump(),
                },
                reasoning="Librarian produced cited intelligence brief",
            )
        ],
    }
