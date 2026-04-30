"""Librarian context helpers."""

from __future__ import annotations

from typing import Any

from src.database.librarian.prompts import LibrarianPrompts
from src.database.librarian.query_builder import TelemetryProcessor
from src.state.cyber_state import CyberState


def build_research_query(state: CyberState) -> str:
    """Build the compact librarian retrieval query from CyberState."""

    return TelemetryProcessor.build_research_query(state)


def build_synthesis_prompt(
    query: str,
    kb_results: list[dict[str, Any]],
    findings_results: list[dict[str, Any]],
    cve_results: list[dict[str, Any]],
    osint_results: list[dict[str, Any]],
    source_status: dict[str, Any],
) -> str:
    """Build the librarian synthesis prompt from retrieved evidence."""

    return LibrarianPrompts.build_user_content(
        query,
        kb_results,
        osint_results,
        findings_results=findings_results,
        cve_results=cve_results,
        source_status=source_status,
    )
