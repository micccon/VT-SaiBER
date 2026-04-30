"""Structured output model for librarian v2."""

from __future__ import annotations

from src.state.models import IntelligenceBrief


class LibrarianOutcome(IntelligenceBrief):
    """Structured synthesis result returned by librarian v2."""

