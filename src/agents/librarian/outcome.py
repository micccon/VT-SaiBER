"""Structured output model for librarian."""

from __future__ import annotations

from src.state.models import IntelligenceBrief


class LibrarianOutcome(IntelligenceBrief):
    """Structured synthesis result returned by librarian."""

