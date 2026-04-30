"""Structured output model for resident."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ResidentOutcome(BaseModel):
    """Lean structured result returned by resident."""

    objective: str = Field(default="")
    objective_status: str
    session_id: str = Field(default="")
    actions_taken: list[str] = Field(default_factory=list)
    evidence_summary: list[str] = Field(default_factory=list)
