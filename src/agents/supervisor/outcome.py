"""Structured outcome for supervisor routing."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from src.agents.supervisor.constants import VALID_NEXT_AGENTS


class SupervisorDecision(BaseModel):
    """Structured routing decision returned by supervisor."""

    next_agent: Literal[
        "scout",
        "fuzzer",
        "librarian",
        "striker",
        "resident",
        "end",
    ]
    rationale: str = Field(default="")
    specific_goal: str = Field(default="")
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)


assert "end" in VALID_NEXT_AGENTS
