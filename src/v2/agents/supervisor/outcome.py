"""Structured outcome for supervisor v2 routing."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from src.v2.agents.supervisor.constants import V2_VALID_NEXT_AGENTS


class SupervisorV2Decision(BaseModel):
    """Structured routing decision returned by supervisor v2."""

    next_agent: Literal[
        "scout_v2",
        "fuzzer_v2",
        "librarian_v2",
        "striker_v2",
        "resident_v2",
        "end",
    ]
    rationale: str = Field(default="")
    specific_goal: str = Field(default="")
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)


assert "end" in V2_VALID_NEXT_AGENTS
