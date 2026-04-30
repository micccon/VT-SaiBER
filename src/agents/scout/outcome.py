"""Structured output contract for Scout."""

from __future__ import annotations

from pydantic import BaseModel, Field

from src.state.models import DiscoveredTarget


class ScoutOutcome(BaseModel):
    """Structured scout result returned by the model."""

    targets: list[DiscoveredTarget] = Field(default_factory=list)
    discovered_hosts: list[str] = Field(default_factory=list)
    operator_summary: str = ""
    stop_reason: str | None = None

