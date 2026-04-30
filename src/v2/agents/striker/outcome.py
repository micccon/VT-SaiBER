"""Structured output contract for Striker v2."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class SessionClaim(BaseModel):
    """Model-claimed session details to verify against telemetry."""

    session_id: str | int | None = None
    target: str | None = None


class ArtifactClaim(BaseModel):
    """Model-claimed artifact details to verify against telemetry."""

    name: str
    description: str | None = None
    source_tool: str | None = None


class StrikerOutcome(BaseModel):
    """Structured outcome returned by the model for a Striker run."""

    status: Literal[
        "no_candidate",
        "approval_blocked",
        "execution_error",
        "validated_no_session",
        "session_opened",
    ]
    target: str | None = None
    service: str | None = None
    port: int | None = None
    selected_path_type: Literal["exploit", "auxiliary", "validation"] | None = None
    search_terms: list[str] = Field(default_factory=list)
    selected_tool: str | None = None
    selected_module: str | None = None
    attempt_summary: str = ""
    session_claim: SessionClaim | None = None
    artifact_claims: list[ArtifactClaim] = Field(default_factory=list)
    stop_reason: str | None = None
    operator_summary: str = ""

