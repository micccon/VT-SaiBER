"""Structured output contract for Fuzzer."""

from __future__ import annotations

from pydantic import BaseModel, Field


class WebFinding(BaseModel):
    """Normalized web finding shape used by Fuzzer."""

    url: str
    path: str
    status_code: int
    content_length: int | None = None
    content_type: str | None = None
    is_api_endpoint: bool = False
    is_interesting: bool = False
    discovery_depth: int = 0
    scan_policy: dict[str, object] = Field(default_factory=dict)
    rationale: str = ""
    source_tool: str | None = None
    redirect_to: str | None = None
    raw_finding: str | None = None


class FuzzerOutcome(BaseModel):
    """Structured Fuzzer result returned by the model."""

    base_url: str
    web_findings: list[WebFinding] = Field(default_factory=list)
    operator_summary: str = ""
    stop_reason: str | None = None

