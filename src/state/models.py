from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class MissionStatus(str, Enum):
    """Top-level mission lifecycle states used by the workflow."""

    ACTIVE = "active"
    SUCCESS = "success"
    FAILED = "failed"
    WAIT_FOR_HUMAN = "wait_for_human"


class SupervisorDecision(BaseModel):
    """Structured output for supervisor routing decisions."""

    next_agent: str = Field(description="The name of the next specialist agent to call")
    rationale: str = Field(description="The logical reasoning for this delegation")
    specific_goal: str = Field(description="The granular task for the worker")
    confidence_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence in this decision (0.0 to 1.0)",
    )


class AgentLogEntry(BaseModel):
    """Single entry in the agent execution log."""

    # The agent that produced the entry.
    agent: str
    # High-level action name such as route_decision, recon_scan, or run_exploit.
    action: str
    # Optional machine-readable decision associated with the action.
    decision: Optional[str] = None
    # Free-form explanation of why the agent took the action.
    reasoning: Optional[str] = None
    # The primary target host, URL, or session for the action.
    target: Optional[str] = None
    # Structured details captured from the action result.
    findings: Optional[Dict[str, Any]] = None
    # Timestamp is generated when the entry is created so logs stay ordered.
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    # Optional error text when the action failed.
    error: Optional[str] = None


class ServiceInfo(BaseModel):
    """Information about a discovered service."""

    # Network port the service was observed on.
    port: int
    # Transport protocol, usually tcp for the current workflow.
    protocol: str = "tcp"
    # Normalized service name such as ssh, http, smb, or mysql.
    service_name: str
    # Optional version string fingerprinted by reconnaissance.
    version: Optional[str] = None
    # Optional raw banner or identifying string.
    banner: Optional[str] = None


class DiscoveredTarget(BaseModel):
    """Validated target discovered by scout."""

    # Primary host or IP address in scope.
    ip_address: str
    # MAC details are optional because they are not always available from recon.
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None
    # Best-effort OS guess from reconnaissance.
    os_guess: Optional[str] = None
    # Flattened port list used for quick routing and reporting.
    ports: List[int] = Field(default_factory=list)
    # Structured service information keyed by port.
    services: Dict[int, ServiceInfo] = Field(default_factory=dict)
    # Simple vulnerability/candidate notes attached during recon or later analysis.
    vulns: List[str] = Field(default_factory=list)


class IntelligenceBrief(BaseModel):
    """Intelligence brief from librarian research."""

    # Human-readable synthesis of the research result.
    summary: str
    # Structured parameters the downstream agents can consume directly.
    technical_params: Dict[str, Any] = Field(default_factory=dict)
    # Flag indicating the brief relied on OSINT rather than only local RAG context.
    is_osint_derived: bool = False
    # Confidence is normalized to 0-1 for routing and operator visibility.
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    # Citations are kept as simple strings for easy rendering and storage.
    citations: List[str] = Field(default_factory=list)
    # Optional conflicting-source notes when the librarian sees disagreement.
    conflicting_sources: Optional[List[str]] = None
    # Source classes that materially contributed to the brief.
    source_types: List[str] = Field(default_factory=list)
    # Dependency readiness / degraded mode data for observability.
    source_status: Dict[str, str] = Field(default_factory=dict)
    degraded_reasons: List[str] = Field(default_factory=list)


class RetrievalSourceTrace(BaseModel):
    """Compact audit summary for one librarian retrieval source."""

    # Dependency status such as ready, empty, skipped, unavailable, or degraded.
    status: str = "unknown"
    # Number of evidence items returned by this source.
    count: int = Field(default=0, ge=0)
    # Short source-specific references such as doc names, CVE IDs, or URLs.
    references: List[str] = Field(default_factory=list)


class RetrievalTrace(BaseModel):
    """Grouped librarian retrieval trace stored in the agent log."""

    kb: RetrievalSourceTrace = Field(default_factory=RetrievalSourceTrace)
    findings: RetrievalSourceTrace = Field(default_factory=RetrievalSourceTrace)
    cve: RetrievalSourceTrace = Field(default_factory=RetrievalSourceTrace)
    osint: RetrievalSourceTrace = Field(default_factory=RetrievalSourceTrace)
    degraded_reasons: List[str] = Field(default_factory=list)


class AgentError(BaseModel):
    """Error reported by an agent."""

    # The agent that surfaced the error.
    agent: str
    # Short machine-readable category for downstream handling.
    error_type: str
    # Human-readable error detail.
    error: str
    # Recoverable errors let the workflow continue or backtrack.
    recoverable: bool = True
    # Timestamp is generated at creation so failures can be ordered in history.
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
