from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field


# ============================================================================
# ENUMS
# ============================================================================

class AgentName(str, Enum):
    SUPERVISOR = "supervisor"
    SCOUT = "scout"
    FUZZER = "fuzzer"
    STRIKER = "striker"
    LIBRARIAN = "librarian"
    RESIDENT = "resident"
    AUTOMOTIVE = "automotive"


class MissionStatus(str, Enum):
    ACTIVE = "active"
    SUCCESS = "success"
    FAILED = "failed"
    WAIT_FOR_HUMAN = "wait_for_human"


# ============================================================================
# SUPERVISOR MODELS
# ============================================================================

class SupervisorDecision(BaseModel):
    """Structured output for Supervisor agent routing decisions."""
    next_agent: str = Field(
        description="The name of the next specialist agent to call"
    )
    rationale: str = Field(
        description="The logical reasoning for this delegation"
    )
    specific_goal: str = Field(
        description="The granular task for the worker"
    )
    confidence_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence in this decision (0.0 to 1.0)"
    )


class AgentLogEntry(BaseModel):
    """Single entry in the agent execution log."""
    agent: str
    action: str
    decision: Optional[str] = None
    reasoning: Optional[str] = None
    target: Optional[str] = None
    findings: Optional[Dict[str, Any]] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    error: Optional[str] = None


# ============================================================================
# SCOUT MODELS
# ============================================================================

class ServiceInfo(BaseModel):
    """Information about a discovered service."""
    port: int
    protocol: str = "tcp"
    service_name: str
    version: Optional[str] = None
    banner: Optional[str] = None


class DiscoveredTarget(BaseModel):
    """Validated target discovered by Scout."""
    ip_address: str
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None
    os_guess: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    services: Dict[int, ServiceInfo] = Field(default_factory=dict)
    vulns: List[str] = Field(default_factory=list)


# ============================================================================
# FUZZER MODELS
# ============================================================================

class WebFinding(BaseModel):
    """Validated web enumeration finding."""
    url: str
    path: str
    status_code: int
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    is_api_endpoint: bool = False
    is_interesting: bool = False
    rationale: str


class WebContext(BaseModel):
    """Web context for fuzzing operations."""
    ip_address: str
    mac_vendor: Optional[str] = None
    base_url: str
    discovered_paths: List[str] = Field(default_factory=list)
    wordlist_strategy: Optional[str] = None
    services: List[Dict[str, Any]] = Field(default_factory=list)


# ============================================================================
# STRIKER MODELS
# ============================================================================

class StrikerPlan(BaseModel):
    """Exploitation plan from Striker agent."""
    selected_module: str
    payload: str
    target_id: int
    required_options: Dict[str, str] = Field(default_factory=dict)
    rationale: str


class ExploitResult(BaseModel):
    """Result of an exploit attempt."""
    success: bool
    session_id: Optional[int] = None
    session_type: Optional[str] = None
    target: Optional[str] = None
    user_context: Optional[str] = None
    exploit_used: Optional[str] = None
    error: Optional[str] = None


# ============================================================================
# AUTOMOTIVE / OT MODELS
# ============================================================================

class CANCommand(BaseModel):
    """CAN bus command schema."""
    action: str
    can_id: str
    data: str
    duration: int = 1
    rationale: str


class OTDiscovery(BaseModel):
    """OT discovery data (CAN IDs, UDS services)."""
    can_arbitration_ids: List[str] = Field(default_factory=list)
    uds_services: Dict[str, List[str]] = Field(default_factory=dict)


class EmbeddedFinding(BaseModel):
    """Embedded/IoT protocol finding."""
    protocol: str  # MQTT, Modbus, CoAP
    endpoint: str
    access_level: str  # public, authenticated, admin
    critical_path: Optional[str] = None
    suggested_action: str
    rationale: str


# ============================================================================
# LIBRARIAN MODELS
# ============================================================================

class IntelligenceBrief(BaseModel):
    """Intelligence brief from Librarian (RAG + OSINT)."""
    summary: str
    technical_params: Dict[str, str] = Field(default_factory=dict)
    is_osint_derived: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    citations: List[str] = Field(default_factory=list)
    conflicting_sources: Optional[List[str]] = None


class OSINTFinding(BaseModel):
    """Individual OSINT finding."""
    source: str
    cve: Optional[str] = None
    description: Optional[str] = None
    exploit_available: bool = False
    data: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# RESIDENT MODELS
# ============================================================================

class SessionAudit(BaseModel):
    """Post-exploitation session audit."""
    session_id: int
    user_context: str
    os_kernel: Optional[str] = None
    internal_networks: List[str] = Field(default_factory=list)
    escalation_path: Optional[str] = None
    persistence_status: bool = False
    established_at: str = Field(default_factory=lambda: datetime.now().isoformat())


class ActiveSession(BaseModel):
    """Active session on a compromised target."""
    session_id: int
    target: str
    user: str
    exploit: Optional[str] = None
    session_type: str
    established: str = Field(default_factory=lambda: datetime.now().isoformat())


# ============================================================================
# ERROR HANDLING
# ============================================================================

class AgentError(BaseModel):
    """Error reported by an agent."""
    agent: str
    error_type: str
    error: str
    recoverable: bool = True
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
