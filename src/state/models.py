from typing import List, Dict, Optional, Any, Literal
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
    LIBRARIAN = "librarian"
    STRIKER = "striker"
    RESIDENT = "resident"


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
# EXPLOIT MODELS
# ============================================================================

class ExploitBackend(str, Enum):
    """Canonical exploit backend selector for the unified striker worker."""
    METASPLOIT = "metasploit"
    KALI = "kali"

class MetasploitSearchPlan(BaseModel):
    """Bounded LLM search-plan output for the hybrid Metasploit worker."""
    decision: Literal["search", "stop"] = "search"
    target: str = ""
    port: int = 0
    service_name: str = ""
    module_type_preference: Literal["exploit", "auxiliary", "either"] = "either"
    search_terms: List[str] = Field(default_factory=list)
    rationale: str = ""
    stop_reason: Optional[str] = None


class MetasploitSelectionPlan(BaseModel):
    """Bounded LLM module-selection output for the hybrid Metasploit worker."""
    decision: Literal["execute", "stop", "pivot"] = "stop"
    module: str = ""
    module_type: Literal["exploit", "auxiliary"] = "exploit"
    target: str = ""
    port: int = 0
    option_overrides: Dict[str, Any] = Field(default_factory=dict)
    payload_name: Optional[str] = None
    payload_options: Dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    stop_reason: Optional[str] = None


class MetasploitService(BaseModel):
    """Normalized service evidence used by the Metasploit worker."""
    target: str
    port: int
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None


class MetasploitEvidence(BaseModel):
    """Condensed CyberState evidence for module search and execution."""
    services: List[MetasploitService] = Field(default_factory=list)
    cves: List[str] = Field(default_factory=list)
    web_paths: List[str] = Field(default_factory=list)
    credentials: Dict[str, Any] = Field(default_factory=dict)
    operator_options: Dict[str, Any] = Field(default_factory=dict)


class MetasploitCandidate(BaseModel):
    """Candidate Metasploit module ranked against observed evidence."""
    module: str
    module_type: str
    service: MetasploitService
    score: int = 0
    matched_terms: List[str] = Field(default_factory=list)


class MetasploitExecutionPlan(BaseModel):
    """Executable Metasploit plan after option resolution."""
    candidate: MetasploitCandidate
    options: Dict[str, Any] = Field(default_factory=dict)
    payload_name: Optional[str] = None
    payload_options: Dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""


class MetasploitAttempt(BaseModel):
    """Persisted record of a Metasploit execution attempt."""
    target: str
    module: str
    status: str
    session_id: Optional[int] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


class ExploitKaliPlan(BaseModel):
    """Execution plan for the Kali exploitation worker."""
    selected_tool: str
    target: str
    command: Optional[str] = None
    arguments: Dict[str, Any] = Field(default_factory=dict)
    rationale: str


class ExploitAttempt(BaseModel):
    """Shared persisted record for one bounded striker execution attempt."""
    backend: ExploitBackend
    tool_or_module: str
    target: str
    status: str
    failure_reason: Optional[str] = None
    session_id: Optional[int] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())


class StrikerPlan(BaseModel):
    """Single bounded execution plan for one striker invocation."""
    backend: ExploitBackend
    target: str
    goal: str
    tool_or_module: str
    rationale: str
    option_hints: Dict[str, Any] = Field(default_factory=dict)


class ExploitResult(BaseModel):
    """Shared result shape for exploit worker attempts."""
    success: bool
    backend: Optional[ExploitBackend] = None
    tool_or_module: Optional[str] = None
    status: str = ""
    failure_reason: Optional[str] = None
    session_id: Optional[int] = None
    session_type: Optional[str] = None
    target: Optional[str] = None
    user_context: Optional[str] = None
    exploit_used: Optional[str] = None
    error: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


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
    technical_params: Dict[str, Any] = Field(default_factory=dict)
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
    user: Optional[str] = None
    exploit: Optional[str] = None
    session_type: Optional[str] = None
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
