
## Scope and Intent

This file is a requirements/specification document, not a strict implementation mirror.

Current implementation reference points:
- Dynamic MCP bridge: `src/mcp/mcp_tool_bridge.py`
- Supervisor routing + safety checks: `src/agents/supervisor.py`, `src/graph/router.py`
- Embedded/IoT agent: removed from active project scope

In other words, treat this document as target behavior and guardrail intent, and verify runtime specifics against code paths above.

Design direction:
- All agents are intended to be ReAct; a hybrid architecture is not the target.

---

## Supervisor Agent

The Supervisor must be implemented as a centralized routing node that manages the transition between worker agents based on the evaluation of the CyberState.

---

## A. CyberState Definition (System-Wide Shared State)

The Supervisor is responsible for maintaining the integrity of the following system-wide shared state, which acts as long-term memory during execution:

- **Mission Goal** (`str`)  
  The objective (e.g., *Exploit the ICSim Speedometer*)

- **Target Map** (`Dict[str, Dict]`)  
  Mapping of IP addresses to discovered ports, services, and vulnerabilities

- **OT Discovery** (`Dict[str, List]`)  
  Mapping of CAN Arbitration IDs and detected UDS services

- **Agent Log** (`List[Dict]`)  
  Chronological history of agent calls, commands executed, and outcomes

- **Critical Findings** (`List[str]`)  
  High-priority leads (e.g., *Anonymous MQTT access found*)

---

## B. Decision Logic & Structured Output

The Supervisor MUST use a zero-temperature LLM with strict JSON schema enforcement.

```python
from pydantic import BaseModel, Field

class SupervisorDecision(BaseModel):
    next_agent: str = Field(description="The name of the next specialist agent to call.")
    rationale: str = Field(description="The logical reasoning for this delegation.")
    specific_goal: str = Field(description="The granular task for the worker.")
    confidence_score: float = Field(ge=0, le=1.0)
````

---

## Advanced Routing & Recursion Management

### OSINT / Librarian Loop

**REQ-SUP-2.1**
If the Scout discovers a service version (e.g., *ProFTPD 1.3.5*), the Supervisor MUST route to the Librarian before routing to the Striker.

### Backtracking Logic

**REQ-SUP-2.2**
If the Striker reports a FAILED exploit, the Supervisor MUST:

* Request an alternative exploit from the Librarian, or
* Route back to the Web Fuzzer to identify a new entry point

### State Persistence

**REQ-SUP-2.3**
Every Supervisor ↔ Worker transition MUST be persisted using:

```
langgraph.checkpoint.postgres.PostgresSaver
```

---

## Mandatory Guardrails & Safety

### Operational Limits

* **REQ-SUP-3.1 (Iteration Cap)**
  If more than 20 agent handoffs occur without mission success or failure, the system MUST enter `WAIT_FOR_HUMAN`.

* **REQ-SUP-3.2 (Safety Lock)**
  Any destructive tool call requires manual approval before execution.

* **REQ-SUP-3.3 (Least Privilege)**
  The Supervisor MUST NOT have direct access to the MCP `call_tool` interface.

* **REQ-SUP-3.4 (Scope Validation)**
  Targets outside the authorized CIDR block MUST immediately abort the mission.

---

## Network Scout Agent

The Scout is a ReAct-style agent that interprets noisy network data.

### Core Responsibilities

1. Analyze ARP tables using `arp-scan`
2. Perform intelligent service fingerprinting
3. Prioritize low-hanging fruit vs specialized OT targets
4. Convert CLI output into structured, validated data

---

## Web Fuzzer Agent

The Web Fuzzer discovers hidden web attack surfaces between the Scout and Striker.

### Web Context State

* `ip_address`
* `mac_vendor`
* `services (port, name, version)`
* `base_url`
* `discovered_paths`
* `wordlist_strategy`

### Structured Output

```python
class WebFinding(BaseModel):
    path: str
    status_code: int
    content_length: int
    content_type: str
    is_api_endpoint: bool
    rationale: str
```

### Guardrails

* GET and HEAD methods only by default
* Recursive depth limited to 3
* Mandatory request throttling (≥200ms)
* Soft-404 detection enforced
* Scope lock required for all scans

---

## Striker Agent (Exploitation)

The Striker executes precision exploits using Metasploit.

### Exploit Plan

```python
class StrikerPlan(BaseModel):
    selected_module: str
    payload: str
    target_id: int
    required_options: Dict[str, str]
    rationale: str
```

### Constraints

* Exploit rank MUST be Great or higher
* Maximum of 3 attempts per exploit
* Hard timeout required for every run
* DoS and fuzzing modules are forbidden
* Successful sessions MUST be verified with `getuid` or `whoami`

---

## Automotive Agent (CAN / OT)

The Automotive Agent interacts with the CAN bus and UDS services.

### Command Schema

```python
class CANCommand(BaseModel):
    action: str
    can_id: str
    data: str
    duration: int
    rationale: str
```

### Safety Requirements

* Message rate ≤100 frames/second
* Critical ID fuzzing is forbidden
* Baseline sniffing required before injection
* Response verification mandatory after sending

---

## Librarian Agent (RAG & OSINT)

The Librarian prevents hallucinations by supplying verified intelligence.

```python
class IntelligenceBrief(BaseModel):
    summary: str
    technical_params: Dict[str, str]
    is_osint_derived: bool
    confidence: float
    citations: List[str]
```

### Requirements

* All technical steps MUST be cited
* Conflicting sources MUST be reported
* Prompt-injection sanitization enforced
* OSINT fallback required below similarity threshold

---

## Resident Agent (Post-Exploitation)

The Resident maintains access and enables lateral movement.

```python
class SessionAudit(BaseModel):
    session_id: int
    user_context: str
    os_kernel: str
    internal_networks: List[str]
    escalation_path_found: Optional[str]
    persistence_status: bool
```

### Responsibilities

* Internal network discovery
* Privilege escalation analysis
* Persistence engineering
* Change logging and cleanup

---

## Chain of Command

1. Scout discovers the target
2. Web Fuzzer finds the entry point
3. Librarian retrieves exploit intelligence
4. Striker gains initial access
5. Resident pivots and persists
6. Automotive agent (optional path) handles CAN/OT-specific operations
