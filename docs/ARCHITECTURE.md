# VT-SaiBER Architecture Documentation

## System Overview

VT-SaiBER is an autonomous multi-agent penetration testing system built on LangGraph. The system uses AI agents that make intelligent decisions about which security testing techniques to apply based on discovered information, rather than following hardcoded rules.

**Core Principle:** The AI decides what to do next, not the code.

---

## High-Level Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    LangGraph Orchestration                  │
│                                                             │
│   ┌──────────┐    ┌───────┐    ┌────────┐    ┌─────────┐    │
│   │Supervisor│ ←→ │ Scout │ ←→ │ Fuzzer │ ←→ │ Striker │    │
│   │  (AI)    │    │ (AI)  │    │  (AI)  │    │  (AI)   │    │
│   └──────────┘    └───────┘    └────────┘    └─────────┘    │
│        ↕              ↕            ↕             ↕          │
│   ┌────────────────────────────────────────────────────┐    │
│   │           Shared CyberState (TypedDict)            │    │
│   │  - discovered_targets                              │    │
│   │  - web_findings                                    │    │
│   │  - active_sessions                                 │    │
│   │  - agent_log                                       │    │
│   └────────────────────────────────────────────────────┘    │
│        ↕                                                    │
│   ┌────────────────────────────────────────────────────┐    │
│   │         PostgreSQL (State Persistence)             │    │
│   └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                          ↕
        ┌─────────────────────────────────────┐
        │    MCP Tool Servers (External)      │
        │  - Kali MCP (nmap, gobuster, etc.)  │
        │  - Metasploit MCP (exploits)        │
        └─────────────────────────────────────┘
```

---

## Core Components

### 1. LangGraph Workflow Engine

**What it does:** Orchestrates the flow of control between agents.

**Why we chose it:**
- Built-in state management
- Automatic checkpointing (can resume after crashes)
- Clear visualization of agent interactions
- Native support for conditional routing

**Graph Structure:**
```python
Supervisor (entry point)
    ↓ (decides next agent via LLM)
    ├─> Scout ──────┐
    ├─> Fuzzer ─────┤
    ├─> Striker ────┤  (all return to Supervisor)
    ├─> Librarian ──┤
    └─> Resident ───┘
         ↓
    Supervisor (re-evaluates)
         ↓
    (loop continues until mission complete)
```

**Key Design Decision:** 
- Each agent is a separate graph node
- State is passed between nodes automatically
- After each node runs, state is saved to PostgreSQL (checkpointing)

---

### 2. CyberState (Shared Memory)

**What it is:** A single TypedDict that all agents read from and write to.

**Why one state?**
- Single source of truth (no sync issues)
- LangGraph passes it to every node automatically
- Easy to debug ("what did the system know at step 5?")

**Structure:**
```python
class CyberState(TypedDict):
    # Graph Control
    current_agent: str              # Which agent just ran
    next_agent: Optional[str]       # Supervisor's decision
    iteration_count: int            # Safety counter
    mission_status: str             # "active" | "success" | "failed"
    
    # Mission Context
    mission_goal: str               # e.g., "Exploit 192.168.1.50"
    target_scope: List[str]         # Allowed IPs/subnets
    
    # Discovery Data (Scout writes here)
    discovered_targets: Annotated[Dict[str, Dict], operator.add]
    # {"192.168.1.50": {"ports": [22, 80], "services": {...}}}
    
    # Web Intelligence (Fuzzer writes here)
    web_findings: Annotated[List[Dict], operator.add]
    # [{"url": "/admin", "status": 200, "size": 1024}]
    
    # Exploitation State (Striker/Resident write here)
    active_sessions: Dict[int, Dict]
    exploited_services: List[str]
    
    # Knowledge (Librarian writes here)
    research_cache: Dict[str, str]
    osint_findings: List[Dict]
    
    # Audit Trail (Everyone writes here)
    agent_log: Annotated[List[Dict], operator.add]
    critical_findings: Annotated[List[str], operator.add]
    errors: Annotated[List[Dict], operator.add]
```

**Important:** The `Annotated[..., operator.add]` tells LangGraph to **merge** updates instead of overwriting. Without this, if Scout writes to `agent_log` and then Fuzzer writes to `agent_log`, Scout's entry would be lost.

---

### 3. Agent Architecture

#### The BaseAgent Pattern

All agents inherit from an abstract base class to ensure consistency:
```python
# src/agents/base.py

from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseAgent(ABC):
    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self.db = DatabaseManager()  # Shared DB access
        self.mcp = MCPClient()        # Shared tool access
    
    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """Each agent defines its own personality/goals"""
        pass
    
    @abstractmethod
    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """Core reasoning loop - must be implemented by each agent"""
        pass
    
    def log_finding(self, finding_type: str, data: Any):
        """Standard logging interface"""
        self.db.insert_finding(agent=self.name, type=finding_type, data=data)
    
    def validate_scope(self, target_ip: str) -> bool:
        """Global safety check"""
        return target_ip in allowed_subnets
```

**Why this works:**
- Every agent has the same interface (`call_llm(state) -> dict`)
- Graph doesn't care which agent it calls - they all work the same way
- New team members just copy the template and fill in their logic

---

### 4. The Supervisor Agent (The Brain)

**Role:** Makes high-level strategic decisions about which agent to call next.

**Critical Design Choice:** The Supervisor does NOT have hardcoded routing rules. Instead, it uses an LLM to interpret the current state and decide intelligently.

**How it works:**
```python
# src/agents/supervisor.py

async def supervisor_node(state: CyberState) -> Dict[str, Any]:
    """
    The Supervisor's job:
    1. Analyze what we know so far
    2. Decide what to do next
    3. Return the next agent to call
    """
    
    # Build context for the LLM
    context = build_context_summary(state)
    
    # Ask LLM to decide (with structured output)
    decision = await llm.with_structured_output(SupervisorDecision).ainvoke([
        SystemMessage(content=SUPERVISOR_SYSTEM_PROMPT),
        HumanMessage(content=context)
    ])
    
    # decision = {
    #   "next_agent": "fuzzer",
    #   "rationale": "Found HTTP server on port 80, should enumerate web directories",
    #   "confidence": 0.85
    # }
    
    # Log the decision
    log_decision(decision)
    
    # Return state updates
    return {
        "next_agent": decision.next_agent,
        "iteration_count": state["iteration_count"] + 1,
        "agent_log": state["agent_log"] + [{
            "agent": "supervisor",
            "decision": decision.next_agent,
            "reasoning": decision.rationale,
            "timestamp": datetime.now().isoformat()
        }]
    }
```

**Supervisor System Prompt (The Intelligence):**
```python
SUPERVISOR_SYSTEM_PROMPT = """
You are the Supervisor of an autonomous penetration testing team. Your job is to coordinate specialist agents to achieve the mission goal.

Available Agents:
- scout: Network reconnaissance (nmap, arp-scan)
- fuzzer: Web directory/API enumeration (gobuster, ffuf)
- striker: Exploitation (Metasploit)
- librarian: Research exploits and gather intelligence (RAG, OSINT)
- resident: Post-exploitation, persistence, pivoting (Meterpreter)

Decision-Making Guidelines:
1. Start with reconnaissance (scout) to discover targets
2. If web services found (ports 80, 443, 8080), use fuzzer to enumerate
3. Before exploiting, consult librarian for exploit requirements
4. After getting a shell, use resident for persistence and pivoting
5. Always validate that targets are in scope before attacking

Current Mission Status:
{context}

Decide which agent to call next and explain your reasoning.
Return your decision in this format:
{
  "next_agent": "scout" | "fuzzer" | "striker" | "librarian" | "resident" | "end",
  "rationale": "explanation of why this is the right next step",
  "confidence": 0.0-1.0
}
"""
```

**Why AI-Driven vs Hardcoded:**
```python
# ❌ WRONG: Hardcoded decision tree
def supervisor_node(state):
    if not state["discovered_targets"]:
        return {"next_agent": "scout"}
    elif 80 in state["ports"] and not state["web_findings"]:
        return {"next_agent": "fuzzer"}
    elif state["web_findings"] and not state["exploited"]:
        return {"next_agent": "striker"}
    # ... this gets unmaintainable fast

# ✅ CORRECT: LLM decides based on context
def supervisor_node(state):
    context = f"""
    Discovered: {state['discovered_targets']}
    Web Findings: {state['web_findings']}
    Sessions: {state['active_sessions']}
    """
    
    decision = llm.ainvoke([
        SystemMessage(content=SUPERVISOR_PROMPT),
        HumanMessage(content=context)
    ])
    
    # LLM intelligently decides based on the full picture
    return decision
```

**Benefits:**
- Handles unexpected scenarios (e.g., "found MQTT on 1883" - LLM can reason about this)
- Adapts to new information (if exploit fails, LLM can decide to try different approach)
- No maintenance of complex if/else trees

---

### 5. Worker Agents (The Specialists)

Each worker agent is a specialist that:
1. Receives the shared state
2. Performs its specific task (scan, fuzz, exploit, etc.)
3. Returns updated state
4. Control goes back to Supervisor

**Example: Scout Agent**
```python
# src/agents/scout.py

class ScoutAgent(BaseAgent):
    @property
    def system_prompt(self) -> str:
        return """
        You are a network reconnaissance specialist. Your job is to discover 
        targets, identify open ports, and fingerprint services.
        
        Available tools:
        - nmap: Port scanning and service detection
        - arp-scan: Discover live hosts on local network
        
        Your output should include:
        - IP addresses discovered
        - Open ports for each host
        - Service versions (critical for exploitation)
        - OS fingerprints if available
        
        Be thorough but avoid aggressive scans that might crash targets.
        """
    
    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """
        Scout's reasoning loop:
        1. Determine what to scan (from mission scope)
        2. Choose appropriate scan type
        3. Execute scan via MCP
        4. Parse and structure results
        5. Return findings
        """
        
        target = state["target_scope"][0]  # Get first target
        
        # LLM decides scan strategy
        strategy = await self.decide_scan_strategy(target, state)
        
        # Execute scan via MCP
        scan_result = await self.mcp.call_tool(
            "nmap",
            {
                "target": target,
                "flags": strategy["flags"]  # e.g., "-sV -sC"
            }
        )
        
        # Parse results (LLM interprets nmap output)
        findings = await self.parse_scan_results(scan_result)
        
        # Validate findings
        validated = self.validate_findings(findings)
        
        # Return state updates
        return {
            "discovered_targets": {
                target: validated
            },
            "agent_log": state["agent_log"] + [{
                "agent": "scout",
                "action": "nmap_scan",
                "target": target,
                "findings": validated,
                "timestamp": datetime.now().isoformat()
            }]
        }
```

**Key Insight:** The worker agent uses an LLM too! It's not just executing a script - it's making intelligent decisions about:
- What scan flags to use
- How to interpret the output
- Whether results look valid
- What's important vs. noise

---

### 6. Graph Routing (How Agents Connect)

**The router is simple - it just follows the Supervisor's decision:**
```python
# src/graph/router.py

def route_to_next_agent(state: CyberState) -> str:
    """
    This function is called by LangGraph to determine the next node.
    
    It does NOT contain business logic - it just reads the Supervisor's
    decision from the state.
    """
    
    # Safety checks (hardcoded limits, not business logic)
    if state["iteration_count"] >= 20:
        logger.warning("Max iterations reached")
        return "end"
    
    if state["mission_status"] in ["success", "failed"]:
        return "end"
    
    # Get Supervisor's decision
    next_agent = state.get("next_agent")
    
    # Validate it's a real agent
    valid_agents = ["scout", "fuzzer", "striker", "librarian", "resident"]
    
    if next_agent not in valid_agents:
        logger.warning(f"Invalid agent choice: {next_agent}")
        return "end"
    
    # Scope validation (safety, not business logic)
    if not validate_all_targets_in_scope(state):
        logger.error("Attempted to scan out-of-scope target!")
        return "end"
    
    return next_agent
```

**Important Distinction:**
- Router has **safety checks** (max iterations, scope validation)
- Router does NOT have **business logic** (if port 80, call fuzzer)
- Business logic lives in the Supervisor's LLM prompt

---

### 7. MCP Integration (Tool Execution)

**What is MCP?** Model Context Protocol - a standard way for AI agents to call external tools.

**Our architecture:**
```
Agent (Python)
    ↓ (calls via MCPClient)
MCP Server (separate process)
    ↓ (executes)
Tool (nmap, metasploit, etc.)
    ↓ (returns output)
MCP Server (formats response)
    ↓ (returns to)
Agent (interprets with LLM)
```

**Example:**
```python
# src/mcp/client.py

class MCPClient:
    """Unified interface to all MCP servers"""
    
    def __init__(self):
        self.kali_server = connect_to_server("kali-mcp")
        self.msf_server = connect_to_server("metasploit-mcp")
    
    async def call_tool(
        self, 
        tool_name: str, 
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Route tool calls to the appropriate MCP server
        """
        
        # Kali tools
        if tool_name in ["nmap", "gobuster", "ffuf", "arp-scan"]:
            return await self.kali_server.call_tool(tool_name, params)
        
        # Metasploit tools
        elif tool_name in ["search_modules", "run_exploit", "sessions"]:
            return await self.msf_server.call_tool(tool_name, params)
        
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
```

**Why MCP?**
- Standardized interface across all tools
- Tools run in isolated environments (Docker containers)
- Can swap tool implementations without changing agent code
- Security: agents can't execute arbitrary shell commands

---

### 8. State Persistence & Checkpointing

**How it works:**
```python
# src/main.py

from langgraph.checkpoint.postgres import PostgresSaver

# Initialize graph with PostgreSQL checkpointing
checkpointer = PostgresSaver(
    connection_string="postgresql://user:pass@localhost/vtsiber"
)

graph = build_graph()
compiled_graph = graph.compile(checkpointer=checkpointer)

# Run mission with a unique thread_id
config = {"configurable": {"thread_id": "mission-001"}}
result = await compiled_graph.ainvoke(initial_state, config)
```

**What gets saved:**
- State after every node execution
- Agent decisions and reasoning
- Tool outputs
- Timestamps

**Why this matters:**
- If system crashes at step 5, restart from step 5 (don't re-scan)
- Can inspect historical state: "What did we know when we decided to call Striker?"
- Essential for long-running missions

**Resume after crash:**
```python
# Later, resume the same mission
config = {"configurable": {"thread_id": "mission-001"}}
result = await compiled_graph.ainvoke(None, config)  # Continues from last checkpoint
```

---

### 9. Database Schema

**PostgreSQL stores two types of data:**

1. **LangGraph Checkpoints** (automatic)
   - Managed by `PostgresSaver`
   - Stores state snapshots
   - Used for resumption

2. **Mission Data** (our custom schema)
   - Findings, targets, sessions
   - Used for reporting and analysis

**Custom Schema:**
```sql
-- src/database/schema.sql

-- Discovered targets
CREATE TABLE targets (
    id SERIAL PRIMARY KEY,
    mission_id VARCHAR(255),
    ip_address VARCHAR(45),
    mac_address VARCHAR(17),
    os_guess VARCHAR(255),
    discovered_at TIMESTAMP DEFAULT NOW()
);

-- Open ports and services
CREATE TABLE services (
    id SERIAL PRIMARY KEY,
    target_id INTEGER REFERENCES targets(id),
    port INTEGER,
    protocol VARCHAR(10),  -- tcp/udp
    service_name VARCHAR(255),
    service_version VARCHAR(255),
    discovered_at TIMESTAMP DEFAULT NOW()
);

-- Findings (vulnerabilities, interesting files, etc.)
CREATE TABLE findings (
    id SERIAL PRIMARY KEY,
    mission_id VARCHAR(255),
    agent_name VARCHAR(50),
    finding_type VARCHAR(100),  -- 'open_port', 'web_directory', 'exploit_success'
    severity VARCHAR(20),       -- 'critical', 'high', 'medium', 'low', 'info'
    target_ip VARCHAR(45),
    data JSONB,                 -- Flexible storage for agent-specific data
    created_at TIMESTAMP DEFAULT NOW()
);

-- Agent decision log
CREATE TABLE agent_log (
    id SERIAL PRIMARY KEY,
    mission_id VARCHAR(255),
    agent_name VARCHAR(50),
    action VARCHAR(100),
    reasoning TEXT,
    state_snapshot JSONB,       -- Full state at decision time
    created_at TIMESTAMP DEFAULT NOW()
);

-- Exploitation sessions
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    mission_id VARCHAR(255),
    session_id INTEGER,         -- Metasploit session ID
    target_ip VARCHAR(45),
    user_context VARCHAR(100),  -- e.g., 'www-data', 'root'
    exploit_used VARCHAR(255),
    established_at TIMESTAMP DEFAULT NOW(),
    closed_at TIMESTAMP
);

-- Knowledge base for Librarian (RAG)
CREATE TABLE knowledge_base (
    id SERIAL PRIMARY KEY,
    doc_name VARCHAR(255),
    chunk_text TEXT,
    embedding vector(1536),     -- pgvector extension
    metadata JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Index for vector similarity search
CREATE INDEX ON knowledge_base USING ivfflat (embedding vector_cosine_ops);
```

---

## Execution Flow: A Complete Example

**Mission:** Exploit target 192.168.1.50

### Turn 1: Initialization
```
User: "Exploit 192.168.1.50"

Initial State:
{
  "mission_goal": "Exploit 192.168.1.50",
  "target_scope": ["192.168.1.0/24"],
  "iteration_count": 0,
  "mission_status": "active",
  "discovered_targets": {},
  "web_findings": [],
  "active_sessions": {},
  "agent_log": []
}

Graph: START → supervisor_node
```

### Turn 2: Supervisor Decides to Scout
```
Supervisor receives state, analyzes it:

LLM Input:
  "Mission: Exploit 192.168.1.50
   Current state: No targets discovered yet
   What should we do first?"

LLM Output:
  {
    "next_agent": "scout",
    "rationale": "No reconnaissance has been performed. Need to discover open ports and services on the target before attempting exploitation.",
    "confidence": 0.95
  }

State Update:
{
  "next_agent": "scout",
  "iteration_count": 1,
  "agent_log": [{
    "agent": "supervisor",
    "decision": "scout",
    "reasoning": "No reconnaissance performed yet...",
    "timestamp": "2026-02-02T14:30:00Z"
  }]
}

Graph: supervisor_node → scout_node
```

### Turn 3: Scout Performs Reconnaissance
```
Scout receives state, sees target: 192.168.1.50

Scout's LLM decides scan strategy:
  "Target is a single IP. Will run comprehensive service scan with version detection."

Scout calls MCP:
  tool: "nmap"
  params: {
    "target": "192.168.1.50",
    "flags": "-sV -sC -p-"
  }

MCP returns (raw nmap output):
  "PORT     STATE SERVICE    VERSION
   21/tcp   open  ftp        vsftpd 2.3.4
   22/tcp   open  ssh        OpenSSH 7.2p2
   80/tcp   open  http       Apache httpd 2.4.18"

Scout's LLM parses this:
  {
    "ip": "192.168.1.50",
    "ports": [21, 22, 80],
    "services": {
      21: {"name": "ftp", "version": "vsftpd 2.3.4"},
      22: {"name": "ssh", "version": "OpenSSH 7.2p2"},
      80: {"name": "http", "version": "Apache httpd 2.4.18"}
    }
  }

State Update:
{
  "discovered_targets": {
    "192.168.1.50": {
      "ports": [21, 22, 80],
      "services": {...}
    }
  },
  "agent_log": [...previous..., {
    "agent": "scout",
    "action": "nmap_scan",
    "findings": {...},
    "timestamp": "2026-02-02T14:31:00Z"
  }]
}

Database: INSERT INTO targets (...), INSERT INTO services (...)

Graph: scout_node → supervisor_node
```

### Turn 4: Supervisor Analyzes Scout Results
```
Supervisor receives updated state:

LLM Input:
  "Mission: Exploit 192.168.1.50
   Discoveries:
   - Port 21: vsftpd 2.3.4 (FTP)
   - Port 22: OpenSSH 7.2p2 (SSH)
   - Port 80: Apache httpd 2.4.18 (HTTP)
   
   What should we do next?"

LLM Output:
  {
    "next_agent": "fuzzer",
    "rationale": "Found HTTP server on port 80. Should enumerate web directories to find potential entry points before attempting exploitation. The FTP version (vsftpd 2.3.4) is known to have a backdoor vulnerability, but will investigate web surface first.",
    "confidence": 0.85
  }

State Update:
{
  "next_agent": "fuzzer",
  "iteration_count": 2,
  "agent_log": [...previous..., {supervisor decision}]
}

Graph: supervisor_node → fuzzer_node
```

### Turn 5: Fuzzer Enumerates Web Directories
```
Fuzzer receives state, sees HTTP service on port 80

Fuzzer's LLM decides strategy:
  "Apache server detected. Will use common web wordlist and look for PHP files."

Fuzzer calls MCP:
  tool: "gobuster"
  params: {
    "url": "http://192.168.1.50",
    "wordlist": "/usr/share/wordlists/dirb/common.txt",
    "extensions": "php,html"
  }

MCP returns:
  "/admin   (Status: 200)
   /api     (Status: 403)
   /login.php (Status: 200)"

Fuzzer's LLM interprets:
  {
    "findings": [
      {"path": "/admin", "status": 200, "interesting": true, "reason": "Admin panel found"},
      {"path": "/api", "status": 403, "interesting": true, "reason": "API endpoint (forbidden)"},
      {"path": "/login.php", "status": 200, "interesting": true, "reason": "Login page"}
    ]
  }

State Update:
{
  "web_findings": [
    {"url": "http://192.168.1.50/admin", "status": 200, ...},
    {"url": "http://192.168.1.50/api", "status": 403, ...},
    {"url": "http://192.168.1.50/login.php", "status": 200, ...}
  ],
  "critical_findings": [
    "Admin panel found at /admin"
  ],
  "agent_log": [...previous..., {fuzzer action}]
}

Graph: fuzzer_node → supervisor_node
```

### Turn 6: Supervisor Consults Librarian
```
Supervisor receives updated state:

LLM Input:
  "Mission: Exploit 192.168.1.50
   Discoveries:
   - FTP: vsftpd 2.3.4
   - HTTP: Apache 2.4.18 with /admin panel
   
   What should we do next?"

LLM Output:
  {
    "next_agent": "librarian",
    "rationale": "Before attempting exploitation, should research known vulnerabilities for vsftpd 2.3.4. This version is known to have a backdoor. Need exploit requirements before proceeding.",
    "confidence": 0.90
  }

Graph: supervisor_node → librarian_node
```

### Turn 7: Librarian Researches Exploit
```
Librarian receives state, sees vsftpd 2.3.4

Librarian's LLM searches knowledge base:
  Query: "vsftpd 2.3.4 exploit"

RAG search returns (from vectorized docs):
  "vsftpd 2.3.4 contains a backdoor triggered by sending a username 
   ending with :) to port 21. Exploit module: exploit/unix/ftp/vsftpd_234_backdoor"

Librarian also queries OSINT (Tavily API):
  Finds CVE-2011-2523, confirms backdoor exists

State Update:
{
  "research_cache": {
    "vsftpd 2.3.4": "exploit/unix/ftp/vsftpd_234_backdoor"
  },
  "osint_findings": [{
    "cve": "CVE-2011-2523",
    "description": "Backdoor in vsftpd 2.3.4",
    "exploit_available": true
  }],
  "agent_log": [...previous..., {librarian research}]
}

Graph: librarian_node → supervisor_node
```

### Turn 8: Supervisor Calls Striker
```
Supervisor receives updated state:

LLM Input:
  "Mission: Exploit 192.168.1.50
   Research findings: vsftpd 2.3.4 backdoor exploit available
   Exploit module: exploit/unix/ftp/vsftpd_234_backdoor
   
   What should we do next?"

LLM Output:
  {
    "next_agent": "striker",
    "rationale": "Librarian confirmed exploitable vulnerability in vsftpd 2.3.4. Exploit module is available. Should attempt exploitation to gain initial access.",
    "confidence": 0.95
  }

Graph: supervisor_node → striker_node
```

### Turn 9: Striker Exploits Target
```
Striker receives state, sees exploit recommendation

Striker's LLM plans exploitation:
  "Will use vsftpd_234_backdoor exploit against 192.168.1.50:21"

Striker calls MCP:
  tool: "run_exploit"
  params: {
    "module": "exploit/unix/ftp/vsftpd_234_backdoor",
    "options": {
      "RHOSTS": "192.168.1.50",
      "RPORT": 21
    }
  }

MCP returns:
  {
    "success": true,
    "session_id": 1,
    "session_type": "shell",
    "target": "192.168.1.50"
  }

Striker verifies session:
  Runs: "whoami"
  Returns: "root"

State Update:
{
  "active_sessions": {
    1: {
      "target": "192.168.1.50",
      "user": "root",
      "exploit": "vsftpd_234_backdoor",
      "established": "2026-02-02T14:35:00Z"
    }
  },
  "exploited_services": ["vsftpd 2.3.4"],
  "mission_status": "success",  # Got root access!
  "critical_findings": [
    ...previous...,
    "ROOT shell obtained on 192.168.1.50 via vsftpd backdoor"
  ],
  "agent_log": [...previous..., {striker exploit success}]
}

Graph: striker_node → supervisor_node
```

### Turn 10: Supervisor Declares Success
```
Supervisor receives updated state:

LLM Input:
  "Mission: Exploit 192.168.1.50
   Status: ROOT shell obtained on target
   
   Mission goal achieved?"

LLM Output:
  {
    "next_agent": "end",
    "rationale": "Mission goal achieved. We have root access on 192.168.1.50. No further action needed.",
    "confidence": 1.0
  }

State Update:
{
  "next_agent": "end",
  "mission_status": "success",
  "iteration_count": 9
}

Graph: supervisor_node → END
```

---

## Key Architectural Principles

### 1. Separation of Concerns

**What:** Each component has a single, clear responsibility.

**Why:** Makes the system easier to understand, test, and modify.

**How we achieve this:**
- **Agents** → Business logic (what to do)
- **MCP** → Tool execution (how to do it)
- **State** → Data storage (what we know)
- **Graph** → Flow control (what happens next)
- **Database** → Persistence (remember for later)

### 2. AI-First Decision Making

**What:** The LLM makes tactical and strategic decisions, not hardcoded rules.

**Why:** 
- Handles unexpected situations
- Adapts to new information
- Scales to new targets/scenarios
- More robust than brittle if/else logic

**What we hardcode:**
- Safety limits (max iterations, scope validation)
- Data structures (state schema)
- Tool interfaces (MCP client)

**What the AI decides:**
- Which agent to call next
- Which tools to use
- How to interpret results
- When the mission is complete

### 3. State as Single Source of Truth

**What:** All information flows through the CyberState TypedDict.

**Why:**
- No hidden state in individual agents
- Easy to debug ("what did we know at step X?")
- Checkpointing works automatically
- Agents are stateless (easier to test)

**How it works:**
```python
# Agent receives state
def agent_node(state: CyberState):
    # Read from state
    target = state["target_scope"][0]
    
    # Do work...
    
    # Return updates (doesn't mutate input)
    return {"discovered_targets": {...}}

# LangGraph merges the updates
new_state = {**old_state, **agent_updates}
```

### 4. Modularity Through Abstraction

**What:** All agents follow the same interface (BaseAgent).

**Why:**
- Team members can work in parallel
- Easy to add new agents
- Can swap agent implementations
- Consistent testing approach

**Example:**
```python
# All agents have this signature:
async def agent_node(state: CyberState) -> Dict[str, Any]:
    pass

# So the graph doesn't care which agent it's calling:
graph.add_node("scout", scout_node)
graph.add_node("fuzzer", fuzzer_node)
# Both work the same way from graph's perspective
```

### 5. Fail-Safe by Design

**What:** System has multiple layers of safety checks.

**Why:** Pentesting tools can be destructive; need to prevent accidents.

**Safety Layers:**
1. **Scope Validation** → Prevent scanning non-authorized targets
2. **Iteration Limits** → Prevent infinite loops
3. **Tool Restrictions** → Agents can only call specific tools
4. **Human-in-the-Loop** → Can pause for approval on critical actions
5. **Checkpointing** → Can resume safely after crashes

---

## Development Workflow

### How to Add a New Agent

1. **Create agent file:**
```python
# src/agents/new_agent.py

from src.agents.base import BaseAgent
from src.state.cyber_state import CyberState

class NewAgent(BaseAgent):
    @property
    def system_prompt(self) -> str:
        return """
        Your role description here...
        """
    
    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        # Your logic here
        return {"state_updates": ...}

# Node function for graph
async def new_agent_node(state: CyberState) -> Dict[str, Any]:
    agent = NewAgent("new_agent", "role description")
    return await agent.call_llm(state)
```

2. **Add to graph:**
```python
# src/graph/builder.py

from src.agents.new_agent import new_agent_node

def build_graph():
    graph.add_node("new_agent", new_agent_node)
    graph.add_edge("new_agent", "supervisor")
```

3. **Update router:**
```python
# src/graph/router.py

def route_to_next_agent(state):
    valid_agents = [..., "new_agent"]
    # ...
```

4. **Update Supervisor prompt:**
```python
# src/prompts/supervisor_prompt.py

SUPERVISOR_PROMPT = """
Available Agents:
- ...
- new_agent: Your new agent's description
"""
```

### How to Test an Agent in Isolation
```python
# tests/test_new_agent.py

import pytest
from src.agents.new_agent import NewAgent
from src.state.cyber_state import CyberState

@pytest.mark.asyncio
async def test_new_agent():
    # Create test state
    test_state: CyberState = {
        "mission_goal": "test",
        "target_scope": ["192.168.1.0/24"],
        "iteration_count": 1,
        # ... other required fields
    }
    
    # Create agent
    agent = NewAgent("new_agent", "test role")
    
    # Call it
    result = await agent.call_llm(test_state)
    
    # Verify output
    assert "state_updates" in result
    assert result["state_updates"]["some_field"] == "expected_value"
```

### How to Debug a Mission

**1. Check LangSmith trace:**
```
https://smith.langchain.com/o/your-org/projects/vtsiber
```
- See every node execution
- View LLM inputs/outputs
- Check state at each step

**2. Query the database:**
```sql
-- See agent decisions
SELECT agent_name, action, reasoning, created_at 
FROM agent_log 
WHERE mission_id = 'mission-001'
ORDER BY created_at;

-- See what was discovered
SELECT * FROM findings 
WHERE mission_id = 'mission-001';
```

**3. Resume from checkpoint:**
```python
# Load state from specific step
config = {
    "configurable": {
        "thread_id": "mission-001",
        "checkpoint_id": "step-5"
    }
}

# Continue from there
result = await graph.ainvoke(None, config)
```

---

## Performance Considerations

### Context Window Management

**Challenge:** Long missions accumulate large state that exceeds LLM context limits.

**Solution:** Summarize old agent_log entries
```python
def trim_agent_log(state: CyberState) -> CyberState:
    """Keep only last 10 entries, summarize older ones"""
    if len(state["agent_log"]) > 10:
        old_entries = state["agent_log"][:-10]
        summary = llm.summarize(old_entries)
        
        return {
            **state,
            "agent_log": [{
                "agent": "system",
                "action": "summary",
                "content": summary
            }] + state["agent_log"][-10:]
        }
    return state
```

### LLM Call Optimization

**Challenge:** Every node calls an LLM, which is slow/expensive.

**Solutions:**
1. **Use faster models for simple tasks:**
```python
# Scout uses GPT-4o (needs good reasoning)
scout_llm = ChatOpenAI(model="gpt-4o")

# Router uses GPT-3.5 (simple validation)
router_llm = ChatOpenAI(model="gpt-3.5-turbo")
```

2. **Cache repetitive queries:**
```python
# If we've already researched vsftpd 2.3.4, don't ask Librarian again
if "vsftpd 2.3.4" in state["research_cache"]:
    exploit = state["research_cache"]["vsftpd 2.3.4"]
else:
    exploit = await librarian.research("vsftpd 2.3.4")
```

3. **Parallelize independent operations** (future work):
```python
# If scanning multiple IPs, could run Scouts in parallel
# See "Advanced Topics" section
```

---

## Security & Safety

### Scope Enforcement
```python
# src/utils/validators.py

import ipaddress

ALLOWED_SUBNETS = [
    ipaddress.ip_network("192.168.1.0/24"),
    ipaddress.ip_network("10.0.0.0/8")
]

def validate_target(ip: str) -> bool:
    """Ensure target is in authorized scope"""
    target_ip = ipaddress.ip_address(ip)
    
    for subnet in ALLOWED_SUBNETS:
        if target_ip in subnet:
            return True
    
    raise ValueError(f"Target {ip} is out of scope!")
```

### Tool Access Control
```python
# src/agents/base.py

class BaseAgent:
    # Define which tools each agent can use
    ALLOWED_TOOLS = []  # Override in subclass
    
    async def call_tool(self, tool_name: str, params: Dict):
        if tool_name not in self.ALLOWED_TOOLS:
            raise PermissionError(
                f"{self.name} is not allowed to use {tool_name}"
            )
        
        return await self.mcp.call_tool(tool_name, params)

# src/agents/scout.py
class ScoutAgent(BaseAgent):
    ALLOWED_TOOLS = ["nmap", "arp-scan"]  # No exploits!

# src/agents/striker.py
class StrikerAgent(BaseAgent):
    ALLOWED_TOOLS = ["search_modules", "run_exploit"]  # Exploitation only
```

### Human Approval for Critical Actions
```python
# src/agents/striker.py

async def striker_node(state: CyberState) -> Dict[str, Any]:
    # Plan exploit
    exploit_plan = await plan_exploitation(state)
    
    # Request human approval
    if not state.get("auto_exploit_approved"):
        print(f"About to run: {exploit_plan['module']}")
        print(f"Target: {exploit_plan['target']}")
        
        approval = input("Proceed? (yes/no): ")
        
        if approval.lower() != "yes":
            return {
                "mission_status": "paused",
                "errors": state["errors"] + [{
                    "agent": "striker",
                    "error": "Exploit declined by user"
                }]
            }
    
    # Proceed with exploit...
```

---

## Common Pitfalls & Solutions

### Pitfall 1: State Updates Not Persisting

**Problem:**
```python
# Agent modifies state in-place (WRONG!)
def bad_agent(state: CyberState):
    state["discovered_targets"]["192.168.1.1"] = {...}
    return state  # LangGraph doesn't see the change!
```

**Solution:**
```python
# Agent returns new dict (CORRECT)
def good_agent(state: CyberState):
    return {
        "discovered_targets": {
            **state["discovered_targets"],
            "192.168.1.1": {...}
        }
    }
```

### Pitfall 2: Forgetting `operator.add` on Lists

**Problem:**
```python
class CyberState(TypedDict):
    agent_log: List[Dict]  # WRONG! Will overwrite

# Agent 1 writes
return {"agent_log": [{"agent": "scout", ...}]}

# Agent 2 writes (overwrites Agent 1!)
return {"agent_log": [{"agent": "fuzzer", ...}]}
```

**Solution:**
```python
from typing import Annotated
import operator

class CyberState(TypedDict):
    agent_log: Annotated[List[Dict], operator.add]  # CORRECT! Merges

# Now both entries are preserved
```

### Pitfall 3: LLM Hallucinating Non-Existent Agents

**Problem:** Supervisor decides `next_agent = "super_hacker"` (doesn't exist)

**Solution:**
```python
# Use structured output with enum
from enum import Enum

class AgentChoice(str, Enum):
    SCOUT = "scout"
    FUZZER = "fuzzer"
    STRIKER = "striker"
    LIBRARIAN = "librarian"
    RESIDENT = "resident"
    END = "end"

class SupervisorDecision(BaseModel):
    next_agent: AgentChoice  # Must be one of these!
    rationale: str

# LLM can only choose valid agents
decision = await llm.with_structured_output(SupervisorDecision).ainvoke(...)
```

### Pitfall 4: Infinite Loops

**Problem:** Supervisor keeps calling Scout forever

**Solution:**
```python
# Add iteration counter
def route_to_next_agent(state: CyberState) -> str:
    MAX_ITERATIONS = 20
    
    if state["iteration_count"] >= MAX_ITERATIONS:
        logger.error("Max iterations reached!")
        return "end"
    
    return state["next_agent"]
```

---

## Future Enhancements

### Parallel Agent Execution

**Current:** Agents run sequentially
**Future:** Multiple agents work simultaneously
```python
from langgraph.constants import Send

def route_parallel(state: CyberState) -> list[Send]:
    """Scan multiple targets in parallel"""
    tasks = []
    
    for ip in state["target_scope"]:
        tasks.append(Send("scout", {"target": ip}))
    
    return tasks

graph.add_conditional_edges("supervisor", route_parallel, ["scout"])
```

### Advanced Planning

**Current:** Supervisor decides one step at a time
**Future:** Multi-step planning with backtracking
```python
class SupervisorDecision(BaseModel):
    next_agent: str
    mission_plan: List[str]  # ["fuzzer", "librarian", "striker"]
    alternative_plans: List[List[str]]  # Backup plans if primary fails
```

### Self-Improvement

**Future:** System learns from past missions
```python
# After each mission, analyze what worked
def analyze_mission(mission_id: str):
    logs = db.get_mission_logs(mission_id)
    
    # What agents were most effective?
    # Which exploits worked?
    # What mistakes were made?
    
    insights = llm.analyze(logs)
    
    # Update agent prompts based on insights
    update_prompts_with_lessons_learned(insights)
```

---

## Glossary

- **Agent:** An AI-powered specialist that performs a specific pentesting task
- **CyberState:** The shared memory structure that all agents read/write
- **LangGraph:** The orchestration framework that manages agent workflow
- **MCP (Model Context Protocol):** Standard interface for agents to call tools
- **Node:** A single step in the LangGraph workflow (typically one agent call)
- **Checkpoint:** A saved snapshot of state that allows resuming after crashes
- **Supervisor:** The coordinating agent that decides which specialist to call next
- **Worker Agent:** Specialist agent (Scout, Fuzzer, Striker, etc.)

---

## Team Contacts & Ownership

- **Teammate 1 (Architect):** Supervisor, Graph, State architecture
- **Teammate 2 (Infrastructure):** MCP, Docker, Striker, Resident
- **Teammate 3 (Agent Developer):** Scout, Fuzzer, Parsers
- **Teammate 4 (Data Lead):** Database, Librarian, RAG
- **Teammate 5 (Quality Engineer):** Prompts, Tests, Documentation

---

## Additional Resources

- [LangGraph Documentation](https://langchain-ai.github.io/langgraph/)
- [Model Context Protocol Spec](https://modelcontextprotocol.io/)
- [Kali MCP Server](https://www.kali.org/tools/mcp-kali-server/)
- [MITRE ATT&CK ICS Matrix](https://attack.mitre.org/matrices/ics/)
- [Project GitHub Repository](https://github.com/your-org/vt-saiber)

---

**Last Updated:** February 2, 2026  
**Version:** 1.0  
**Status:** Living Document (update as architecture evolves)