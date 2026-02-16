from typing import TypedDict, List, Dict, Optional, Annotated
import operator


class CyberState(TypedDict):
    # Graph Control
    current_agent: str              # Which agent just ran
    next_agent: Optional[str]       # Supervisor's decision
    iteration_count: int            # Safety counter
    mission_status: str             # "active" | "success" | "failed"
    
    # Mission Context
    mission_goal: str               # e.g., "Exploit 192.168.1.50"
    target_scope: List[str]         # Allowed IPs/subnets
    mission_id: str                 # Unique identifier for the mission
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