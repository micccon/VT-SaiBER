from __future__ import annotations

from typing import Any, Annotated, Dict, List, Optional, TypedDict


def _merge_lists(left: Optional[List[Any]], right: Optional[List[Any]]) -> List[Any]:
    return list(left or []) + list(right or [])


def _merge_dicts(left: Optional[Dict[str, Any]], right: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    merged = dict(left or {})
    merged.update(dict(right or {}))
    return merged


class CyberState(TypedDict):
    # Graph Control
    current_agent: str                     # Which agent just ran
    next_agent: Optional[str]              # Supervisor's decision
    iteration_count: int                   # Safety counter
    mission_status: str                    # active | success | failed | wait_for_human

    # Mission Context
    mission_goal: str                      # e.g., "Exploit 192.168.1.50"
    target_scope: List[str]                # Allowed IPs/subnets
    mission_id: str                        # Unique identifier for the mission

    # Discovery Data
    discovered_targets: Annotated[Dict[str, Dict[str, Any]], _merge_dicts]
    ot_discovery: Annotated[Dict[str, List[Any]], _merge_dicts]

    # Web Intelligence
    web_findings: Annotated[List[Dict[str, Any]], _merge_lists]

    # Exploitation State
    active_sessions: Annotated[Dict[str, Dict[str, Any]], _merge_dicts]
    exploited_services: Annotated[List[Dict[str, Any]], _merge_lists]

    # Knowledge
    research_cache: Annotated[Dict[str, Any], _merge_dicts]
    osint_findings: Annotated[List[Dict[str, Any]], _merge_lists]

    # Supervisor memory / expectations
    supervisor_messages: List[Dict[str, Any]]
    supervisor_expectations: Dict[str, Any]

    # Audit Trail
    agent_log: Annotated[List[Dict[str, Any]], _merge_lists]
    critical_findings: Annotated[List[str], _merge_lists]
    errors: Annotated[List[Dict[str, Any]], _merge_lists]
