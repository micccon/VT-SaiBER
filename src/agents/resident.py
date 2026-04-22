"""
Resident Agent - Post-Exploitation Specialist.

Maintains access and performs post-exploitation activities on open sessions.
Uses LangGraph's create_react_agent for autonomous enumeration and escalation.
"""

from __future__ import annotations

import inspect
import json
import os
from datetime import datetime
from typing import Any, Dict, List

from langchain_core.messages import ToolMessage
from langgraph.prebuilt import create_react_agent

from src.database.persistence import persist_state_update
from src.mcp.mcp_tool_bridge import get_mcp_bridge
from src.prompts.resident_prompt import RESIDENT_SYSTEM_PROMPT
from src.state.cyber_state import CyberState
from src.state.models import AgentError, AgentLogEntry

try:
    from langchain_openai import ChatOpenAI
except Exception:  # pragma: no cover - optional dependency path
    ChatOpenAI = None


RESIDENT_ALLOWED_TOOLS = {
    "list_active_sessions",
    "send_session_command",
    "run_post_module",
    "list_exploits",
    "terminate_session",
}

POST_TOOL_NAMES = {"msf_send_session_command", "msf_run_post_module"}


def _build_llm():
    provider = os.getenv("LLM_CLIENT", "openrouter").strip().lower()
    if provider != "openrouter":
        raise RuntimeError(
            f"Unsupported LLM_CLIENT='{provider}'. "
            "Current VT-SaiBER config supports openrouter only."
        )
    if ChatOpenAI is None:
        raise RuntimeError("langchain-openai is not installed")
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is required when LLM_CLIENT=openrouter")
    model = os.getenv("LLM_MODEL", "nvidia/nemotron-3-super-120b-a12b:free")
    return ChatOpenAI(
        model=model,
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        temperature=0,
    )


def _create_react_agent_with_prompt(model, tools, system_prompt: str):
    try:
        params = inspect.signature(create_react_agent).parameters
    except Exception:
        params = {}

    if "prompt" in params:
        return create_react_agent(model=model, tools=tools, prompt=system_prompt)
    if "state_modifier" in params:
        return create_react_agent(model=model, tools=tools, state_modifier=system_prompt)
    return create_react_agent(model=model, tools=tools)


def _build_resident_context(state: CyberState) -> str:
    active_sessions = state.get("active_sessions", {}) or {}
    discovered_targets = state.get("discovered_targets", {}) or {}
    research_cache = state.get("research_cache", {}) or {}
    intelligence_findings = state.get("intelligence_findings", []) or []

    sessions_lines = []
    for target, info in active_sessions.items():
        sid = info.get("session_id", "?")
        module = info.get("module", "unknown")
        established = info.get("established_at", "?")
        sessions_lines.append(
            f"  session_id={sid}  target={target}  via={module}  opened={established}"
        )
    sessions_block = "\n".join(sessions_lines) if sessions_lines else "  (none)"

    target_lines = []
    for ip, data in discovered_targets.items():
        os_guess = data.get("os_guess", "unknown")
        services = data.get("services", {})
        svc_names = [
            value.get("service_name", str(value)) if isinstance(value, dict) else str(value)
            for value in list(services.values())[:5]
        ]
        target_lines.append(f"  {ip}  OS: {os_guess}  services: {', '.join(svc_names)}")
    targets_block = "\n".join(target_lines) if target_lines else "  (none)"

    research_lines = []
    for key, value in list(research_cache.items())[:4]:
        research_lines.append(f"  {key}: {str(value)[:120]}")
    for finding in intelligence_findings[:3]:
        if not isinstance(finding, dict):
            continue
        desc = finding.get("description", "")
        cve = finding.get("cve", "")
        if desc:
            prefix = f"[{cve}] " if cve else ""
            research_lines.append(f"  OSINT: {prefix}{desc[:120]}")
    research_block = "\n".join(research_lines) if research_lines else "  (none)"

    return (
        f"MISSION: {state.get('mission_goal') or '(not specified)'}\n\n"
        f"ACTIVE SESSIONS:\n{sessions_block}\n\n"
        f"TARGET CONTEXT:\n{targets_block}\n\n"
        f"RESEARCH & OSINT INTELLIGENCE:\n{research_block}\n\n"
        "Begin post-exploitation. Enumerate each live session, assess privilege level, "
        "run appropriate post modules, and summarize your findings."
    )


def _extract_resident_updates(messages: List[Any], state: CyberState) -> Dict[str, Any]:
    active_sessions = state.get("active_sessions", {}) or {}
    critical_findings: List[str] = []
    findings_summary: Dict[str, Any] = {}

    for msg in messages:
        if not isinstance(msg, ToolMessage) or msg.name not in POST_TOOL_NAMES:
            continue

        try:
            data = json.loads(msg.content) if isinstance(msg.content, str) else msg.content
        except (json.JSONDecodeError, TypeError):
            data = {}

        if not isinstance(data, dict):
            continue

        output = data.get("output", "") or data.get("module_output", "") or ""
        status = data.get("status", "")

        if "uid=0" in output or output.strip().startswith("root"):
            findings_summary["privilege"] = "root"
            critical_findings.append("Post-exploitation: root privileges confirmed")
        elif "uid=" in output and "privilege" not in findings_summary:
            findings_summary["privilege"] = "user"

        if "linux" in output.lower() and findings_summary.get("os_info") is None:
            findings_summary["os_info"] = output.strip()[:120]

        if msg.name == "msf_run_post_module" and status == "success":
            critical_findings.append(f"Post module succeeded: {data.get('module', 'unknown')}")

    updates: Dict[str, Any] = {
        "iteration_count": state.get("iteration_count", 0) + 1,
        "agent_log": [AgentLogEntry(
            agent="resident",
            action="post_exploitation",
            findings=findings_summary or None,
            reasoning="ReAct agent completed post-exploitation tasks",
        )],
    }

    if critical_findings:
        updates["critical_findings"] = critical_findings

    if findings_summary and active_sessions:
        enriched = {}
        for target, info in active_sessions.items():
            enriched[target] = {
                **info,
                **findings_summary,
                "post_exploitation_at": datetime.now().isoformat(),
            }
        updates["active_sessions"] = enriched

    return updates


async def resident_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper for the Resident agent."""

    active_sessions = state.get("active_sessions", {})
    if not active_sessions:
        updates = {
            "errors": [AgentError(
                agent="resident",
                error_type="ValidationError",
                error="No active sessions - run Striker first",
                recoverable=True,
            )],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }
        persist_state_update(state, updates)
        return updates

    bridge = await get_mcp_bridge()
    tools = bridge.get_tools_for_agent(RESIDENT_ALLOWED_TOOLS)
    if not tools:
        updates = {
            "errors": [AgentError(
                agent="resident",
                error_type="ToolError",
                error="No MSF tools available - is msf-mcp running?",
                recoverable=False,
            )],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }
        persist_state_update(state, updates)
        return updates

    tool_names = {tool.name for tool in tools}
    if "msf_send_session_command" not in tool_names:
        updates = {
            "errors": [AgentError(
                agent="resident",
                error_type="ToolError",
                error="Required tool msf_send_session_command missing from bridge",
                recoverable=False,
            )],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }
        persist_state_update(state, updates)
        return updates

    llm = _build_llm()
    agent = _create_react_agent_with_prompt(
        model=llm,
        tools=tools,
        system_prompt=RESIDENT_SYSTEM_PROMPT,
    )

    print(f"[Resident] Starting ReAct agent - {len(active_sessions)} active session(s)")

    result = await agent.ainvoke({"messages": [("human", _build_resident_context(state))]})
    updates = _extract_resident_updates(result["messages"], state)
    persist_state_update(state, updates)
    return updates
