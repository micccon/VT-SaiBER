"""
Resident Agent - Post-Exploitation Specialist.

Maintains access and performs post-exploitation activities on open sessions.
Uses the shared OpenRouter tool loop for autonomous enumeration and escalation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from src.agents.helpers import iter_tool_payloads, resolve_openrouter_runtime, run_agent_tool_loop
from src.agents.worker_harness import load_filtered_tools, tool_names
from src.config import get_runtime_config
from src.database.persistence import persist_state_update
from src.prompts.resident_prompt import RESIDENT_SYSTEM_PROMPT
from src.state.cyber_state import CyberState
from src.state.models import AgentError, AgentLogEntry


RESIDENT_ALLOWED_TOOLS = {
    "msf_list_sessions",
    "msf_session_command",
    "msf_run_post",
    "msf_search_modules",
    "msf_terminate_session",
}

POST_TOOL_NAMES = {"msf_session_command", "msf_run_post"}


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
    findings_by_session: Dict[str, Dict[str, Any]] = {}

    for msg, data in iter_tool_payloads(messages):
        if msg.name not in POST_TOOL_NAMES:
            continue

        if not isinstance(data, dict):
            continue

        output = (
            data.get("output", "")
            or data.get("module_output", "")
            or (
                data.get("raw", {}).get("output")
                if isinstance(data.get("raw"), dict)
                else ""
            )
            or ""
        )
        status = data.get("status", "")
        session_id = str(
            data.get("session_id")
            or data.get("session")
            or (data.get("options", {}) or {}).get("SESSION")
            or "unknown"
        )
        session_findings = findings_by_session.setdefault(session_id, {"successful_post_modules": []})

        if "uid=0" in output or output.strip().startswith("root"):
            session_findings["privilege"] = "root"
            critical_findings.append("Post-exploitation: root privileges confirmed")
        elif "uid=" in output and "privilege" not in session_findings:
            session_findings["privilege"] = "user"

        if output.strip():
            first_line = output.strip().splitlines()[0].strip()
            if first_line and msg.name == "msf_session_command" and (" " not in first_line or "uid=" not in first_line):
                session_findings.setdefault("user_context", first_line[:120])

        if "linux" in output.lower() and session_findings.get("os_info") is None:
            session_findings["os_info"] = output.strip()[:120]

        if msg.name == "msf_run_post" and status == "success":
            module_name = str(data.get("module", "unknown") or "unknown")
            session_findings.setdefault("successful_post_modules", []).append(module_name)
            critical_findings.append(f"Post module succeeded: {module_name}")

    updates: Dict[str, Any] = {
        "iteration_count": state.get("iteration_count", 0) + 1,
        "agent_log": [AgentLogEntry(
            agent="resident",
            action="post_exploitation",
            findings={"session_count": len(active_sessions)} or None,
            reasoning="Resident completed post-exploitation tasks",
        )],
    }

    if critical_findings:
        updates["critical_findings"] = critical_findings

    if findings_by_session and active_sessions:
        enriched = {}
        for target, info in active_sessions.items():
            session_key = str(info.get("session_id", "unknown"))
            enriched[target] = {
                **info,
                **findings_by_session.get(session_key, {}),
                "post_exploitation_at": datetime.now().isoformat(),
            }
        updates["active_sessions"] = enriched
        updates["validations"] = [
            {
                "type": "session_post_exploitation",
                "status": "success",
                "sessions": list(findings_by_session.keys()),
            }
        ]

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

    tools = await load_filtered_tools(RESIDENT_ALLOWED_TOOLS)
    if not tools:
        updates = {
            "errors": [AgentError(
                agent="resident",
                error_type="ToolError",
                error="No attackbox post-exploitation tools are available.",
                recoverable=False,
            )],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }
        persist_state_update(state, updates)
        return updates

    available_tools = tool_names(tools)
    if "msf_session_command" not in available_tools:
        updates = {
            "errors": [AgentError(
                agent="resident",
                error_type="ToolError",
                error="Required tool msf_session_command missing from bridge",
                recoverable=False,
            )],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }
        persist_state_update(state, updates)
        return updates

    try:
        runtime = resolve_openrouter_runtime(
            config=get_runtime_config(),
        )
    except Exception as exc:
        updates = {
            "errors": [AgentError(
                agent="resident",
                error_type="LLMConfigError",
                error=str(exc),
                recoverable=False,
            )],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }
        persist_state_update(state, updates)
        return updates

    print(f"[Resident] Starting tool loop - {len(active_sessions)} active session(s)")

    try:
        result = await run_agent_tool_loop(
            client=runtime.client,
            model=runtime.model,
            tools=tools,
            system_prompt=RESIDENT_SYSTEM_PROMPT,
            user_prompt=_build_resident_context(state),
        )
    except Exception as exc:
        updates = {
            "errors": [AgentError(
                agent="resident",
                error_type="LLMError",
                error=f"Resident LLM/tool loop failed: {exc}",
                recoverable=False,
            )],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }
        persist_state_update(state, updates)
        return updates

    updates = _extract_resident_updates(result.messages, state)
    persist_state_update(state, updates)
    return updates
