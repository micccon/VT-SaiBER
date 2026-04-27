"""Resident Agent - OpenRouter-driven post-exploitation specialist."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from src.agents.base import BaseAgent
from src.config import get_runtime_config
from src.database.persistence import persist_state_update
from src.prompts.resident_prompt import RESIDENT_SYSTEM_PROMPT
from src.state.cyber_state import CyberState
from src.state.models import AgentLogEntry
from src.utils.agent_runtime import iter_tool_messages
from src.utils.agent_parsers import extract_tool_output_text


RESIDENT_ALLOWED_TOOLS = {
    "msf_list_sessions",
    "msf_session_command",
    "msf_run_post",
    "msf_search_modules",
    "msf_terminate_session",
}

POST_TOOL_NAMES = {"msf_session_command", "msf_run_post"}


class ResidentAgent(BaseAgent):
    """Post-exploitation worker using the shared OpenAI SDK tool loop."""

    ALLOWED_TOOLS = RESIDENT_ALLOWED_TOOLS

    def __init__(self):
        super().__init__("resident", "Post-Exploitation Specialist")
        self._init_runtime(config=get_runtime_config())

    @property
    def system_prompt(self) -> str:
        return RESIDENT_SYSTEM_PROMPT

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        active_sessions = state.get("active_sessions", {}) or {}
        if not active_sessions:
            return self._error_update(
                state,
                error_type="ValidationError",
                message="No active sessions - run Striker first",
                recoverable=True,
            )
        return await self._run_tool_agent(
            state,
            user_prompt=self._build_context(state),
            allowed_tools=self.ALLOWED_TOOLS,
            required_tools={"msf_session_command"},
            extractor=self._extract_updates,
            max_rounds=6,
            error_message="Resident LLM/tool loop failed.",
        )

    def _build_context(self, state: CyberState) -> str:
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

    def _extract_updates(self, messages: List[dict[str, Any]], state: CyberState) -> Dict[str, Any]:
        active_sessions = state.get("active_sessions", {}) or {}
        critical_findings: List[str] = []
        findings_by_session: Dict[str, Dict[str, Any]] = {}

        for message, data in iter_tool_messages(messages):
            if str(message.get("name", "") or "") not in POST_TOOL_NAMES:
                continue
            if not isinstance(data, dict):
                continue

            output = extract_tool_output_text(data)
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
                if (
                    first_line
                    and message.get("name") == "msf_session_command"
                    and (" " not in first_line or "uid=" not in first_line)
                ):
                    session_findings.setdefault("user_context", first_line[:120])

            if "linux" in output.lower() and session_findings.get("os_info") is None:
                session_findings["os_info"] = output.strip()[:120]

            if message.get("name") == "msf_run_post" and status == "success":
                module_name = str(data.get("module", "unknown") or "unknown")
                session_findings.setdefault("successful_post_modules", []).append(module_name)
                critical_findings.append(f"Post module succeeded: {module_name}")

        updates: Dict[str, Any] = {
            **self._agent_update(state),
            "agent_log": [AgentLogEntry(
                agent=self.name,
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
    updates = await ResidentAgent().call_llm(state)
    persist_state_update(state, updates)
    return updates
