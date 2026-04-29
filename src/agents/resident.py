"""Resident Agent - OpenRouter-driven session-backed objective worker."""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List

from src.agents.base import BaseAgent
from src.config import get_runtime_config
from src.database.persistence import persist_state_update
from src.skills import match_skills, render_skill_matches
from src.state.cyber_state import CyberState
from src.state.models import AgentLogEntry
from src.utils.agent_parsers import extract_tool_output_text
from src.utils.agent_runtime import collect_reasoning_chunks, iter_tool_messages
from src.utils.approval import require_manual_approval
from src.utils.parsers import extract_json_payload
from src.utils.tools import BaseToolPolicy, RuntimeTool, ToolInterception


RESIDENT_ALLOWED_TOOLS = {
    "msf_list_sessions",
    "msf_session_command",
    "msf_run_post",
    "msf_search_modules",
    "msf_terminate_session",
    "system_execute_command",
}

RESIDENT_REQUIRE_CONFIRMATION = os.getenv("RESIDENT_REQUIRE_CONFIRMATION", "true").lower() == "true"
RESIDENT_OBJECTIVE_STATUSES = {"completed", "in_progress", "blocked", "needs_approval", "failed"}
READ_ONLY_SESSION_COMMAND_PATTERNS = (
    re.compile(r"^\s*id\s*$", re.IGNORECASE),
    re.compile(r"^\s*whoami\s*$", re.IGNORECASE),
    re.compile(r"^\s*uname(?:\s+-[^\s]+)?(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*hostname\s*$", re.IGNORECASE),
    re.compile(r"^\s*pwd\s*$", re.IGNORECASE),
    re.compile(r"^\s*env\s*$", re.IGNORECASE),
    re.compile(r"^\s*printenv\s*$", re.IGNORECASE),
    re.compile(r"^\s*ls(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*cat(?:\s+.+)$", re.IGNORECASE),
    re.compile(r"^\s*ip\s+addr(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*ip\s+route(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*ss(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*netstat(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*ps(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*sudo\s+-l(?:\s+.*)?$", re.IGNORECASE),
    re.compile(r"^\s*find(?:\s+.+)$", re.IGNORECASE),
    re.compile(r"^\s*grep(?:\s+.+)$", re.IGNORECASE),
    re.compile(r"^\s*crontab\s+-l(?:\s+.*)?$", re.IGNORECASE),
)
READ_ONLY_POST_MODULES = {
    "post/linux/gather/enum_system",
    "post/multi/gather/env",
    "post/linux/gather/enum_network",
    "post/linux/gather/checkvm",
}
OBJECTIVE_ACTION_TOOL_NAMES = {"msf_session_command", "msf_run_post", "system_execute_command"}

RESIDENT_SYSTEM_PROMPT = """You are the VT-SaiBER resident agent.

You operate only after a live session already exists. Your job is not just to enumerate the host. Your job is to use the session to advance the operator's immediate objective in a bounded, evidence-driven way.

Primary mission:
1. Validate which sessions are still alive with msf_list_sessions before doing any other work.
2. Select the best live session for the stated objective.
3. Perform only the minimum read-only orientation needed to understand the host and confirm the path forward.
4. Decide whether the next bounded step belongs inside the session or on the attackbox.
5. Execute one bounded step at a time.
6. Validate whether the objective advanced, completed, or is blocked.
7. Return a structured objective report.

Available tools:
- msf_list_sessions: confirm live sessions and their details
- msf_session_command: run commands inside a live session
- msf_run_post: run bounded Metasploit post modules against a validated session
- msf_search_modules: search for relevant local post-exploitation or escalation modules
- msf_terminate_session: close a session only when explicitly justified
- system_execute_command: run a precise attackbox-side command when the objective requires host-side interaction outside the session

Read-only orientation examples:
- id
- whoami
- uname -a
- hostname
- pwd
- env
- printenv
- ls
- cat
- ip addr
- ip route
- ss
- netstat
- ps
- sudo -l
- find
- grep
- crontab -l

Operational rules:
- Always validate sessions first with msf_list_sessions.
- Work only toward the stated objective. Do not drift into generic post-exploitation for its own sake.
- Prefer the smallest action that can confirm progress.
- Treat msf_session_command as the default for in-session inspection and bounded objective steps.
- Use msf_run_post only when a named post module is the clearest path.
- Use system_execute_command only when the objective genuinely requires attackbox-side execution, such as host-side tooling or interface interaction that the session cannot perform directly.
- Do not repeat the same failed action without new evidence.
- If a command or module requires approval, explain why it matters to the objective and stop cleanly.
- Do not run destructive or broad-impact actions without necessity.

Automotive and interface-aware behavior:
- If the objective references CAN, VCAN, UDS, door locks, vehicle state, or another host-side interface, first confirm the required host/session context and then choose the smallest validating action.
- Prefer validation and state confirmation before attempting a mission action such as opening a car door.

When you are finished, return ONLY a JSON object with this shape:
{
  "objective": "<the immediate goal you worked on>",
  "objective_status": "completed|in_progress|blocked|needs_approval|failed",
  "session_id": "<session id or empty string>",
  "actions_taken": ["short action 1", "short action 2"],
  "evidence_summary": ["short evidence line 1", "short evidence line 2"]
}

Meaning of objective_status:
- completed: the objective was validated as achieved
- in_progress: the objective advanced but is not complete yet
- blocked: the current path is blocked but the session may still be useful
- needs_approval: the next meaningful action requires human approval
- failed: the objective cannot proceed because the session is gone or the path definitively failed
"""


def _resolve_objective(state: CyberState) -> str:
    """Use the supervisor's specific_goal when present, falling back to mission_goal."""

    expectations = state.get("supervisor_expectations", {}) or {}
    objective = str(expectations.get("specific_goal", "") or "").strip()
    if objective:
        return objective
    return str(state.get("mission_goal", "") or "(not specified)").strip() or "(not specified)"


def _stringify(value: Any) -> str:
    """Normalize an arbitrary value to a stripped string."""

    text = str(value or "").strip()
    return text


def _compact_lines(values: Iterable[str], *, limit: int = 8) -> str:
    """Render up to a small number of non-empty lines for prompt sections."""

    lines = [line for line in (_stringify(value) for value in values) if line]
    return "\n".join(lines[:limit]) if lines else "  (none)"


def _build_resident_context(state: CyberState) -> str:
    """Build the resident objective prompt from sessions, targets, and research context."""

    objective = _resolve_objective(state)
    mission_goal = str(state.get("mission_goal") or "(not specified)")
    active_sessions = state.get("active_sessions", {}) or {}
    discovered_targets = state.get("discovered_targets", {}) or {}
    research_cache = state.get("research_cache", {}) or {}
    intelligence_findings = state.get("intelligence_findings", []) or []
    skill_matches = match_skills(state, "resident", limit=2)
    skills_block = render_skill_matches(skill_matches)
    skills_section = f"RELEVANT SKILLS:\n{skills_block}\n\n" if skills_block else ""

    session_lines: List[str] = []
    for target, info in active_sessions.items():
        session_lines.append(
            "  session_id={sid} target={target} via={module} user={user} opened={opened}".format(
                sid=info.get("session_id", "?"),
                target=target,
                module=info.get("module", info.get("exploit", "unknown")),
                user=info.get("user", "unknown"),
                opened=info.get("established_at", info.get("established", "?")),
            )
        )

    target_lines: List[str] = []
    for ip, data in discovered_targets.items():
        if not isinstance(data, dict):
            continue
        services = data.get("services", {}) or {}
        service_bits: List[str] = []
        for port, value in list(services.items())[:6]:
            if isinstance(value, dict):
                name = value.get("service_name", "unknown")
                version = f" {value.get('version')}" if value.get("version") else ""
                service_bits.append(f"{port}:{name}{version}")
            else:
                service_bits.append(f"{port}:{value}")
        target_lines.append(
            f"  {ip} os={data.get('os_guess', 'unknown')} services={', '.join(service_bits) or '(none)'}"
        )

    research_lines: List[str] = []
    for key, value in list(research_cache.items())[:5]:
        research_lines.append(f"  Research ({key}): {str(value)[:180]}")
    for finding in intelligence_findings[:5]:
        if isinstance(finding, dict):
            cve = str(finding.get("cve", "") or "").strip()
            description = str(finding.get("description", "") or "").strip()
            if cve or description:
                prefix = f"[{cve}] " if cve else ""
                label = "OSINT" if finding.get("is_osint_derived") and finding.get("source_types") == ["osint"] else "Intel"
                research_lines.append(f"  {label}: {prefix}{description[:180]}")
        else:
            research_lines.append(f"  Intel: {str(finding)[:180]}")

    return (
        f"MISSION GOAL: {mission_goal}\n"
        f"IMMEDIATE OBJECTIVE: {objective}\n\n"
        f"ACTIVE SESSIONS:\n{_compact_lines(session_lines)}\n\n"
        f"TARGET CONTEXT:\n{_compact_lines(target_lines)}\n\n"
        f"RESEARCH & INTELLIGENCE:\n{_compact_lines(research_lines)}\n\n"
        f"{skills_section}"
        "Work toward the immediate objective with one bounded next step. "
        "Validate sessions first, minimize noisy enumeration, and stop cleanly when approval is required."
    )


def _is_read_only_session_command(command: str) -> bool:
    """Check whether a session command falls inside the read-only allowlist."""

    candidate = str(command or "").strip()
    return any(pattern.match(candidate) for pattern in READ_ONLY_SESSION_COMMAND_PATTERNS)


def _normalize_summary_list(values: Any) -> List[str]:
    """Normalize assistant JSON summary fields to a simple string list."""

    if isinstance(values, list):
        return [str(item).strip() for item in values if str(item).strip()]
    if isinstance(values, str) and values.strip():
        return [values.strip()]
    return []


def _build_action_label(tool_name: str, invocation: Dict[str, Any]) -> str:
    """Generate a short action label for resident audit logging."""

    if tool_name == "msf_session_command":
        return f"msf_session_command(session={invocation.get('session_id', '?')}, command={invocation.get('command', '')})"
    if tool_name == "msf_run_post":
        options = invocation.get("options", {}) if isinstance(invocation.get("options"), dict) else {}
        return f"msf_run_post(module={invocation.get('module_name', '')}, session={options.get('SESSION', '?')})"
    if tool_name == "system_execute_command":
        return f"system_execute_command(command={invocation.get('command', '')})"
    if tool_name == "msf_terminate_session":
        return f"msf_terminate_session(session={invocation.get('session_id', '?')})"
    if tool_name == "msf_search_modules":
        return f"msf_search_modules(search_term={invocation.get('search_term', '')})"
    return tool_name


def _extract_summary_payload(messages: List[dict[str, Any]]) -> Dict[str, Any]:
    """Read the final assistant JSON summary, if one was returned cleanly."""

    for message in reversed(messages):
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        content = str(message.get("content", "") or "").strip()
        if not content:
            continue
        try:
            payload = extract_json_payload(content)
        except Exception:
            continue
        if isinstance(payload, dict):
            return payload
    return {}


def _extract_resident_updates(
    messages: List[dict[str, Any]],
    state: CyberState,
    matched_skill_names: List[str] | None = None,
) -> Dict[str, Any]:
    """Convert resident tool activity into objective-tracking state updates."""

    objective = _resolve_objective(state)
    active_sessions = state.get("active_sessions", {}) or {}
    summary = _extract_summary_payload(messages)
    reasoning = "\n\n".join(chunk for chunk in collect_reasoning_chunks(messages) if chunk).strip()

    live_sessions_payload: Dict[str, Any] = {}
    saw_session_validation = False
    saw_approval_gate = False
    saw_failures = False
    actions_taken: List[str] = []
    evidence_summary: List[str] = []
    findings_by_session: Dict[str, Dict[str, Any]] = {}
    selected_session_id = ""

    # Resident cares about validated session liveness, bounded actions taken, and evidence of objective progress.
    for message, data in iter_tool_messages(messages):
        if not isinstance(data, dict):
            continue
        tool_name = str(message.get("name", "") or "")
        invocation = data.get("invocation", {}) if isinstance(data.get("invocation"), dict) else {}
        status = str(data.get("status", "") or "").strip().lower()

        if tool_name == "msf_list_sessions":
            # Session validation is always the ground truth for whether resident can proceed.
            saw_session_validation = True
            evidence = data.get("evidence", {}) if isinstance(data.get("evidence"), dict) else {}
            sessions = evidence.get("sessions") if isinstance(evidence.get("sessions"), dict) else data.get("sessions")
            if isinstance(sessions, dict):
                live_sessions_payload = sessions
            continue

        if tool_name in OBJECTIVE_ACTION_TOOL_NAMES or tool_name == "msf_terminate_session":
            actions_taken.append(_build_action_label(tool_name, invocation))

        if data.get("objective_status") == "needs_approval" or "manual approval" in str(data.get("message", "") or "").lower():
            saw_approval_gate = True

        if status in {"error", "blocked"}:
            saw_failures = True

        output = extract_tool_output_text(data)
        first_line = output.strip().splitlines()[0].strip() if output.strip() else ""
        if first_line and len(evidence_summary) < 6:
            evidence_summary.append(first_line[:220])

        if tool_name not in {"msf_session_command", "msf_run_post"}:
            continue

        session_id = str(
            data.get("session_id")
            or data.get("session")
            or invocation.get("session_id")
            or ((data.get("options", {}) or {}).get("SESSION") if isinstance(data.get("options"), dict) else "")
            or ((invocation.get("options", {}) or {}).get("SESSION") if isinstance(invocation.get("options"), dict) else "")
            or ""
        ).strip()
        if session_id and not selected_session_id:
            selected_session_id = session_id
        if not session_id:
            continue

        session_findings = findings_by_session.setdefault(session_id, {"successful_post_modules": []})
        if "uid=0" in output or output.strip().startswith("root"):
            session_findings["privilege"] = "root"
        elif "uid=" in output and "privilege" not in session_findings:
            session_findings["privilege"] = "user"

        if tool_name == "msf_session_command" and first_line:
            session_findings.setdefault("user_context", first_line[:120])
        if "linux" in output.lower() and session_findings.get("os_info") is None:
            session_findings["os_info"] = output.strip()[:160]
        if tool_name == "msf_run_post" and status == "success":
            module_name = str(data.get("module") or data.get("module_name") or invocation.get("module_name") or "unknown")
            session_findings.setdefault("successful_post_modules", []).append(module_name)

    live_session_ids = {str(key) for key in live_sessions_payload.keys()}
    if not selected_session_id and live_session_ids:
        selected_session_id = next(iter(live_session_ids))
    if summary.get("session_id") and str(summary.get("session_id")).strip():
        selected_session_id = str(summary.get("session_id")).strip()

    # Prefer the assistant's structured summary when it exists, but fall back to extracted tool evidence.
    if summary.get("actions_taken"):
        actions_taken = _normalize_summary_list(summary.get("actions_taken")) or actions_taken
    if summary.get("evidence_summary"):
        evidence_summary = _normalize_summary_list(summary.get("evidence_summary")) or evidence_summary

    objective_status = str(summary.get("objective_status", "") or "").strip().lower()
    if objective_status not in RESIDENT_OBJECTIVE_STATUSES:
        if saw_approval_gate:
            objective_status = "needs_approval"
        elif not saw_session_validation:
            objective_status = "blocked"
        elif not live_session_ids:
            objective_status = "failed"
        elif saw_failures:
            objective_status = "blocked"
        else:
            objective_status = "in_progress"

    summary_objective = str(summary.get("objective", "") or "").strip()
    if summary_objective:
        objective = summary_objective

    if not evidence_summary:
        if objective_status == "needs_approval":
            evidence_summary = ["Next bounded action requires human approval."]
        elif objective_status == "failed":
            evidence_summary = ["No validated live session remained after session validation."]
        elif objective_status == "blocked":
            evidence_summary = ["Resident could not validate clear objective progress from the current step."]

    live_target_sessions: Dict[str, Dict[str, Any]] = {}
    if live_session_ids:
        # Enrich only still-live sessions with the new resident findings.
        for target, info in active_sessions.items():
            session_key = str(info.get("session_id", ""))
            if session_key not in live_session_ids:
                continue
            live_info = live_sessions_payload.get(session_key, {}) if isinstance(live_sessions_payload, dict) else {}
            live_target_sessions[target] = {
                **info,
                **(live_info if isinstance(live_info, dict) else {}),
                **findings_by_session.get(session_key, {}),
                "objective": objective,
                "resident_objective_status": objective_status,
                "resident_actions_taken": actions_taken,
                "resident_evidence_summary": evidence_summary,
                "resident_validated_at": datetime.now().isoformat(),
            }

    findings = {
        "objective": objective,
        "objective_status": objective_status,
        "session_id": selected_session_id or None,
        "actions_taken": actions_taken,
        "evidence_summary": evidence_summary,
        "live_session_count": len(live_session_ids),
        "session_validation_performed": saw_session_validation,
    }
    if matched_skill_names:
        findings["matched_skills"] = list(dict.fromkeys(matched_skill_names))

    validation = {
        "type": "resident_objective",
        "status": objective_status,
        "objective": objective,
        "session_id": selected_session_id or None,
        "actions_taken": actions_taken,
        "evidence_summary": evidence_summary,
        "live_session_count": len(live_session_ids),
    }

    updates: Dict[str, Any] = {
        "current_agent": "resident",
        "iteration_count": int(state.get("iteration_count", 0)) + 1,
        "agent_log": [AgentLogEntry(
            agent="resident",
            action="objective_worker",
            target=next(iter(live_target_sessions.keys()), next(iter(active_sessions.keys()), None)),
            findings=findings,
            reasoning=reasoning or objective,
        )],
        "validations": [validation],
    }

    if live_target_sessions:
        updates["active_sessions"] = live_target_sessions

    critical_findings: List[str] = []
    if objective_status == "completed":
        critical_findings.append(f"Resident completed objective: {objective}")
    elif objective_status == "needs_approval":
        critical_findings.append(f"Resident needs approval to continue objective: {objective}")
    if any(info.get("privilege") == "root" for info in findings_by_session.values()):
        critical_findings.append("Resident confirmed root privileges on at least one live session")
    if critical_findings:
        updates["critical_findings"] = critical_findings

    return updates


class ResidentToolPolicy(BaseToolPolicy):
    def __init__(self, *, require_confirmation: bool):
        """Enforce the resident approval boundary for mutating or high-impact actions."""

        self.require_confirmation = require_confirmation

    async def before_call(self, tool: RuntimeTool, arguments: dict[str, Any]) -> ToolInterception | None:
        """Allow bounded read-only triage and gate higher-impact actions behind approval."""

        if tool.name == "msf_session_command":
            command = str(arguments.get("command", "") or "")
            if _is_read_only_session_command(command):
                return None
            approved = require_manual_approval(
                tool_name=tool.name,
                module_name=command,
                target=str(arguments.get("session_id") or "session"),
                enabled=self.require_confirmation,
            )
            if approved:
                return None
            return ToolInterception(
                {
                    "status": "aborted",
                    "objective_status": "needs_approval",
                    "message": "Execution blocked pending manual approval.",
                    "command": command,
                }
            )

        if tool.name == "msf_run_post":
            module_name = str(arguments.get("module_name", "") or "").strip().lower()
            if module_name in READ_ONLY_POST_MODULES:
                return None
            approved = require_manual_approval(
                tool_name=tool.name,
                module_name=module_name,
                target=str(((arguments.get("options", {}) or {}).get("SESSION") if isinstance(arguments.get("options"), dict) else "") or "session"),
                enabled=self.require_confirmation,
            )
            if approved:
                return None
            return ToolInterception(
                {
                    "status": "aborted",
                    "objective_status": "needs_approval",
                    "message": "Execution blocked pending manual approval.",
                    "module_name": module_name,
                }
            )

        if tool.name == "msf_terminate_session":
            approved = require_manual_approval(
                tool_name=tool.name,
                module_name="terminate_session",
                target=str(arguments.get("session_id") or "session"),
                enabled=self.require_confirmation,
            )
            if approved:
                return None
            return ToolInterception(
                {
                    "status": "aborted",
                    "objective_status": "needs_approval",
                    "message": "Execution blocked pending manual approval.",
                }
            )

        if tool.name == "system_execute_command":
            approved = require_manual_approval(
                tool_name=tool.name,
                module_name=str(arguments.get("command", "") or ""),
                target="attackbox",
                enabled=self.require_confirmation,
            )
            if approved:
                return None
            return ToolInterception(
                {
                    "status": "aborted",
                    "objective_status": "needs_approval",
                    "message": "Execution blocked pending manual approval.",
                    "command": str(arguments.get("command", "") or ""),
                }
            )

        return None


class ResidentAgent(BaseAgent):
    """Session-backed objective worker using the shared OpenAI SDK tool loop."""

    ALLOWED_TOOLS = RESIDENT_ALLOWED_TOOLS

    def __init__(self):
        """Initialize the resident objective worker with the shared runtime."""

        super().__init__("resident", "Session-Backed Objective Worker")
        self.require_confirmation = RESIDENT_REQUIRE_CONFIRMATION
        self._init_runtime(config=get_runtime_config())

    @property
    def system_prompt(self) -> str:
        """Resident doctrine embedded directly in the agent file."""

        return RESIDENT_SYSTEM_PROMPT

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """Advance a mission objective using already-established sessions."""

        active_sessions = state.get("active_sessions", {}) or {}
        if not active_sessions:
            return self._error_update(
                state,
                error_type="ValidationError",
                message="No active sessions - run Striker first",
                recoverable=True,
            )
        matched_skill_names = [match.skill.relative_path for match in match_skills(state, self.name, limit=2)]
        return await self._run_tool_agent(
            state,
            user_prompt=_build_resident_context(state),
            allowed_tools=self.ALLOWED_TOOLS,
            required_tools={"msf_list_sessions", "msf_session_command"},
            policy=ResidentToolPolicy(require_confirmation=self.require_confirmation),
            extractor=lambda messages, current_state: _extract_resident_updates(
                messages,
                current_state,
                matched_skill_names=matched_skill_names,
            ),
            max_rounds=6,
            error_message="Resident LLM/tool loop failed.",
        )


async def resident_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper for the Resident agent."""
    updates = await ResidentAgent().call_llm(state)
    persist_state_update(state, updates)
    return updates
