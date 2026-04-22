"""
Supervisor Agent - mission orchestration and routing.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Tuple

from langchain_core.messages import HumanMessage, SystemMessage

from src.agents.base import BaseAgent
from src.config import get_runtime_config
from src.database.persistence import persist_state_update
from src.graph.router import validate_all_targets_in_scope
from src.state.cyber_state import CyberState
from src.state.models import SupervisorDecision
from src.utils.llm import build_chat_openai, extract_text_content, to_langchain_messages
from src.utils.parsers import extract_json_payload
from src.utils.validators import (
    has_agent_run,
    has_service_version_intel,
    list_recent_agent_names,
)

logger = logging.getLogger(__name__)

VALID_NEXT_AGENTS = {"scout", "fuzzer", "librarian", "striker", "resident", "end"}


class SupervisorAgent(BaseAgent):
    """Centralized supervisor that routes specialist workers."""

    def __init__(self):
        super().__init__("supervisor", "Mission Coordinator")
        self.config = get_runtime_config()
        self._llm = None
        if self.config.openrouter_api_key:
            self._llm = build_chat_openai(
                model=self.config.supervisor_model,
                base_url=self.config.openrouter_base_url,
                timeout_seconds=self.config.supervisor_timeout_seconds,
            )
        else:
            logger.warning("OPENROUTER_API_KEY is not set; supervisor will use fallback routing only.")

    @property
    def system_prompt(self) -> str:
        return """You are the VT-SaiBER Supervisor. You route the mission to the best specialist worker agent.

Agent roles:
- scout: Network reconnaissance — host discovery, port scanning, service fingerprinting.
- fuzzer: Web attack-surface enumeration — directory brute-forcing, endpoint and API path discovery.
- librarian: Vulnerability intelligence — CVE research, exploit-path analysis, OSINT gathering.
- striker: Exploitation — launching exploits, gaining shells and remote sessions.
- resident: Post-exploitation — session enumeration, privilege escalation, persistence.
- end: Mission complete or awaiting human review.

Output format — return ONLY a single JSON object:
{
  "next_agent": "scout|fuzzer|librarian|striker|resident|end",
  "rationale": "<concise technical reason>",
  "specific_goal": "<one precise objective for the selected agent>",
  "confidence_score": <0.0–1.0>
}

Routing strategy:

1. MATCH THE MISSION GOAL to the agent whose role best fits the requested task.
   This is the strongest routing signal.
   - Goal asks to discover, scan, or fingerprint hosts/services      → scout
   - Goal asks to enumerate web directories, endpoints, or API paths → fuzzer
   - Goal asks to research vulnerabilities, look up CVEs, or gather intelligence → librarian
   - Goal asks to exploit a target, gain a shell, or launch an attack → striker
   - Goal asks to enumerate sessions, escalate privileges, or perform post-exploitation → resident
   Key distinction: "research exploit paths" or "find CVEs" = librarian;
   "run the exploit" or "gain a shell" = striker.

2. RESPECT PIPELINE PROGRESSION. Read the MISSION PHASE block in the context.
   The standard pipeline is: scout → fuzzer → librarian → striker → resident → end.
   Prefer advancing forward. Only go backward if the mission goal explicitly demands it.

3. HARD CONSTRAINTS (never violate):
   - NEVER pick striker unless librarian has already run (librarian_ran=True).
   - NEVER pick resident unless active_sessions > 0.
   - If the last exploit attempt failed, pick librarian or fuzzer — not striker again.

4. When the goal is ambiguous, follow the MISSION PHASE recommendation.

Do not call any tools. You are routing-only.
"""

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        iteration_count = int(state.get("iteration_count", 0))
        mission_status = str(state.get("mission_status", "active")).lower()

        if mission_status in {"success", "failed", "wait_for_human"}:
            return self._terminal_update(
                state=state,
                mission_status=mission_status,
                rationale=f"Mission already in terminal state: {mission_status}",
                specific_goal="N/A",
            )

        if iteration_count > self.config.max_iterations:
            return self._terminal_update(
                state=state,
                mission_status="wait_for_human",
                rationale=(
                    f"Iteration cap exceeded ({self.config.max_iterations}). "
                    "Escalating to human operator."
                ),
                specific_goal="Wait for human guidance",
            )

        if not validate_all_targets_in_scope(state):
            update = self._terminal_update(
                state=state,
                mission_status="failed",
                rationale="Out-of-scope target detected. Mission aborted for safety.",
                specific_goal="N/A",
            )
            update["errors"] = [{
                "agent": "supervisor",
                "error_type": "scope_violation",
                "error": "Out-of-scope target discovered in state",
                "recoverable": False,
            }]
            return update

        # Deterministic Phase-6 shortcut: resident has verified the session — no LLM needed.
        agent_log = state.get("agent_log", []) or []
        if (state.get("active_sessions") or {}) and has_agent_run(agent_log, "resident"):
            return self._terminal_update(
                state=state,
                mission_status="success",
                rationale="Active session confirmed and post-exploitation completed by resident.",
                specific_goal="Mission objectives satisfied.",
            )

        context_summary = self._build_context_summary(state)
        history = self._sanitize_history(state.get("supervisor_messages", []))
        prompt_messages = [
            SystemMessage(content=self.system_prompt),
            *to_langchain_messages(history),
            HumanMessage(content=context_summary),
        ]

        try:
            if self._llm is None:
                raise RuntimeError("ChatOpenAI client unavailable")
            llm_message = await self._llm.ainvoke(prompt_messages)
            llm_content = extract_text_content(llm_message)
            decision = self._parse_decision(llm_content)
            assistant_payload = {
                "role": "assistant",
                "content": llm_content,
            }
        except Exception as exc:
            logger.warning("Supervisor LLM fallback engaged: %s", exc)
            decision = self._fallback_decision(state, reason=str(exc))
            assistant_payload = {
                "role": "assistant",
                "content": json.dumps(decision.model_dump()),
            }

        decision, guardrail_reason = self._apply_guardrails(state, decision)
        next_agent = decision.next_agent.strip().lower()

        new_history = [
            *history,
            {"role": "user", "content": context_summary},
            assistant_payload,
        ]
        max_msgs = max(2, self.config.supervisor_max_reasoning_messages)
        new_history = new_history[-max_msgs:]

        reasoning = decision.rationale
        if guardrail_reason:
            reasoning = f"{reasoning} | Guardrail: {guardrail_reason}"

        if next_agent == "end":
            terminal_status, terminal_goal = self._derive_terminal_outcome(state, decision.specific_goal)
            return self._terminal_update(
                state=state,
                mission_status=terminal_status,
                rationale=reasoning,
                specific_goal=terminal_goal,
            )

        return {
            "current_agent": "supervisor",
            "next_agent": next_agent,
            "iteration_count": iteration_count + 1,
            "supervisor_messages": new_history,
            "supervisor_expectations": {
                "specific_goal": decision.specific_goal,
                "confidence_score": decision.confidence_score,
            },
            **self.log_action(
                state,
                action="route_decision",
                decision=next_agent,
                reasoning=reasoning,
                findings={
                    "specific_goal": decision.specific_goal,
                    "confidence_score": decision.confidence_score,
                },
            ),
        }

    def _terminal_update(
        self,
        state: CyberState,
        mission_status: str,
        rationale: str,
        specific_goal: str,
    ) -> Dict[str, Any]:
        return {
            "current_agent": "supervisor",
            "next_agent": "end",
            "mission_status": mission_status,
            "iteration_count": int(state.get("iteration_count", 0)) + 1,
            "supervisor_expectations": {
                "specific_goal": specific_goal,
                "confidence_score": 1.0,
            },
            **self.log_action(
                state,
                action="route_decision",
                decision="end",
                reasoning=rationale,
                findings={"specific_goal": specific_goal, "confidence_score": 1.0},
            ),
        }

    def _build_context_summary(self, state: CyberState) -> str:
        from src.utils.validators import has_agent_run, has_service_version_intel

        discovered_targets = state.get("discovered_targets", {}) or {}
        web_findings = state.get("web_findings", []) or []
        active_sessions = state.get("active_sessions", {}) or {}
        critical_findings = state.get("critical_findings", []) or []
        agent_log = state.get("agent_log", []) or []

        target_lines: List[str] = []
        for ip, details in discovered_targets.items():
            services = details.get("services", {}) if isinstance(details, dict) else {}
            service_summary = []
            for port, svc in list(services.items())[:8]:
                if isinstance(svc, dict):
                    name = svc.get("service_name", "unknown")
                    version = svc.get("version", "")
                    label = f"{port}:{name}"
                    if version:
                        label += f" {version}"
                    service_summary.append(label)
                else:
                    service_summary.append(f"{port}:{svc}")
            svc_block = ", ".join(service_summary) if service_summary else "no services"
            target_lines.append(f"- {ip} -> {svc_block}")
        targets_block = "\n".join(target_lines) if target_lines else "- none"

        recent_actions = []
        for entry in agent_log[-6:]:
            if isinstance(entry, dict):
                agent = entry.get("agent", "?")
                action = entry.get("action", entry.get("decision", "?"))
            else:
                agent = getattr(entry, "agent", "?")
                action = getattr(entry, "action", "?")
            recent_actions.append(f"- {agent}: {action}")
        recent_block = "\n".join(recent_actions) if recent_actions else "- none"

        critical_block = "\n".join(f"- {item}" for item in critical_findings[-6:]) if critical_findings else "- none"

        # Derive the current mission phase so the LLM has an unambiguous signal.
        scout_ran     = has_agent_run(agent_log, "scout")
        fuzzer_ran    = has_agent_run(agent_log, "fuzzer")
        librarian_ran = has_agent_run(agent_log, "librarian")
        striker_ran   = has_agent_run(agent_log, "striker")
        resident_ran  = has_agent_run(agent_log, "resident")
        has_targets   = bool(discovered_targets)
        has_versions  = has_service_version_intel(discovered_targets)
        has_web       = bool(web_findings)
        has_sessions  = bool(active_sessions)

        # Sessions take highest priority — check them before anything else.
        if has_sessions and resident_ran:
            phase = "Phase 6 — COMPLETE: resident finished post-exploitation → route to end"
        elif has_sessions and not resident_ran:
            phase = "Phase 5 — POST-EXPLOITATION: active session open, resident has not run → route to resident"
        elif librarian_ran and not has_sessions:
            phase = "Phase 4 — EXPLOITATION: intelligence gathered, no active session → route to striker"
        elif (has_web or has_targets) and not librarian_ran:
            phase = "Phase 3 — INTELLIGENCE: targets/web found, librarian has not run → route to librarian"
        elif has_targets and has_web and not fuzzer_ran:
            phase = "Phase 2 — WEB ENUMERATION: web service present, fuzzer has not run → route to fuzzer"
        elif not has_targets:
            phase = "Phase 1 — RECONNAISSANCE: no targets discovered yet → route to scout"
        else:
            phase = "Phase unknown — use recent actions and state to decide"

        phase_flags = (
            f"  targets_found={has_targets}  versions_known={has_versions}"
            f"  web_found={has_web}  active_sessions={len(active_sessions)}\n"
            f"  scout_ran={scout_ran}  fuzzer_ran={fuzzer_ran}"
            f"  librarian_ran={librarian_ran}  striker_ran={striker_ran}"
            f"  resident_ran={resident_ran}"
        )

        return (
            f"Mission goal: {state.get('mission_goal', '(unknown)')}\n"
            f"Mission status: {state.get('mission_status', 'active')}\n"
            f"Iteration: {state.get('iteration_count', 0)}/{self.config.max_iterations}\n"
            f"Target scope: {state.get('target_scope', [])}\n\n"
            f"Discovered targets:\n{targets_block}\n\n"
            f"Web findings count: {len(web_findings)}\n"
            f"Active sessions count: {len(active_sessions)}\n"
            f"Critical findings:\n{critical_block}\n\n"
            f"Recent actions:\n{recent_block}\n\n"
            f"MISSION PHASE:\n  {phase}\n{phase_flags}\n"
        )

    def _parse_decision(self, raw_content: str) -> SupervisorDecision:
        payload = extract_json_payload(raw_content)
        if "confidence" in payload and "confidence_score" not in payload:
            payload["confidence_score"] = payload["confidence"]
        if "expected_outcome" in payload and "specific_goal" not in payload:
            payload["specific_goal"] = payload["expected_outcome"]
        return SupervisorDecision.model_validate(payload)

    def _fallback_decision(self, state: CyberState, reason: str) -> SupervisorDecision:
        discovered_targets = state.get("discovered_targets", {}) or {}
        active_sessions = state.get("active_sessions", {}) or {}
        web_findings = state.get("web_findings", []) or []

        if active_sessions and has_agent_run(state.get("agent_log", []) or [], "resident"):
            next_agent = "end"
            specific_goal = "Mission objective satisfied after post-exploitation review."
        elif active_sessions:
            next_agent = "resident"
            specific_goal = "Enumerate and stabilize active sessions."
        elif not discovered_targets:
            next_agent = "scout"
            specific_goal = "Discover targets and fingerprint exposed services."
        elif web_findings and not has_agent_run(state.get("agent_log", []) or [], "librarian"):
            next_agent = "librarian"
            specific_goal = "Research exploit paths from discovered findings."
        elif web_findings:
            next_agent = "striker"
            specific_goal = "Attempt exploitation using researched vectors."
        else:
            next_agent = "fuzzer"
            specific_goal = "Enumerate web attack surface for discovered hosts."

        return SupervisorDecision(
            next_agent=next_agent,
            rationale=f"Fallback routing due to LLM error: {reason}",
            specific_goal=specific_goal,
            confidence_score=0.35,
        )

    def _apply_guardrails(
        self,
        state: CyberState,
        decision: SupervisorDecision,
    ) -> Tuple[SupervisorDecision, str]:
        reason = ""
        normalized_agent = decision.next_agent.strip().lower()

        if normalized_agent not in VALID_NEXT_AGENTS:
            normalized_agent = "scout" if not state.get("discovered_targets") else "librarian"
            reason = "invalid-next-agent-corrected"

        librarian_has_run = has_agent_run(state.get("agent_log", []) or [], "librarian")
        has_versions = has_service_version_intel(state.get("discovered_targets", {}) or {})
        if normalized_agent == "striker" and has_versions and not librarian_has_run:
            normalized_agent = "librarian"
            reason = "forced-librarian-before-striker"

        if self._striker_failed_recently(state):
            if normalized_agent not in {"librarian", "fuzzer", "end"}:
                recent_agents = list_recent_agent_names(state.get("agent_log", []) or [], n=4)
                normalized_agent = "fuzzer" if recent_agents and recent_agents[-1] == "librarian" else "librarian"
                reason = "striker-failure-backtrack"

        return (
            SupervisorDecision(
                next_agent=normalized_agent,
                rationale=decision.rationale,
                specific_goal=decision.specific_goal,
                confidence_score=decision.confidence_score,
            ),
            reason,
        )

    def _sanitize_history(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        safe: List[Dict[str, Any]] = []
        for message in messages or []:
            if not isinstance(message, dict):
                continue
            role = str(message.get("role", "")).strip().lower()
            if role not in {"user", "assistant"}:
                continue
            item: Dict[str, Any] = {
                "role": role,
                "content": str(message.get("content", "")),
            }
            safe.append(item)
        return safe

    def _striker_failed_recently(self, state: CyberState) -> bool:
        exploited_services = state.get("exploited_services", []) or []
        for record in reversed(exploited_services):
            if not isinstance(record, dict):
                continue
            status = str(record.get("status", "")).strip().lower()
            if not status:
                continue
            return status not in {"success", "succeeded", "opened"}

        # Fallback heuristic: striker was last worker and no active session opened.
        recent_agents = [a for a in list_recent_agent_names(state.get("agent_log", []) or [], n=5) if a != "supervisor"]
        if recent_agents and recent_agents[-1] == "striker" and not (state.get("active_sessions", {}) or {}):
            return True
        return False

    def _derive_terminal_outcome(self, state: CyberState, specific_goal: str) -> Tuple[str, str]:
        mission_status = str(state.get("mission_status", "active")).strip().lower()
        if mission_status in {"success", "failed", "wait_for_human"}:
            return mission_status, specific_goal or "N/A"

        mission_goal = str(state.get("mission_goal", "")).lower()
        active_sessions = state.get("active_sessions", {}) or {}
        critical_findings = [str(item).lower() for item in (state.get("critical_findings", []) or [])]
        resident_has_run = has_agent_run(state.get("agent_log", []) or [], "resident")

        if active_sessions and resident_has_run:
            return "success", specific_goal or "Resident validated post-exploitation success."

        if active_sessions and any(
            term in mission_goal
            for term in ("exploit", "initial access", "session", "shell", "meterpreter", "foothold")
        ):
            return "success", specific_goal or "Initial access objective satisfied."

        if any("session " in finding or "root privileges" in finding for finding in critical_findings):
            return "success", specific_goal or "Critical mission objective reached."

        return "wait_for_human", specific_goal or "Wait for operator confirmation before closing mission."


async def supervisor_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper for the Supervisor agent."""
    agent = SupervisorAgent()
    updates = await agent.call_llm(state)
    persist_state_update(state, updates)
    return updates
