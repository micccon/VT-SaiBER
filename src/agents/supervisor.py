"""Supervisor agent - mission orchestration and routing."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Tuple

from src.agents.base import BaseAgent
from src.config import get_runtime_config
from src.database.persistence import persist_state_update
from src.graph.router import validate_all_targets_in_scope
from src.state.cyber_state import CyberState
from src.state.models import SupervisorDecision
from src.utils.parsers import extract_json_payload
from src.utils.validators import has_agent_run, has_service_version_intel, list_recent_agent_names

logger = logging.getLogger(__name__)
VALID_NEXT_AGENTS = {"scout", "fuzzer", "librarian", "striker", "resident", "end"}


class SupervisorAgent(BaseAgent):
    def __init__(self):
        super().__init__("supervisor", "Mission Coordinator")
        self.config = get_runtime_config()
        if self.config.openrouter_api_key:
            self._init_runtime(
                config=self.config,
                model=self.config.supervisor_model,
                base_url=self.config.openrouter_base_url,
                api_key=self.config.openrouter_api_key,
                timeout_seconds=self.config.supervisor_timeout_seconds,
            )
        else:
            logger.warning("OPENROUTER_API_KEY is not set; supervisor will use fallback routing only.")

    @property
    def system_prompt(self) -> str:
        return (
            "You are the VT-SaiBER Supervisor. Route the mission to the best specialist worker.\n\n"
            "Roles:\n"
            "- scout: host discovery, port scanning, service fingerprinting\n"
            "- fuzzer: web directories, endpoints, API path discovery\n"
            "- librarian: CVE research, exploit-path analysis, OSINT\n"
            "- striker: exploitation, gaining shells or sessions\n"
            "- resident: session enumeration, privilege escalation, post-exploitation\n"
            "- end: mission complete or awaiting human review\n\n"
            'Return ONLY JSON: {"next_agent":"scout|fuzzer|librarian|striker|resident|end","rationale":"...","specific_goal":"...","confidence_score":0.0}\n\n'
            "Routing rules:\n"
            "1. Match the mission goal to the best role.\n"
            "2. Prefer the pipeline scout -> fuzzer -> librarian -> striker -> resident -> end.\n"
            "3. Never pick striker before librarian. Never pick resident without active sessions.\n"
            "4. After a failed exploit, pick librarian or fuzzer instead of striker.\n"
            "5. When ambiguous, follow the MISSION PHASE recommendation.\n"
            "Do not call tools."
        )

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        iteration_count = int(state.get("iteration_count", 0))
        mission_status = str(state.get("mission_status", "active")).lower()
        if mission_status in {"success", "failed", "wait_for_human"}:
            return self._terminal_update(state, mission_status, f"Mission already in terminal state: {mission_status}", "N/A")
        if iteration_count > self.config.max_iterations:
            return self._terminal_update(
                state,
                "wait_for_human",
                f"Iteration cap exceeded ({self.config.max_iterations}). Escalating to human operator.",
                "Wait for human guidance",
            )
        if not validate_all_targets_in_scope(state):
            update = self._terminal_update(state, "failed", "Out-of-scope target detected. Mission aborted for safety.", "N/A")
            update["errors"] = [{
                "agent": self.name,
                "error_type": "scope_violation",
                "error": "Out-of-scope target discovered in state",
                "recoverable": False,
            }]
            return update

        agent_log = state.get("agent_log", []) or []
        if (state.get("active_sessions") or {}) and has_agent_run(agent_log, "resident"):
            return self._terminal_update(
                state,
                "success",
                "Active session confirmed and post-exploitation completed by resident.",
                "Mission objectives satisfied.",
            )

        context = self._build_context_summary(state)
        history = self._sanitize_history(state.get("supervisor_messages", []))
        try:
            content = await self._run_chat_agent(
                state,
                user_prompt=context,
                history=history,
                temperature=0.0,
                error_message="Supervisor chat completion failed.",
            )
            if isinstance(content, dict):
                raise RuntimeError(content.get("errors", [{}])[0].get("error", "OpenRouter client unavailable"))
            decision = self._parse_decision(content)
            assistant_payload = {"role": "assistant", "content": content}
        except Exception as exc:
            logger.warning("Supervisor LLM fallback engaged: %s", exc)
            decision = self._fallback_decision(state, str(exc))
            assistant_payload = {"role": "assistant", "content": json.dumps(decision.model_dump())}

        decision, guardrail_reason = self._apply_guardrails(state, decision)
        reasoning = decision.rationale if not guardrail_reason else f"{decision.rationale} | Guardrail: {guardrail_reason}"
        history = [*history, {"role": "user", "content": context}, assistant_payload]
        history = history[-max(2, self.config.supervisor_max_reasoning_messages):]

        if decision.next_agent == "end":
            terminal_status, terminal_goal = self._derive_terminal_outcome(state, decision.specific_goal)
            return self._terminal_update(state, terminal_status, reasoning, terminal_goal)

        return {
            **self._agent_update(state),
            "next_agent": decision.next_agent,
            "supervisor_messages": history,
            "supervisor_expectations": {
                "specific_goal": decision.specific_goal,
                "confidence_score": decision.confidence_score,
            },
            **self.log_action(
                state,
                action="route_decision",
                decision=decision.next_agent,
                reasoning=reasoning,
                findings={
                    "specific_goal": decision.specific_goal,
                    "confidence_score": decision.confidence_score,
                },
            ),
        }

    def _terminal_update(self, state: CyberState, mission_status: str, rationale: str, specific_goal: str) -> Dict[str, Any]:
        return {
            **self._agent_update(state),
            "next_agent": "end",
            "mission_status": mission_status,
            "supervisor_expectations": {"specific_goal": specific_goal, "confidence_score": 1.0},
            **self.log_action(
                state,
                action="route_decision",
                decision="end",
                reasoning=rationale,
                findings={"specific_goal": specific_goal, "confidence_score": 1.0},
            ),
        }

    def _build_context_summary(self, state: CyberState) -> str:
        discovered_targets = state.get("discovered_targets", {}) or {}
        web_findings = state.get("web_findings", []) or []
        active_sessions = state.get("active_sessions", {}) or {}
        critical_findings = state.get("critical_findings", []) or []
        agent_log = state.get("agent_log", []) or []

        targets_block = "\n".join(
            f"- {ip} -> {self._service_summary(details.get('services', {}) if isinstance(details, dict) else {})}"
            for ip, details in discovered_targets.items()
        ) or "- none"
        recent_block = "\n".join(
            f"- {entry.get('agent', '?') if isinstance(entry, dict) else getattr(entry, 'agent', '?')}: "
            f"{entry.get('action', entry.get('decision', '?')) if isinstance(entry, dict) else getattr(entry, 'action', '?')}"
            for entry in agent_log[-6:]
        ) or "- none"
        critical_block = "\n".join(f"- {item}" for item in critical_findings[-6:]) or "- none"

        scout_ran = has_agent_run(agent_log, "scout")
        fuzzer_ran = has_agent_run(agent_log, "fuzzer")
        librarian_ran = has_agent_run(agent_log, "librarian")
        striker_ran = has_agent_run(agent_log, "striker")
        resident_ran = has_agent_run(agent_log, "resident")
        has_targets = bool(discovered_targets)
        has_versions = has_service_version_intel(discovered_targets)
        has_web = bool(web_findings)
        has_sessions = bool(active_sessions)

        if has_sessions and resident_ran:
            phase = "Phase 6 - COMPLETE: resident finished post-exploitation -> route to end"
        elif has_sessions:
            phase = "Phase 5 - POST-EXPLOITATION: active session open -> route to resident"
        elif librarian_ran:
            phase = "Phase 4 - EXPLOITATION: intelligence gathered, no active session -> route to striker"
        elif has_targets and has_web and not fuzzer_ran:
            phase = "Phase 2 - WEB ENUMERATION: web service present -> route to fuzzer"
        elif has_web or has_targets:
            phase = "Phase 3 - INTELLIGENCE: targets/web found, librarian has not run -> route to librarian"
        elif not has_targets:
            phase = "Phase 1 - RECONNAISSANCE: no targets discovered yet -> route to scout"
        else:
            phase = "Phase unknown - use recent actions and state to decide"

        phase_flags = (
            f"targets_found={has_targets} versions_known={has_versions} web_found={has_web} active_sessions={len(active_sessions)}\n"
            f"scout_ran={scout_ran} fuzzer_ran={fuzzer_ran} librarian_ran={librarian_ran} "
            f"striker_ran={striker_ran} resident_ran={resident_ran}"
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
            f"MISSION PHASE:\n{phase}\n{phase_flags}\n"
        )

    @staticmethod
    def _service_summary(services: Dict[str, Any]) -> str:
        items = []
        for port, service in list((services or {}).items())[:8]:
            if isinstance(service, dict):
                label = f"{port}:{service.get('service_name', 'unknown')}"
                if service.get("version"):
                    label += f" {service['version']}"
            else:
                label = f"{port}:{service}"
            items.append(label)
        return ", ".join(items) if items else "no services"

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
            next_agent, goal = "end", "Mission objective satisfied after post-exploitation review."
        elif active_sessions:
            next_agent, goal = "resident", "Enumerate and stabilize active sessions."
        elif not discovered_targets:
            next_agent, goal = "scout", "Discover targets and fingerprint exposed services."
        elif web_findings and not has_agent_run(state.get("agent_log", []) or [], "librarian"):
            next_agent, goal = "librarian", "Research exploit paths from discovered findings."
        elif web_findings:
            next_agent, goal = "striker", "Attempt exploitation using researched vectors."
        else:
            next_agent, goal = "fuzzer", "Enumerate web attack surface for discovered hosts."
        return SupervisorDecision(
            next_agent=next_agent,
            rationale=f"Fallback routing due to LLM error: {reason}",
            specific_goal=goal,
            confidence_score=0.35,
        )

    def _apply_guardrails(self, state: CyberState, decision: SupervisorDecision) -> Tuple[SupervisorDecision, str]:
        next_agent = decision.next_agent.strip().lower()
        reason = ""
        if next_agent not in VALID_NEXT_AGENTS:
            next_agent = "scout" if not state.get("discovered_targets") else "librarian"
            reason = "invalid-next-agent-corrected"
        if next_agent == "striker" and has_service_version_intel(state.get("discovered_targets", {}) or {}) and not has_agent_run(state.get("agent_log", []) or [], "librarian"):
            next_agent = "librarian"
            reason = "forced-librarian-before-striker"
        if self._striker_failed_recently(state) and next_agent not in {"librarian", "fuzzer", "end"}:
            recent_agents = list_recent_agent_names(state.get("agent_log", []) or [], n=4)
            next_agent = "fuzzer" if recent_agents and recent_agents[-1] == "librarian" else "librarian"
            reason = "striker-failure-backtrack"
        return SupervisorDecision(
            next_agent=next_agent,
            rationale=decision.rationale,
            specific_goal=decision.specific_goal,
            confidence_score=decision.confidence_score,
        ), reason

    def _sanitize_history(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            {"role": role, "content": str(message.get("content", ""))}
            for message in (messages or [])
            if isinstance(message, dict)
            for role in [str(message.get("role", "")).strip().lower()]
            if role in {"user", "assistant"}
        ]

    def _striker_failed_recently(self, state: CyberState) -> bool:
        for record in reversed(state.get("exploited_services", []) or []):
            if isinstance(record, dict):
                status = str(record.get("status", "")).strip().lower()
                if status:
                    return status not in {"success", "succeeded", "opened"}
        recent_agents = [agent for agent in list_recent_agent_names(state.get("agent_log", []) or [], n=5) if agent != self.name]
        return bool(recent_agents and recent_agents[-1] == "striker" and not (state.get("active_sessions", {}) or {}))

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
        if active_sessions and any(term in mission_goal for term in ("exploit", "initial access", "session", "shell", "meterpreter", "foothold")):
            return "success", specific_goal or "Initial access objective satisfied."
        if any("session " in finding or "root privileges" in finding for finding in critical_findings):
            return "success", specific_goal or "Critical mission objective reached."
        return "wait_for_human", specific_goal or "Wait for operator confirmation before closing mission."


async def supervisor_node(state: CyberState) -> Dict[str, Any]:
    agent = SupervisorAgent()
    updates = await agent.call_llm(state)
    persist_state_update(state, updates)
    return updates
