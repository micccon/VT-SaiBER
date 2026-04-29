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
from src.utils.agent_parsers import iter_target_services
from src.utils.parsers import extract_json_payload
from src.utils.validators import has_agent_run, has_service_version_intel, list_recent_agent_names

logger = logging.getLogger(__name__)
VALID_NEXT_AGENTS = {"scout", "fuzzer", "librarian", "striker", "resident", "end"}


class SupervisorAgent(BaseAgent):
    def __init__(self):
        """Initialize the router agent and its shared OpenRouter runtime."""

        super().__init__("supervisor", "Mission Coordinator")
        self.config = get_runtime_config()
        if self.config.openrouter_api_key:
            self._init_runtime(
                config=self.config,
                model=self.config.openrouter_model,
                base_url=self.config.openrouter_base_url,
                api_key=self.config.openrouter_api_key,
                timeout_seconds=self.config.supervisor_timeout_seconds,
            )
        else:
            logger.warning("OPENROUTER_API_KEY is not set; supervisor will use fallback routing only.")

    @property
    def system_prompt(self) -> str:
        """Prompt that constrains the supervisor to routing-only JSON decisions."""

        return (
            "You are the VT-SaiBER Supervisor. Route the mission to the best specialist worker.\n\n"
            "Roles:\n"
            "- scout: host discovery, port scanning, service fingerprinting\n"
            "- fuzzer: web directories, endpoints, API path discovery\n"
            "- librarian: knowledge-base lookup, historical finding recall, official CVE research, and documentation-guided exploit-path analysis\n"
            "- striker: exploitation, gaining shells or sessions\n"
            "- resident: session-backed objective completion after access already exists\n"
            "- end: mission complete or awaiting human review\n\n"
            'Return ONLY JSON: {"next_agent":"scout|fuzzer|librarian|striker|resident|end","rationale":"...","specific_goal":"...","confidence_score":0.0}\n\n'
            "Routing rules:\n"
            "1. Match the mission goal to the best role.\n"
            "2. Prefer the pipeline scout -> fuzzer -> librarian -> striker -> resident -> end.\n"
            "3. Never pick striker before librarian. Never pick resident without active sessions.\n"
            "4. After a failed exploit, pick librarian or fuzzer instead of striker.\n"
            "5. Only route to end when the mission is complete or human approval is required.\n"
            "6. When ambiguous, follow the MISSION PHASE recommendation.\n"
            "7. For librarian goals that prepare exploitation, say: research exploit path, map product/version to CVEs, and prepare striker with tooling guidance.\n"
            "Do not call tools."
        )

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """Route the mission to the next worker or end state."""

        iteration_count = int(state.get("iteration_count", 0))
        mission_status = str(state.get("mission_status", "active")).lower()
        # Respect terminal mission states before trying to route again.
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
            # Supervisor is the last safe place to stop the graph before an out-of-scope action happens.
            update = self._terminal_update(state, "failed", "Out-of-scope target detected. Mission aborted for safety.", "N/A")
            update["errors"] = [{
                "agent": self.name,
                "error_type": "scope_violation",
                "error": "Out-of-scope target discovered in state",
                "recoverable": False,
            }]
            return update

        agent_log = state.get("agent_log", []) or []
        resident_outcome = self._latest_resident_outcome(state)
        resident_status = str(resident_outcome.get("objective_status", "") or "").strip().lower()
        # Resident objective completion or approval gating is authoritative for closing the mission.
        if resident_status == "completed":
            return self._terminal_update(
                state,
                "success",
                "Resident reported objective completion on a live session.",
                resident_outcome.get("objective") or "Mission objectives satisfied.",
            )
        if resident_status == "needs_approval":
            return self._terminal_update(
                state,
                "wait_for_human",
                "Resident reported that the next meaningful action requires human approval.",
                resident_outcome.get("objective") or "Await human approval for resident action.",
            )

        context = self._build_context_summary(state)
        history = self._sanitize_history(state.get("supervisor_messages", []))
        try:
            # The LLM gets a compact mission snapshot and returns a strict JSON routing decision.
            content = await self._run_chat_agent(
                state,
                user_prompt=context,
                history=history,
                temperature=0.0,
                error_message="Supervisor chat completion failed.",
            )
            if isinstance(content, dict):
                raise RuntimeError(self._error_text_from_update(content, "OpenRouter client unavailable"))
            if not str(content or "").strip():
                content = await self._run_chat_agent(
                    state,
                    user_prompt=f"{context}\n\nYour previous response was empty. Return only the required JSON routing object.",
                    history=[],
                    temperature=0.0,
                    error_message="Supervisor chat completion retry failed.",
                )
                if isinstance(content, dict):
                    raise RuntimeError(self._error_text_from_update(content, "OpenRouter client unavailable"))
            decision = self._parse_decision(content)
            assistant_payload = {"role": "assistant", "content": content}
        except Exception as exc:
            # If the model path fails, fall back to deterministic routing so the graph still moves safely.
            logger.warning("Supervisor LLM fallback engaged: %s", exc)
            decision = self._fallback_decision(state, str(exc))
            assistant_payload = {"role": "assistant", "content": json.dumps(decision.model_dump())}

        # Guardrails can rewrite unsafe or out-of-order decisions without losing the model's rationale.
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
        """Build the standard terminal-state supervisor update."""

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
        """Summarize the mission state into a routing-friendly text block."""

        discovered_targets = state.get("discovered_targets", {}) or {}
        web_findings = state.get("web_findings", []) or []
        active_sessions = state.get("active_sessions", {}) or {}
        critical_findings = state.get("critical_findings", []) or []
        agent_log = state.get("agent_log", []) or []
        resident_outcome = self._latest_resident_outcome(state)
        resident_status = str(resident_outcome.get("objective_status", "") or "").strip().lower()
        resident_objective = str(resident_outcome.get("objective", "") or "").strip()
        has_services = self._has_any_services(discovered_targets)
        has_http_service = self._has_http_service(discovered_targets)

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
        has_web_surface = has_web or has_http_service
        has_sessions = bool(active_sessions)

        # The phase hint keeps the routing prompt simple while still nudging the pipeline order.
        if resident_status == "completed":
            phase = "Phase 6 - COMPLETE: resident validated objective completion -> route to end"
        elif resident_status == "needs_approval":
            phase = "Phase 6 - HUMAN APPROVAL: resident identified the next high-impact step -> route to end"
        elif has_sessions:
            if resident_status in {"blocked", "failed"}:
                phase = "Phase 5 - SESSION OBJECTIVE BLOCKED: active session remains but resident needs a new path -> route to resident or librarian"
            else:
                phase = "Phase 5 - SESSION OBJECTIVE EXECUTION: active session open -> route to resident"
        elif has_targets and not has_services and librarian_ran:
            phase = "Phase 6 - NO REMOTE ATTACK SURFACE: scout found no services and librarian already reviewed evidence -> route to end"
        elif librarian_ran:
            phase = "Phase 4 - EXPLOITATION: intelligence gathered, no active session -> route to striker"
        elif has_targets and has_web_surface and not fuzzer_ran:
            phase = "Phase 2 - WEB ENUMERATION: web service present -> route to fuzzer"
        elif has_targets and not has_services:
            phase = "Phase 3 - INTELLIGENCE: target found but no services detected -> route to librarian for no-service/deeper-enumeration guidance"
        elif has_web_surface or has_targets:
            phase = "Phase 3 - INTELLIGENCE: targets/web found, librarian has not run -> route to librarian"
        elif not has_targets:
            phase = "Phase 1 - RECONNAISSANCE: no targets discovered yet -> route to scout"
        else:
            phase = "Phase unknown - use recent actions and state to decide"

        phase_flags = (
            f"targets_found={has_targets} services_found={has_services} versions_known={has_versions} "
            f"http_service_found={has_http_service} web_found={has_web} active_sessions={len(active_sessions)}\n"
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
            f"Resident objective status: {resident_status or 'none'}\n"
            f"Resident objective: {resident_objective or '(none)'}\n"
            f"Critical findings:\n{critical_block}\n\n"
            f"Recent actions:\n{recent_block}\n\n"
            f"MISSION PHASE:\n{phase}\n{phase_flags}\n"
        )

    @staticmethod
    def _service_summary(services: Dict[str, Any]) -> str:
        """Render a short per-target service summary for the supervisor prompt."""

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

    @staticmethod
    def _error_text_from_update(update: Dict[str, Any], default: str) -> str:
        """Extract a useful error string from dict or pydantic error updates."""

        errors = update.get("errors") if isinstance(update, dict) else None
        if not errors:
            return default
        first = errors[0]
        if isinstance(first, dict):
            return str(first.get("error") or first.get("message") or default)
        return str(getattr(first, "error", None) or getattr(first, "message", None) or default)

    @staticmethod
    def _has_any_services(discovered_targets: Dict[str, Dict[str, Any]]) -> bool:
        """Return True when reconnaissance found at least one concrete service."""

        for target_data in (discovered_targets or {}).values():
            if not isinstance(target_data, dict):
                continue
            if target_data.get("ports"):
                return True
            if target_data.get("services"):
                return True
        return False

    @staticmethod
    def _has_http_service(discovered_targets: Dict[str, Dict[str, Any]]) -> bool:
        """Return True only when fuzzer has an HTTP-like service to enumerate."""

        http_names = {"http", "https", "http-proxy"}
        for _ip, port, name in iter_target_services(discovered_targets or {}):
            if name in http_names or int(port) in {80, 443, 8000, 8080, 8443}:
                return True
        return False

    def _parse_decision(self, raw_content: str) -> SupervisorDecision:
        """Parse and normalize the model's JSON routing decision."""

        payload = extract_json_payload(raw_content)
        if "confidence" in payload and "confidence_score" not in payload:
            payload["confidence_score"] = payload["confidence"]
        if "expected_outcome" in payload and "specific_goal" not in payload:
            payload["specific_goal"] = payload["expected_outcome"]
        return SupervisorDecision.model_validate(payload)

    def _fallback_decision(self, state: CyberState, reason: str) -> SupervisorDecision:
        """Use deterministic routing when the chat-completion path fails."""

        discovered_targets = state.get("discovered_targets", {}) or {}
        active_sessions = state.get("active_sessions", {}) or {}
        web_findings = state.get("web_findings", []) or []
        agent_log = state.get("agent_log", []) or []
        has_services = self._has_any_services(discovered_targets)
        has_http_service = self._has_http_service(discovered_targets)
        librarian_ran = has_agent_run(agent_log or [], "librarian")
        fuzzer_ran = has_agent_run(agent_log or [], "fuzzer")
        resident_outcome = self._latest_resident_outcome(state)
        resident_status = str(resident_outcome.get("objective_status", "") or "").strip().lower()
        resident_objective = resident_outcome.get("objective") or state.get("supervisor_expectations", {}).get("specific_goal") or state.get("mission_goal")
        if resident_status == "completed":
            next_agent, goal = "end", str(resident_objective or "Mission objective satisfied.")
        elif resident_status == "needs_approval":
            next_agent, goal = "end", str(resident_objective or "Await human approval for resident action.")
        elif active_sessions:
            if resident_status in {"blocked", "failed"} and not ((state.get("research_cache") or {}) or (state.get("intelligence_findings") or [])):
                next_agent, goal = "librarian", self._build_librarian_goal(
                    state,
                    f"Research a new path to accomplish the session-backed objective: {resident_objective}",
                )
            else:
                next_agent, goal = "resident", str(resident_objective or "Advance the current mission objective using the live session.")
        elif not discovered_targets:
            next_agent, goal = "scout", "Discover targets and fingerprint exposed services."
        elif not has_services and not librarian_ran:
            next_agent, goal = "librarian", self._build_librarian_goal(
                state,
                "Review the no-services reconnaissance result and recommend deeper safe enumeration or closure.",
            )
        elif not has_services:
            next_agent, goal = "end", "No exposed services were detected after reconnaissance and librarian review; summarize findings and request operator guidance."
        elif has_http_service and not fuzzer_ran:
            next_agent, goal = "fuzzer", "Enumerate web attack surface for discovered HTTP/HTTPS services."
        elif web_findings and not librarian_ran:
            next_agent, goal = "librarian", self._build_librarian_goal(
                state,
                "Research exploit paths from discovered findings.",
            )
        elif web_findings or librarian_ran:
            next_agent, goal = "striker", "Attempt exploitation using researched vectors."
        else:
            next_agent, goal = "librarian", self._build_librarian_goal(
                state,
                "Research the discovered non-web services and prepare a safe exploitation plan.",
            )
        return SupervisorDecision(
            next_agent=next_agent,
            rationale=f"Fallback routing due to LLM error: {reason}",
            specific_goal=goal,
            confidence_score=0.35,
        )

    def _apply_guardrails(self, state: CyberState, decision: SupervisorDecision) -> Tuple[SupervisorDecision, str]:
        """Rewrite unsafe, invalid, or out-of-order routing decisions."""

        next_agent = decision.next_agent.strip().lower()
        reason = ""
        discovered_targets = state.get("discovered_targets", {}) or {}
        agent_log = state.get("agent_log", []) or []
        has_services = self._has_any_services(discovered_targets)
        has_http_service = self._has_http_service(discovered_targets)
        librarian_ran = has_agent_run(agent_log, "librarian")
        resident_outcome = self._latest_resident_outcome(state)
        resident_status = str(resident_outcome.get("objective_status", "") or "").strip().lower()
        resident_objective = str(
            resident_outcome.get("objective")
            or state.get("supervisor_expectations", {}).get("specific_goal")
            or state.get("mission_goal")
            or ""
        ).strip()
        if next_agent not in VALID_NEXT_AGENTS:
            next_agent = "scout" if not state.get("discovered_targets") else "librarian"
            reason = "invalid-next-agent-corrected"
        if next_agent == "fuzzer" and not has_http_service:
            if not has_services and librarian_ran:
                next_agent = "end"
                reason = "fuzzer-without-services-corrected"
            elif not has_services:
                next_agent = "librarian"
                reason = "fuzzer-without-services-corrected"
            else:
                next_agent = "librarian"
                reason = "fuzzer-without-http-service-corrected"
        if next_agent == "resident" and not (state.get("active_sessions") or {}):
            next_agent = "striker" if librarian_ran else "librarian"
            reason = "resident-without-session-corrected"
        if next_agent == "end" and (state.get("active_sessions") or {}) and resident_status not in {"completed", "needs_approval"}:
            if resident_status in {"blocked", "failed"} and not ((state.get("research_cache") or {}) or (state.get("intelligence_findings") or [])):
                next_agent = "librarian"
                reason = "resident-needs-new-intel"
            else:
                next_agent = "resident"
                reason = "resident-not-finished"
        if next_agent == "striker" and has_service_version_intel(discovered_targets) and not librarian_ran:
            next_agent = "librarian"
            reason = "forced-librarian-before-striker"
        if self._striker_failed_recently(state) and next_agent not in {"librarian", "fuzzer", "end"}:
            recent_agents = list_recent_agent_names(state.get("agent_log", []) or [], n=4)
            next_agent = "fuzzer" if recent_agents and recent_agents[-1] == "librarian" else "librarian"
            reason = "striker-failure-backtrack"
        return SupervisorDecision(
            next_agent=next_agent,
            rationale=decision.rationale,
            specific_goal=self._rewrite_specific_goal(state, next_agent, resident_objective, decision.specific_goal),
            confidence_score=decision.confidence_score,
        ), reason

    def _rewrite_specific_goal(
        self,
        state: CyberState,
        next_agent: str,
        resident_objective: str,
        original_goal: str,
    ) -> str:
        if next_agent == "resident" and resident_objective:
            return resident_objective
        if next_agent == "librarian":
            return self._build_librarian_goal(state, original_goal)
        return original_goal

    def _build_librarian_goal(self, state: CyberState, base_goal: str) -> str:
        services: List[str] = []
        discovered_targets = state.get("discovered_targets", {}) or {}
        for ip, details in list(discovered_targets.items())[:3]:
            service_map = details.get("services", {}) if isinstance(details, dict) else {}
            for port, service in list((service_map or {}).items())[:6]:
                if isinstance(service, dict):
                    label = f"{ip}:{port} {service.get('service_name', 'unknown')}"
                    version = str(service.get("version") or service.get("service_version") or "").strip()
                    if version:
                        label += f" {version}"
                else:
                    label = f"{ip}:{port} {service}"
                services.append(label)

        hints: List[str] = []
        if services:
            hints.append("services=" + "; ".join(services[:6]))

        recent_failures: List[str] = []
        for attempt in (state.get("exploit_attempts", []) or [])[-4:]:
            if not isinstance(attempt, dict):
                continue
            status = str(attempt.get("status") or "").strip().lower()
            if status and status not in {"success", "succeeded", "opened"}:
                recent_failures.append(str(attempt.get("summary") or attempt.get("module") or status))
        if recent_failures:
            hints.append("recent_failures=" + "; ".join(recent_failures[:3]))

        active_sessions = state.get("active_sessions", {}) or {}
        if active_sessions:
            hints.append(f"active_sessions={len(active_sessions)}")

        guidance = (
            "Research exploit path and prepare striker. Use KB and historical findings first, map exact products/versions to official CVE and KEV data, "
            "then use targeted external documentation or OSINT for exploit modules, tooling guidance, and practical caveats."
        )
        suffix = f" {' | '.join(hints)}" if hints else ""
        return f"{base_goal} {guidance}{suffix}".strip()

    def _sanitize_history(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Keep only clean user/assistant messages in supervisor history."""

        return [
            {"role": role, "content": str(message.get("content", ""))}
            for message in (messages or [])
            if isinstance(message, dict)
            for role in [str(message.get("role", "")).strip().lower()]
            if role in {"user", "assistant"}
        ]

    def _striker_failed_recently(self, state: CyberState) -> bool:
        """Detect whether the most recent exploitation path failed and needs backtracking."""

        for record in reversed(state.get("exploited_services", []) or []):
            if isinstance(record, dict):
                status = str(record.get("status", "")).strip().lower()
                if status:
                    return status not in {"success", "succeeded", "opened"}
        recent_agents = [agent for agent in list_recent_agent_names(state.get("agent_log", []) or [], n=5) if agent != self.name]
        return bool(recent_agents and recent_agents[-1] == "striker" and not (state.get("active_sessions", {}) or {}))

    def _latest_resident_outcome(self, state: CyberState) -> Dict[str, Any]:
        """Read the most recent resident objective status from validations or agent logs."""

        for validation in reversed(state.get("validations", []) or []):
            if isinstance(validation, dict) and validation.get("type") == "resident_objective":
                outcome = dict(validation)
                if not outcome.get("objective_status") and outcome.get("status"):
                    outcome["objective_status"] = outcome.get("status")
                return outcome
        for entry in reversed(state.get("agent_log", []) or []):
            if not isinstance(entry, dict):
                if getattr(entry, "agent", "") != "resident":
                    continue
                findings = getattr(entry, "findings", None)
                if isinstance(findings, dict) and findings.get("objective_status"):
                    return dict(findings)
                continue
            if str(entry.get("agent", "")).strip().lower() != "resident":
                continue
            findings = entry.get("findings")
            if isinstance(findings, dict) and findings.get("objective_status"):
                return dict(findings)
        return {}

    def _derive_terminal_outcome(self, state: CyberState, specific_goal: str) -> Tuple[str, str]:
        """Translate a route-to-end decision into a concrete terminal mission status."""

        mission_status = str(state.get("mission_status", "active")).strip().lower()
        if mission_status in {"success", "failed", "wait_for_human"}:
            return mission_status, specific_goal or "N/A"
        resident_outcome = self._latest_resident_outcome(state)
        resident_status = str(resident_outcome.get("objective_status", "") or "").strip().lower()
        resident_objective = str(resident_outcome.get("objective", "") or specific_goal or "").strip()
        if resident_status == "completed":
            return "success", resident_objective or "Resident completed the session-backed objective."
        if resident_status == "needs_approval":
            return "wait_for_human", resident_objective or "Resident requires approval for the next step."
        return "wait_for_human", specific_goal or "Wait for operator confirmation before closing mission."


async def supervisor_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper for the supervisor."""

    agent = SupervisorAgent()
    updates = await agent.call_llm(state)
    persist_state_update(state, updates)
    return updates
