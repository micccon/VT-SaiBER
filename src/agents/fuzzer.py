"""Fuzzer Agent - web surface discovery worker."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from src.agents.base import BaseAgent
from src.config import get_runtime_config
from src.database.persistence import persist_state_update
from src.state.cyber_state import CyberState
from src.utils.agent_runtime import iter_tool_messages
from src.utils.agent_parsers import dedupe_web_findings, iter_target_services, parse_gobuster_output, parse_nikto_output

FUZZER_ALLOWED_TOOLS = {"web_content_enum", "web_nikto_scan"}
MAX_RECURSION_DEPTH = 3
REQUEST_THROTTLE_MS = 200
SOFT_404_STATUSES = {404}


class FuzzerAgent(BaseAgent):
    """Enumerates web paths and stores normalized findings."""

    def __init__(self):
        super().__init__("fuzzer", "Web Fuzzing Specialist")
        self._init_runtime(config=get_runtime_config())

    @property
    def system_prompt(self) -> str:
        return (
            "You are the VT-SaiBER fuzzer agent.\n"
            "Use only the provided web enumeration tools.\n"
            "Enumerate the supplied web target carefully and gather useful attack-surface findings.\n"
            "Prefer web_content_enum first, then web_nikto_scan for additional signals.\n"
            "Stay focused on the provided target."
        )

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        target = self._pick_web_target(state.get("discovered_targets", {}) or {})
        if target is None:
            return self._error_update(
                state,
                error_type="ValidationError",
                message="No HTTP/HTTPS service found in discovered_targets",
            )

        ip = target["ip"]
        port = target["port"]
        scheme = "https" if port == 443 else "http"
        base_url = f"{scheme}://{ip}:{port}" if port not in {80, 443} else f"{scheme}://{ip}"

        findings_update = await self._run_tool_agent(
            state,
            user_prompt=self._build_context(state, base_url),
            allowed_tools=FUZZER_ALLOWED_TOOLS,
            extractor=lambda messages, _: {"web_findings": self._extract_updates(messages, base_url)},
            max_rounds=5,
            error_message="Fuzzer LLM/tool loop failed.",
        )
        if "errors" in findings_update:
            return findings_update
        findings = findings_update.get("web_findings", [])
        if not findings:
            findings = [{
                "url": f"{base_url}/",
                "path": "/",
                "status_code": 200,
                "content_length": 0,
                "content_type": "unknown",
                "is_api_endpoint": False,
                "is_interesting": False,
                "discovery_depth": 0,
                "scan_policy": self._scan_policy(),
                "rationale": "Fallback finding while MCP scan is unavailable",
            }]

        return {
            **self._agent_update(state),
            "web_findings": findings,
            **self.log_action(
                state,
                action="web_enumeration",
                target=base_url,
                findings={
                    "findings_count": len(findings),
                    "max_depth": MAX_RECURSION_DEPTH,
                    "request_throttle_ms": REQUEST_THROTTLE_MS,
                    "soft_404_detection": True,
                },
                reasoning="Fuzzer completed constrained GET/HEAD path discovery with soft-404 filtering",
            ),
        }

    def _pick_web_target(self, discovered_targets: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        for ip, port, name in iter_target_services(discovered_targets):
            if name in {"http", "https", "http-proxy"}:
                return {"ip": ip, "port": int(port), "service_name": name}
        return None

    def _build_context(self, state: CyberState, base_url: str) -> str:
        existing = state.get("web_findings", []) or []
        return (
            f"MISSION: {state.get('mission_goal') or '(not specified)'}\n\n"
            f"TARGET URL: {base_url}\n"
            f"EXISTING WEB FINDINGS: {len(existing)}\n\n"
            "Enumerate high-value paths, endpoints, and weak web surface indicators for this target."
        )

    def _extract_updates(self, messages: List[Dict[str, Any]], base_url: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        for message, data in iter_tool_messages(messages):
            name = str(message.get("name", "") or "")
            if name == "web_content_enum":
                findings.extend(
                    parse_gobuster_output(
                        data,
                        base_url=base_url,
                        max_depth=MAX_RECURSION_DEPTH,
                        soft_404_statuses=SOFT_404_STATUSES,
                        scan_policy=self._scan_policy(),
                    )
                )
            elif name == "web_nikto_scan":
                findings.extend(
                    parse_nikto_output(
                        data,
                        base_url=base_url,
                        max_depth=MAX_RECURSION_DEPTH,
                        scan_policy=self._scan_policy(),
                    )
                )

        return dedupe_web_findings(findings)[:100]

    def _scan_policy(self) -> Dict[str, Any]:
        return {
            "methods": ["GET", "HEAD"],
            "max_depth": MAX_RECURSION_DEPTH,
            "request_throttle_ms": REQUEST_THROTTLE_MS,
            "soft_404_detection": True,
        }


async def fuzzer_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper."""
    agent = FuzzerAgent()
    updates = await agent.call_llm(state)
    persist_state_update(state, updates)
    return updates
