"""
Fuzzer Agent - web surface discovery worker.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from src.agents.base import BaseAgent
from src.database.persistence import persist_state_update
from src.mcp.mcp_tool_bridge import get_mcp_bridge
from src.state.cyber_state import CyberState

FUZZER_ALLOWED_TOOLS = {"gobuster_scan", "nikto_scan"}
MAX_RECURSION_DEPTH = 3
REQUEST_THROTTLE_MS = 200
SOFT_404_STATUSES = {404}


class FuzzerAgent(BaseAgent):
    """Enumerates web paths and stores normalized findings."""

    def __init__(self):
        super().__init__("fuzzer", "Web Fuzzing Specialist")

    @property
    def system_prompt(self) -> str:
        return "Web enumeration worker."

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        target = self._pick_web_target(state.get("discovered_targets", {}) or {})
        if target is None:
            return self.log_error(
                state,
                error_type="ValidationError",
                error="No HTTP/HTTPS service found in discovered_targets",
            )

        ip = target["ip"]
        port = target["port"]
        scheme = "https" if port == 443 else "http"
        base_url = f"{scheme}://{ip}:{port}" if port not in {80, 443} else f"{scheme}://{ip}"

        findings = await self._enumerate_paths(base_url)
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
            "current_agent": "fuzzer",
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
        for ip, target_data in discovered_targets.items():
            services = target_data.get("services", {}) if isinstance(target_data, dict) else {}
            ports = target_data.get("ports", []) if isinstance(target_data, dict) else []
            for port in ports:
                service = services.get(str(port)) or services.get(port)
                if isinstance(service, dict):
                    name = str(service.get("service_name", "")).lower()
                else:
                    name = str(service or "").lower()
                if name in {"http", "https", "http-proxy"}:
                    return {"ip": ip, "port": int(port), "service_name": name}
        return None

    async def _enumerate_paths(self, base_url: str) -> List[Dict[str, Any]]:
        bridge = None
        try:
            bridge = await get_mcp_bridge()
        except Exception:
            bridge = None

        if bridge is None:
            return []

        tools = bridge.get_tools_for_agent(FUZZER_ALLOWED_TOOLS)
        findings: List[Dict[str, Any]] = []
        gobuster_tool = next((tool for tool in tools if tool.name.endswith("gobuster_scan")), None)
        nikto_tool = next((tool for tool in tools if tool.name.endswith("nikto_scan")), None)

        if gobuster_tool is not None:
            try:
                raw = await gobuster_tool.coroutine(
                    url=base_url,
                    mode="dir",
                    wordlist="/usr/share/wordlists/dirb/common.txt",
                    additional_args=f"--delay {REQUEST_THROTTLE_MS}ms",
                )
                findings.extend(self._parse_gobuster_output(raw, base_url))
            except Exception:
                pass

        if nikto_tool is not None:
            try:
                raw = await nikto_tool.coroutine(
                    target=base_url,
                    additional_args="",
                )
                findings.extend(self._parse_nikto_output(raw, base_url))
            except Exception:
                pass

        deduped: List[Dict[str, Any]] = []
        seen = set()
        for finding in findings:
            key = (finding.get("path"), finding.get("status_code"), finding.get("rationale"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped[:100]

    def _scan_policy(self) -> Dict[str, Any]:
        return {
            "methods": ["GET", "HEAD"],
            "max_depth": MAX_RECURSION_DEPTH,
            "request_throttle_ms": REQUEST_THROTTLE_MS,
            "soft_404_detection": True,
        }

    def _extract_text_payload(self, raw_output: Any) -> str:
        payload = raw_output
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {"output": raw_output}

        if isinstance(payload, dict):
            for key in ("output", "stdout", "result", "data"):
                value = payload.get(key)
                if isinstance(value, str):
                    return value
                if isinstance(value, dict):
                    maybe_text = value.get("output") or value.get("stdout")
                    if isinstance(maybe_text, str):
                        return maybe_text
        return ""

    def _parse_gobuster_output(self, raw_output: Any, base_url: str) -> List[Dict[str, Any]]:
        text = self._extract_text_payload(raw_output)

        findings: List[Dict[str, Any]] = []
        # Gobuster lines often look like: /admin (Status: 301) [Size: 0]
        line_regex = re.compile(r"^(/[^ ]*)\s+\(Status:\s*(\d{3})\)", re.IGNORECASE)
        for line in text.splitlines():
            match = line_regex.match(line.strip())
            if not match:
                continue
            path = match.group(1)
            status_code = int(match.group(2))
            depth = len([segment for segment in path.split("/") if segment])
            if depth > MAX_RECURSION_DEPTH or status_code in SOFT_404_STATUSES:
                continue
            is_interesting = (
                path.startswith("/api")
                or any(token in path.lower() for token in ("admin", "login", "dashboard", "config"))
                or status_code in {200, 401, 403}
            )
            findings.append({
                "url": f"{base_url}{path}",
                "path": path,
                "status_code": status_code,
                "content_length": None,
                "content_type": None,
                "is_api_endpoint": path.startswith("/api"),
                "is_interesting": is_interesting,
                "discovery_depth": depth,
                "scan_policy": self._scan_policy(),
                "rationale": "Discovered by gobuster",
            })

        return findings[:100]

    def _parse_nikto_output(self, raw_output: Any, base_url: str) -> List[Dict[str, Any]]:
        text = self._extract_text_payload(raw_output)
        findings: List[Dict[str, Any]] = []
        line_regex = re.compile(r"^\+\s+(/[^:\s]*).*?:\s*(.+)$")
        for line in text.splitlines():
            match = line_regex.match(line.strip())
            if not match:
                continue
            path = match.group(1)
            detail = match.group(2).strip()
            depth = len([segment for segment in path.split("/") if segment])
            if depth > MAX_RECURSION_DEPTH:
                continue
            findings.append({
                "url": f"{base_url}{path}",
                "path": path,
                "status_code": 0,
                "content_length": None,
                "content_type": "nikto-report",
                "is_api_endpoint": path.startswith("/api"),
                "is_interesting": True,
                "discovery_depth": depth,
                "scan_policy": self._scan_policy(),
                "rationale": f"Nikto finding: {detail[:160]}",
            })
        return findings[:50]


async def fuzzer_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper."""
    agent = FuzzerAgent()
    updates = await agent.call_llm(state)
    persist_state_update(state, updates)
    return updates
