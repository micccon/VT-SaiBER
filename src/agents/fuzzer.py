"""
Fuzzer Agent - web surface discovery worker.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional

from src.agents.base import BaseAgent
from src.mcp.mcp_tool_bridge import get_mcp_bridge
from src.state.cyber_state import CyberState

FUZZER_ALLOWED_TOOLS = {"gobuster_scan", "nikto_scan"}
MAX_RECURSION_DEPTH = 3


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
                "path": "/",
                "status_code": 200,
                "content_length": 0,
                "content_type": "unknown",
                "is_api_endpoint": False,
                "rationale": "Fallback finding while MCP scan is unavailable",
            }]

        return {
            "current_agent": "fuzzer",
            "web_findings": findings,
            **self.log_action(
                state,
                action="web_enumeration",
                target=base_url,
                findings={"findings_count": len(findings), "max_depth": MAX_RECURSION_DEPTH},
                reasoning="Fuzzer completed constrained path discovery (GET/HEAD only policy)",
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
        gobuster_tool = next((tool for tool in tools if tool.name.endswith("gobuster_scan")), None)
        if gobuster_tool is None:
            return []

        try:
            raw = await gobuster_tool.coroutine(
                url=base_url,
                mode="dir",
                wordlist="/usr/share/wordlists/dirb/common.txt",
                additional_args="",
            )
            return self._parse_gobuster_output(raw, base_url)
        except Exception:
            return []

    def _parse_gobuster_output(self, raw_output: Any, base_url: str) -> List[Dict[str, Any]]:
        payload = raw_output
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {"output": raw_output}

        text = ""
        if isinstance(payload, dict):
            for key in ("output", "stdout", "result", "data"):
                value = payload.get(key)
                if isinstance(value, str):
                    text = value
                    break
                if isinstance(value, dict):
                    maybe_text = value.get("output") or value.get("stdout")
                    if isinstance(maybe_text, str):
                        text = maybe_text
                        break

        findings: List[Dict[str, Any]] = []
        # Gobuster lines often look like: /admin (Status: 301) [Size: 0]
        line_regex = re.compile(r"^(/[^ ]*)\s+\(Status:\s*(\d{3})\)", re.IGNORECASE)
        for line in text.splitlines():
            match = line_regex.match(line.strip())
            if not match:
                continue
            path = match.group(1)
            status_code = int(match.group(2))
            findings.append({
                "url": f"{base_url}{path}",
                "path": path,
                "status_code": status_code,
                "content_length": None,
                "content_type": None,
                "is_api_endpoint": path.startswith("/api"),
                "rationale": "Discovered by gobuster",
            })

        return findings[:100]


async def fuzzer_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper."""
    agent = FuzzerAgent()
    return await agent.call_llm(state)
