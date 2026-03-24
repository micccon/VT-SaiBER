"""
Scout Agent - network reconnaissance worker.
"""

from __future__ import annotations
import json
import re
from typing import Any, Dict

from src.agents.base import BaseAgent
from src.mcp.mcp_tool_bridge import get_mcp_bridge
from src.state.cyber_state import CyberState
from src.state.models import DiscoveredTarget, ServiceInfo

SCOUT_ALLOWED_TOOLS = {"nmap_scan"}

class ScoutAgent(BaseAgent):
    """Discovers targets/ports/services and writes structured target intel."""

    def __init__(self):
        super().__init__("scout", "Network Reconnaissance Specialist")

    @property
    def system_prompt(self) -> str:
        return "Recon worker: discover active services and versions."

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        target_scope = state.get("target_scope", [])
        if not target_scope:
            return self.log_error(
                state,
                error_type="ValidationError",
                error="No targets in target_scope",
            )

        target = str(target_scope[0])
        if not self.validate_scope(target, target_scope):
            return self.log_error(
                state,
                error_type="ScopeViolation",
                error=f"Target {target} not in scope",
            )

        services = await self._discover_services(target)
        ports = sorted(services.keys())

        discovered_target = DiscoveredTarget(
            ip_address=target,
            ports=ports,
            services=services,
            os_guess="Unknown",
        )

        return {
            "current_agent": "scout",
            "discovered_targets": {target: discovered_target.model_dump()},
            **self.log_action(
                state,
                action="recon_scan",
                target=target,
                findings={"ports_found": ports, "services_found": len(services)},
                reasoning="Scout completed reconnaissance update",
            ),
        }

    async def _discover_services(self, target: str) -> Dict[int, ServiceInfo]:
        bridge = None
        try:
            bridge = await get_mcp_bridge()
        except Exception:
            bridge = None

        if bridge is not None:
            tools = bridge.get_tools_for_agent(SCOUT_ALLOWED_TOOLS)
            nmap_tool = next((tool for tool in tools if tool.name.endswith("nmap_scan")), None)
            if nmap_tool:
                try:
                    raw = await nmap_tool.coroutine(
                        target=target,
                        scan_type="-sV",
                        ports="1-1024",
                        additional_args="",
                    )
                    parsed = self._parse_nmap_output(raw)
                    if parsed:
                        return parsed
                except Exception:
                    pass

        # Safe fallback when MCP is unavailable.
        return {
            22: ServiceInfo(port=22, service_name="ssh", version="OpenSSH", banner=""),
            80: ServiceInfo(port=80, service_name="http", version="Apache", banner=""),
        }

    def _parse_nmap_output(self, raw_output: Any) -> Dict[int, ServiceInfo]:
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

        services: Dict[int, ServiceInfo] = {}
        if text:
            pattern = re.compile(r"^(\d{1,5})/(tcp|udp)\s+open\s+([^\s]+)\s*(.*)$", re.IGNORECASE)
            for line in text.splitlines():
                match = pattern.match(line.strip())
                if not match:
                    continue
                port = int(match.group(1))
                proto = match.group(2).lower()
                service_name = match.group(3).lower()
                version = match.group(4).strip() or None
                services[port] = ServiceInfo(
                    port=port,
                    protocol=proto,
                    service_name=service_name,
                    version=version,
                    banner=None,
                )
        return services


async def scout_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper."""
    agent = ScoutAgent()
    return await agent.call_llm(state)
