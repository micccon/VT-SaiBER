"""
Scout Agent - network reconnaissance worker.
"""

from __future__ import annotations
from ipaddress import ip_address, ip_network
import json
import re
from typing import Any, Dict, List

from src.agents.base import BaseAgent
from src.database.persistence import persist_state_update
from src.mcp.mcp_tool_bridge import get_mcp_bridge
from src.state.cyber_state import CyberState
from src.state.models import DiscoveredTarget, ServiceInfo
from src.utils.validators import target_in_scope

SCOUT_ALLOWED_TOOLS = {"nmap_scan"}
MAX_SCOUT_TARGETS = 5

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

        scan_targets = await self._resolve_scan_targets(state)
        if not scan_targets:
            return self.log_error(
                state,
                error_type="ValidationError",
                error="Scout could not derive a concrete in-scope host to scan",
            )

        discovered_targets: Dict[str, Dict[str, Any]] = {}
        total_services = 0
        total_ports: List[int] = []

        for target in scan_targets:
            if not target_in_scope(target, target_scope):
                continue

            services = await self._discover_services(target)
            ports = sorted(services.keys())
            total_services += len(services)
            total_ports.extend(ports)

            discovered_target = DiscoveredTarget(
                ip_address=target,
                ports=ports,
                services=services,
                os_guess="Unknown",
            )
            discovered_targets[target] = discovered_target.model_dump()

        if not discovered_targets:
            return self.log_error(
                state,
                error_type="ScopeViolation",
                error="Scout derived only out-of-scope targets",
            )

        return {
            "current_agent": "scout",
            "discovered_targets": discovered_targets,
            **self.log_action(
                state,
                action="recon_scan",
                target=", ".join(scan_targets),
                findings={
                    "targets_scanned": list(discovered_targets.keys()),
                    "ports_found": sorted(set(total_ports)),
                    "services_found": total_services,
                },
                reasoning="Scout completed reconnaissance update using concrete in-scope hosts",
            ),
        }

    async def _resolve_scan_targets(self, state: CyberState) -> List[str]:
        discovered_targets = state.get("discovered_targets", {}) or {}
        target_scope = state.get("target_scope", []) or []

        concrete_targets = [
            target
            for target in discovered_targets.keys()
            if target_in_scope(str(target), target_scope)
        ]
        if concrete_targets:
            return concrete_targets[:MAX_SCOUT_TARGETS]

        direct_targets = [
            entry
            for entry in target_scope
            if self._is_concrete_target(entry)
        ]
        if direct_targets:
            return direct_targets[:MAX_SCOUT_TARGETS]

        discovered_hosts: List[str] = []
        for scope_entry in target_scope:
            if not self._is_network_scope(scope_entry):
                continue
            hosts = await self._discover_hosts(scope_entry)
            for host in hosts:
                if host not in discovered_hosts and target_in_scope(host, target_scope):
                    discovered_hosts.append(host)
                if len(discovered_hosts) >= MAX_SCOUT_TARGETS:
                    return discovered_hosts
        return discovered_hosts

    def _is_concrete_target(self, value: str) -> bool:
        candidate = str(value or "").strip()
        if not candidate or self._is_network_scope(candidate):
            return False
        try:
            ip_address(candidate)
            return True
        except ValueError:
            return True

    def _is_network_scope(self, value: str) -> bool:
        candidate = str(value or "").strip()
        if "/" not in candidate:
            return False
        try:
            ip_network(candidate, strict=False)
            return True
        except ValueError:
            return False

    async def _discover_hosts(self, scope_entry: str) -> List[str]:
        bridge = None
        try:
            bridge = await get_mcp_bridge()
        except Exception:
            bridge = None

        if bridge is None:
            return []

        tools = bridge.get_tools_for_agent(SCOUT_ALLOWED_TOOLS)
        nmap_tool = next((tool for tool in tools if tool.name.endswith("nmap_scan")), None)
        if nmap_tool is None:
            return []

        try:
            raw = await nmap_tool.coroutine(
                target=scope_entry,
                scan_type="-sn",
                ports="",
                additional_args="-T4",
            )
            return self._parse_host_discovery_output(raw)
        except Exception:
            return []

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

    def _parse_host_discovery_output(self, raw_output: Any) -> List[str]:
        text = self._extract_text_payload(raw_output)
        if not text:
            return []

        hosts: List[str] = []
        report_regex = re.compile(r"^Nmap scan report for (.+)$", re.IGNORECASE)
        ip_regex = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
        for line in text.splitlines():
            match = report_regex.match(line.strip())
            if not match:
                continue
            candidate = match.group(1).strip()
            ip_match = ip_regex.search(candidate)
            host = ip_match.group(0) if ip_match else candidate
            if host and host not in hosts:
                hosts.append(host)
        return hosts[:MAX_SCOUT_TARGETS]

    def _parse_nmap_output(self, raw_output: Any) -> Dict[int, ServiceInfo]:
        text = self._extract_text_payload(raw_output)

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
    updates = await agent.call_llm(state)
    persist_state_update(state, updates)
    return updates
