"""Scout Agent - network reconnaissance worker."""

from __future__ import annotations

from typing import Any, Dict, List

from src.agents.base import BaseAgent
from src.config import get_runtime_config
from src.database.persistence import persist_state_update
from src.state.cyber_state import CyberState
from src.state.models import DiscoveredTarget
from src.utils.agent_runtime import iter_tool_messages
from src.utils.agent_parsers import parse_host_discovery_output, parse_nmap_output, parse_service_records
from src.utils.validators import target_in_scope

SCOUT_ALLOWED_TOOLS = {"recon_host_discovery", "recon_port_scan", "recon_service_probe"}
MAX_SCOUT_TARGETS = 5

class ScoutAgent(BaseAgent):
    """Discovers targets/ports/services and writes structured target intel."""

    def __init__(self):
        """Initialize the shared runtime for reconnaissance."""

        super().__init__("scout", "Network Reconnaissance Specialist")
        self._init_runtime(config=get_runtime_config())

    @property
    def system_prompt(self) -> str:
        """Prompt that keeps scout constrained to in-scope recon work."""

        return (
            "You are the VT-SaiBER scout agent.\n"
            "Use only the provided recon tools.\n"
            "If scope contains concrete hosts, probe them directly.\n"
            "If scope contains CIDR ranges, discover live hosts first, then probe up to "
            f"{MAX_SCOUT_TARGETS} in-scope hosts.\n"
            "Prefer recon_service_probe for service/version detail.\n"
            "Do not go out of scope.\n"
            "Finish with a concise summary."
        )

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """Run the shared tool loop for host discovery and service probing."""

        target_scope = state.get("target_scope", [])
        if not target_scope:
            return self._error_update(
                state,
                error_type="ValidationError",
                message="No targets in target_scope",
            )
        return await self._run_tool_agent(
            state,
            user_prompt=self._build_context(state),
            allowed_tools=SCOUT_ALLOWED_TOOLS,
            extractor=self._extract_updates,
            max_rounds=6,
            error_message="Scout LLM/tool loop failed.",
        )

    def _build_context(self, state: CyberState) -> str:
        """Build a compact recon objective for the model."""

        discovered_targets = list((state.get("discovered_targets", {}) or {}).keys())
        target_scope = state.get("target_scope", []) or []
        return (
            f"MISSION: {state.get('mission_goal') or '(not specified)'}\n\n"
            f"TARGET SCOPE: {target_scope}\n"
            f"ALREADY KNOWN TARGETS: {discovered_targets[:MAX_SCOUT_TARGETS] or '(none)'}\n\n"
            "Discover live in-scope hosts and enumerate their exposed services with versions."
        )

    def _extract_updates(self, messages: List[Dict[str, Any]], state: CyberState) -> Dict[str, Any]:
        """Convert recon tool messages into structured discovered_targets updates."""

        target_scope = state.get("target_scope", []) or []
        discovered_targets: Dict[str, Dict[str, Any]] = {}
        discovered_hosts: List[str] = []

        # Track IPs discovered from in-scope hostnames
        resolved_ips: set[str] = set()

        for message, data in iter_tool_messages(messages):
            name = str(message.get("name", "") or "")
            invocation = data.get("invocation", {}) if isinstance(data.get("invocation"), dict) else {}

            if name == "recon_host_discovery":
                # Check if the original targets argument was in scope
                scan_targets = str(invocation.get("targets") or "").strip()
                original_in_scope = any(target_in_scope(t.strip(), target_scope) for t in scan_targets.split(",") if t.strip())

                evidence = data.get("evidence", {}) if isinstance(data, dict) else {}
                if isinstance(evidence, dict) and isinstance(evidence.get("hosts"), list):
                    for host in evidence["hosts"]:
                        host_text = str(host)
                        # Accept if original target was in scope OR the IP itself is in scope
                        if (original_in_scope or target_in_scope(host_text, target_scope)) and host_text not in discovered_hosts:
                            discovered_hosts.append(host_text)
                            resolved_ips.add(host_text)
                else:
                    for host in parse_host_discovery_output(data, max_hosts=MAX_SCOUT_TARGETS):
                        if (original_in_scope or target_in_scope(host, target_scope)) and host not in discovered_hosts:
                            discovered_hosts.append(host)
                            resolved_ips.add(host)
                continue

            if name not in {"recon_service_probe", "recon_port_scan"}:
                continue

            # Only persist service data for validated in-scope targets.
            target = str(invocation.get("target") or "").strip()
            # Accept if target is in scope OR was resolved from an in-scope hostname
            if not target or not (target_in_scope(target, target_scope) or target in resolved_ips):
                continue

            evidence = data.get("evidence", {}) if isinstance(data, dict) else {}
            services = evidence.get("services", []) if isinstance(evidence, dict) else []
            parsed = parse_service_records(services)
            if not parsed:
                # Fall back to raw nmap-style parsing when the tool did not return normalized services.
                parsed = parse_nmap_output(data)
            if not parsed:
                continue

            discovered_target = DiscoveredTarget(
                ip_address=target,
                ports=sorted(parsed.keys()),
                services=parsed,
                os_guess="Unknown",
            )
            discovered_targets[target] = discovered_target.model_dump()

        if not discovered_targets:
            # If scout only found live hosts, still preserve them so the pipeline can continue.
            for host in discovered_hosts[:MAX_SCOUT_TARGETS]:
                discovered_targets[host] = DiscoveredTarget(
                    ip_address=host,
                    ports=[],
                    services={},
                    os_guess="Unknown",
                ).model_dump()

        if not discovered_targets:
            return self._error_update(
                state,
                error_type="ValidationError",
                message="Scout did not produce any in-scope targets or services",
            )

        total_ports = sorted(
            {
                int(port)
                for target in discovered_targets.values()
                for port in (target.get("ports", []) or [])
            }
        )
        total_services = sum(
            len((target.get("services", {}) or {}))
            for target in discovered_targets.values()
        )

        return {
            "discovered_targets": discovered_targets,
            **self._agent_update(state),
            **self.log_action(
                state,
                action="recon_scan",
                target=", ".join(discovered_targets.keys()),
                findings={
                    "targets_scanned": list(discovered_targets.keys()),
                    "ports_found": total_ports,
                    "services_found": total_services,
                },
                reasoning="Scout completed reconnaissance update using shared OpenRouter tool orchestration",
            ),
        }


async def scout_node(state: CyberState) -> Dict[str, Any]:
    """LangGraph node wrapper."""
    agent = ScoutAgent()
    updates = await agent.call_llm(state)
    persist_state_update(state, updates)
    return updates
