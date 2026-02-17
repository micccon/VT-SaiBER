"""
Scout Agent - Network Reconnaissance
=====================================
Discovers targets, open ports, and services.
Uses BaseAgent pattern with MCP bridge for dynamic tool discovery.
"""

import json
from typing import Dict, Any
from datetime import datetime

from src.agents.base import BaseAgent
from src.state.cyber_state import CyberState
from src.state.models import DiscoveredTarget, ServiceInfo


class ScoutAgent(BaseAgent):
    """Network reconnaissance specialist agent."""

    def __init__(self):
        super().__init__("scout", "Network Reconnaissance Specialist")
        # Import GeminiClient for LLM reasoning
        from src.agents.demo import GeminiClient
        self.llm = GeminiClient()

    @property
    def system_prompt(self) -> str:
        return """You are a network reconnaissance specialist. Your goal is to:
        1. Analyze target IPs and discover open ports
        2. Identify services running on those ports
        3. Return findings in a structured JSON format

        Be thorough but efficient. Focus on actionable intelligence."""

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """
        Main reasoning loop for the Scout agent.

        Flow:
        1. Read target_scope from state
        2. Ask Gemini what to scan
        3. Use MCP tools for actual scanning
        4. Return validated state updates
        """
        # Step 1: Get targets from state
        target_scope = state.get("target_scope", [])
        if not target_scope:
            return self.log_error(
                state,
                error_type="ValidationError",
                error="No targets in target_scope",
            )

        target_ip = target_scope[0]
        print(f"\n[Scout] Analyzing target: {target_ip}")

        # Step 2: Validate scope (safety check)
        if not self.validate_scope(target_ip, target_scope):
            return self.log_error(
                state,
                error_type="ScopeViolation",
                error=f"Target {target_ip} not in scope",
            )

        # Step 3: Use Gemini to plan reconnaissance
        user_prompt = f"""
Target: {target_ip}
Scope: {target_scope}

Respond with exactly one JSON object (no other text) with:
- "ports_to_scan": array of port numbers to scan (e.g. [22, 80, 443])
- "scan_strategy": one of "quick", "standard", "deep"
"""
        try:
            plan = await self.llm.ask_json(
                self.system_prompt,
                user_prompt,
            )
            ports_to_scan = plan.get("ports_to_scan") or [22, 80, 443]
            if not isinstance(ports_to_scan, list):
                ports_to_scan = [22, 80, 443]
            ports_to_scan = [int(p) for p in ports_to_scan if isinstance(p, (int, float))][:20]
            if not ports_to_scan:
                ports_to_scan = [22, 80, 443]
        except (json.JSONDecodeError, TypeError) as e:
            ports_to_scan = [22, 80, 443]
            print(f"[Scout] LLM parse fallback: {e}")

        # Step 4: Try to use MCP bridge for actual scanning
        # In real implementation: call self.mcp.call_tool("nmap", {...})
        # For demo: simulate scan results
        default_services = {
            22: ServiceInfo(port=22, service_name="ssh", version="OpenSSH 8.2p1", banner="SSH-2.0-OpenSSH_8.2p1"),
            80: ServiceInfo(port=80, service_name="http", version="Apache 2.4.41", banner=None),
            443: ServiceInfo(port=443, service_name="https", version="Apache 2.4.41", banner=None),
            8080: ServiceInfo(port=8080, service_name="http-proxy", version="Unknown", banner=None),
            21: ServiceInfo(port=21, service_name="ftp", version="vsftpd 3.0.3", banner=None),
        }
        simulated_services = {
            p: default_services.get(
                p,
                ServiceInfo(port=p, service_name="unknown", version=None, banner=None),
            )
            for p in ports_to_scan
        }

        # Step 5: Build validated target
        target = DiscoveredTarget(
            ip_address=target_ip,
            ports=ports_to_scan,
            services=simulated_services,
            os_guess="Linux (Ubuntu 20.04)",
        )

        print(f"[Scout] Discovered {len(target.ports)} ports on {target_ip}")

        # Step 6: Return state updates
        return {
            "discovered_targets": {target_ip: target.model_dump()},
            **self.log_action(
                state,
                action="port_scan",
                target=target_ip,
                findings={"ports_found": target.ports, "services": len(target.services)},
                reasoning=f"Discovered {len(target.ports)} open ports",
            ),
        }


# Node function for LangGraph integration
async def scout_node(state: CyberState) -> Dict[str, Any]:
    """Scout node for LangGraph workflow."""
    agent = ScoutAgent()
    return await agent.call_llm(state)
