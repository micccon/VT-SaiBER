"""
Fuzzer Agent - Web Vulnerability Discovery
===========================================
Discovers web vulnerabilities through fuzzing and enumeration.
Uses BaseAgent pattern with MCP bridge for tool discovery.
"""

from typing import Dict, Any
from datetime import datetime

from src.agents.base import BaseAgent
from src.state.cyber_state import CyberState


class FuzzerAgent(BaseAgent):
    """Web fuzzing specialist agent."""

    def __init__(self):
        super().__init__("fuzzer", "Web Fuzzing Specialist")
        # Import GeminiClient for LLM reasoning
        from src.agents.demo import GeminiClient
        self.llm = GeminiClient()

    @property
    def system_prompt(self) -> str:
        return """You are a web fuzzing specialist. Your goal is to:
        1. Enumerate paths and endpoints on web servers
        2. Identify interesting endpoints and parameters
        3. Test for common vulnerabilities (SQLi, XSS, etc.)
        4. Return findings in a structured JSON format

        Be thorough but efficient. Focus on high-impact findings."""

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """
        Main reasoning loop for the Fuzzer agent.

        Flow:
        1. Get discovered targets from state
        2. Identify web services (ports 80, 443, 8080, etc.)
        3. Use Gemini to plan fuzzing strategy
        4. Execute fuzzing (in production, would use MCP tools)
        5. Return validated state updates
        """
        # Step 1: Get discovered targets
        discovered_targets = state.get("discovered_targets", {})
        if not discovered_targets:
            return self.log_error(
                state,
                error_type="ValidationError",
                error="No discovered targets - run scout first",
            )

        # Step 2: Find web services
        web_targets = []
        for ip, target_data in discovered_targets.items():
            services = target_data.get("services", {})
            ports = target_data.get("ports", [])
            for port in ports:
                service = services.get(str(port)) or services.get(port)
                if service and isinstance(service, dict):
                    service_name = service.get("service_name", "")
                elif service:
                    service_name = getattr(service, "service_name", "")
                else:
                    service_name = ""
                    
                if service_name in ("http", "https", "http-proxy"):
                    web_targets.append({"ip": ip, "port": port, "service": service_name})

        if not web_targets:
            return self.log_error(
                state,
                error_type="ValidationError",
                error="No web services found - run scout to discover services",
            )

        target = web_targets[0]
        target_ip = target["ip"]
        target_port = target["port"]
        print(f"\n[Fuzzer] Fuzzing {target_ip}:{target_port}")

        # Step 3: Use Gemini to plan fuzzing
        user_prompt = f"""
Target: {target_ip}:{target_port}
Discovered Services: {discovered_targets}

Respond with exactly one JSON object (no other text) with:
- "paths_to_test": array of paths to fuzz (e.g. ["/admin", "/api", "/login"])
- "fuzz_strategy": one of "quick", "standard", "deep"
- "test_parameters": array of parameters to test (e.g. ["id", "q", "search"])
"""
        try:
            from src.agents.demo import GeminiClient
            plan = await self.llm.ask_json(
                self.system_prompt,
                user_prompt,
            )
            paths_to_test = plan.get("paths_to_test") or ["/admin", "/api", "/login", "/dashboard"]
            if not isinstance(paths_to_test, list):
                paths_to_test = ["/admin", "/api", "/login"]
            fuzz_strategy = plan.get("fuzz_strategy", "standard")
        except Exception as e:
            paths_to_test = ["/admin", "/api", "/login", "/dashboard"]
            fuzz_strategy = "standard"
            print(f"[Fuzzer] LLM parse fallback: {e}")

        # Step 4: Simulate fuzzing results
        # In production: call self.mcp.call_tool("fuzzer", {...})
        simulated_findings = [
            {
                "path": "/admin",
                "method": "GET",
                "status": 200,
                "finding": "Admin panel discovered",
                "severity": "medium"
            },
            {
                "path": "/api/v1/users",
                "method": "GET",
                "status": 200,
                "finding": "API endpoint with potential information disclosure",
                "severity": "low"
            }
        ]

        print(f"[Fuzzer] Found {len(simulated_findings)} potential findings")

        # Step 5: Return state updates
        return {
            "web_findings": simulated_findings,
            **self.log_action(
                state,
                action="web_fuzz",
                target=f"{target_ip}:{target_port}",
                findings={"paths_tested": paths_to_test, "findings_count": len(simulated_findings)},
                reasoning=f"Discovered {len(simulated_findings)} endpoints during fuzzing",
            ),
        }


# Node function for LangGraph integration
async def fuzzer_node(state: CyberState) -> Dict[str, Any]:
    """Fuzzer node for LangGraph workflow."""
    agent = FuzzerAgent()
    return await agent.call_llm(state)
