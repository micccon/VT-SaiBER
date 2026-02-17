"""
Striker Agent - Exploitation Specialist
======================================
Exploits found vulnerabilities to gain access.
Uses BaseAgent pattern with MCP bridge for tool discovery.
"""

import json
from typing import Dict, Any
from datetime import datetime

from src.agents.base import BaseAgent
from src.state.cyber_state import CyberState


class StrikerAgent(BaseAgent):
    """Exploitation specialist agent."""

    def __init__(self):
        super().__init__("striker", "Exploitation Specialist")
        # Import GeminiClient for LLM reasoning
        from src.agents.demo import GeminiClient
        self.llm = GeminiClient()

    @property
    def system_prompt(self) -> str:
        return """You are an exploitation specialist. Your goal is to:
        1. Analyze web findings and vulnerabilities
        2. Select appropriate exploits for target systems
        3. Execute exploits to gain access
        4. Document successful exploitation
        5. Report findings in a structured JSON format

        Be careful and ethical. Only target systems in scope."""

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """
        Main reasoning loop for the Striker agent.

        Flow:
        1. Get web findings from state
        2. Analyze vulnerabilities
        3. Use Gemini to plan exploitation strategy
        4. Execute exploits (in production, would use MCP tools)
        5. Return validated state updates
        """
        # Step 1: Get web findings and discovered targets
        web_findings = state.get("web_findings", [])
        discovered_targets = state.get("discovered_targets", {})

        if not web_findings:
            return self.log_error(
                state,
                error_type="ValidationError",
                error="No web findings - run fuzzer first",
            )

        if not discovered_targets:
            return self.log_error(
                state,
                error_type="ValidationError",
                error="No discovered targets - run scout first",
            )

        # Get primary target
        target_ip = list(discovered_targets.keys())[0]
        target_data = discovered_targets[target_ip]

        print(f"\n[Striker] Analyzing {len(web_findings)} findings for {target_ip}")

        # Step 2: Use Gemini to plan exploitation
        user_prompt = """
Web Findings:
{}

Target: {}

Respond with exactly one JSON object (no other text) with:
- "exploit_to_run": name of exploit to attempt
- "target_param": parameter to target
- "expected_impact": description of expected impact
- "confidence": number between 0.0 and 1.0
""".format(json.dumps(web_findings), target_ip)

        try:
            plan = await self.llm.ask_json(
                self.system_prompt,
                user_prompt,
            )
            exploit_to_run = plan.get("exploit_to_run", "none")
            target_param = plan.get("target_param", "id")
            expected_impact = plan.get("expected_impact", "Unknown")
            confidence = plan.get("confidence", 0.5)
        except Exception as e:
            exploit_to_run = "none"
            target_param = "id"
            expected_impact = "Unknown"
            confidence = 0.5
            print(f"[Striker] LLM parse fallback: {e}")

        # Step 3: Simulate exploitation
        # In production: call self.mcp.call_tool("exploit", {...})
        simulated_exploit = {
            "exploit": exploit_to_run,
            "target": target_ip,
            "status": "success",
            "session_token": "simulated_session_12345",
            "access_level": "user",
            "impact": expected_impact,
        }

        print(f"[Striker] Exploitation {'successful' if simulated_exploit['status'] == 'success' else 'failed'}")

        # Step 4: Update active sessions if exploitation succeeded
        state_updates = {}
        if simulated_exploit["status"] == "success":
            state_updates["active_sessions"] = {
                **state.get("active_sessions", {}),
                target_ip: {
                    "session_token": simulated_exploit["session_token"],
                    "access_level": simulated_exploit["access_level"],
                    "created_at": datetime.now().isoformat(),
                }
            }
            state_updates["exploited_services"] = [
                *state.get("exploited_services", []),
                {
                    "target": target_ip,
                    "exploit": exploit_to_run,
                    "timestamp": datetime.now().isoformat(),
                }
            ]

        # Step 5: Return state updates
        return {
            **state_updates,
            **self.log_action(
                state,
                action="exploitation",
                target=target_ip,
                findings=simulated_exploit,
                reasoning=f"Exploitation {simulated_exploit['status']}: {expected_impact}",
            ),
        }


# Node function for LangGraph integration
async def striker_node(state: CyberState) -> Dict[str, Any]:
    """Striker node for LangGraph workflow."""
    agent = StrikerAgent()
    return await agent.call_llm(state)
