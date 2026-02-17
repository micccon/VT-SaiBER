"""
Supervisor Agent - Mission Coordinator
======================================
Routes to other specialist agents based on mission state.
Uses Gemini for reasoning and decision making.
"""

import json
from typing import Dict, Any

from src.agents.base import BaseAgent
from src.state.cyber_state import CyberState
from src.state.models import SupervisorDecision


class SupervisorAgent(BaseAgent):
    """Supervisor agent that routes to other agents using Gemini."""

    def __init__(self):
        super().__init__("supervisor", "Mission Coordinator")
        # Import GeminiClient for LLM reasoning
        from src.agents.demo import GeminiClient
        self.llm = GeminiClient()

    @property
    def system_prompt(self) -> str:
        return """You are the supervisor of a security testing team.
        Your job is to:
        1. Review the current mission state
        2. Decide which specialist agent to call next
        3. Explain your reasoning

        Available agents:
        - scout: Discover targets and open ports
        - fuzzer: Find web vulnerabilities
        - striker: Exploit found vulnerabilities
        - librarian: Research techniques and gather intelligence

        Return your decision in JSON format."""

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """Decide next agent based on current state (real LLM call)."""
        context = f"""
Mission Goal: {state.get('mission_goal', 'Unknown')}
Iteration: {state.get('iteration_count', 0)}
Mission Status: {state.get('mission_status', 'active')}

Discovered Targets: {list(state.get('discovered_targets', {}).keys())}
Web Findings count: {len(state.get('web_findings', []))}
Active Sessions: {state.get('active_sessions', {})}

Respond with exactly one JSON object (no other text) with:
- "next_agent": one of "scout", "fuzzer", "striker", "librarian", "end"
- "rationale": short reasoning for this choice
- "specific_goal": one sentence task for the chosen agent (or "N/A" if end)
- "confidence_score": number between 0.0 and 1.0
"""
        try:
            decision = await self.llm.ask_json(
                self.system_prompt,
                context,
                model_class=SupervisorDecision,
            )
            next_agent = decision.next_agent.strip().lower()
            if next_agent not in ("scout", "fuzzer", "striker", "librarian", "end"):
                next_agent = "scout"
            rationale = decision.rationale or "No rationale provided."
        except (json.JSONDecodeError, TypeError, Exception) as e:
            # Fallback routing logic
            targets = state.get("discovered_targets", {})
            if not targets:
                next_agent, rationale = "scout", "No targets yet; starting reconnaissance."
            elif len(state.get("web_findings", [])) == 0:
                next_agent, rationale = "fuzzer", "Targets found; running web fuzzer."
            else:
                next_agent, rationale = "striker", "Web findings present; exploitation phase."
            print(f"[Supervisor] LLM fallback: {e}")

        print(f"\n[Supervisor] Decision: {next_agent}")
        print(f"[Supervisor] Rationale: {rationale}")

        return {
            "next_agent": next_agent,
            "iteration_count": state.get("iteration_count", 0) + 1,
            **self.log_action(
                state,
                action="route_decision",
                decision=next_agent,
                reasoning=rationale,
            ),
        }


# Node function for LangGraph integration
async def supervisor_node(state: CyberState) -> Dict[str, Any]:
    """Supervisor node for LangGraph workflow."""
    agent = SupervisorAgent()
    return await agent.call_llm(state)
