"""
Librarian Agent - Research and Intelligence
===========================================
Gathers research, techniques, and intelligence for the mission.
Uses BaseAgent pattern for reasoning.
"""

import json
from typing import Dict, Any

from src.agents.base import BaseAgent
from src.state.cyber_state import CyberState


class LibrarianAgent(BaseAgent):
    """Research and intelligence specialist agent."""

    def __init__(self):
        super().__init__("librarian", "Research and Intelligence Specialist")
        # Import GeminiClient for LLM reasoning
        from src.agents.demo import GeminiClient
        self.llm = GeminiClient()

    @property
    def system_prompt(self) -> str:
        return """You are a research and intelligence specialist. Your goal is to:
        1. Research vulnerabilities and exploitation techniques
        2. Gather relevant CVEs and security advisories
        3. Find applicable proof-of-concept code
        4. Compile relevant documentation
        5. Return findings in a structured JSON format

        Be thorough and focus on actionable intelligence for the mission."""

    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """
        Main reasoning loop for the Librarian agent.

        Flow:
        1. Get mission context and discovered information
        2. Identify research needs
        3. Use Gemini to research relevant techniques
        4. Cache findings in research_cache
        5. Return validated state updates
        """
        # Step 1: Get mission context
        mission_goal = state.get("mission_goal", "")
        discovered_targets = state.get("discovered_targets", {})
        web_findings = state.get("web_findings", [])

        print(f"\n[Librarian] Researching for mission: {mission_goal}")

        # Step 2: Determine research focus
        if web_findings:
            # Research the most recent finding
            latest_finding = web_findings[0]
            research_topic = f"{latest_finding.get('finding', 'vulnerability research')}"
        elif discovered_targets:
            # Research discovered services
            target_ip = list(discovered_targets.keys())[0]
            target_data = discovered_targets[target_ip]
            services = target_data.get("services", {})
            research_topic = f"{target_ip} services: {list(services.keys())}"
        else:
            research_topic = "general vulnerability research"

        # Step 3: Use Gemini to research
        user_prompt = f"""
Mission Goal: {mission_goal}
Research Topic: {research_topic}

Respond with exactly one JSON object (no other text) with:
- "cve_ids": array of relevant CVE IDs (e.g. ["CVE-2024-1234"])
- "technique": name of exploitation technique
- "references": array of reference URLs
- "mitigation": array of mitigation steps
- "relevance_score": number between 0.0 and 1.0 indicating how relevant this is to the mission
"""
        try:
            research = await self.llm.ask_json(
                self.system_prompt,
                user_prompt,
            )
            cve_ids = research.get("cve_ids", [])
            technique = research.get("technique", "N/A")
            references = research.get("references", [])
            mitigation = research.get("mitigation", [])
            relevance_score = research.get("relevance_score", 0.5)
        except Exception as e:
            cve_ids = []
            technique = "N/A"
            references = []
            mitigation = []
            relevance_score = 0.5
            print(f"[Librarian] LLM parse fallback: {e}")

        # Step 4: Compile research findings
        research_findings = {
            "topic": research_topic,
            "cve_ids": cve_ids,
            "technique": technique,
            "references": references,
            "mitigation": mitigation,
            "relevance_score": relevance_score,
        }

        print(f"[Librarian] Research complete: {len(references)} references found")

        # Step 5: Update research cache
        existing_cache = state.get("research_cache", {})
        cache_key = research_topic.lower().replace(" ", "_")[:50]
        
        # Step 6: Return state updates
        return {
            "research_cache": {
                **existing_cache,
                cache_key: research_findings,
            },
            "osint_findings": [
                *state.get("osint_findings", []),
                {
                    "type": "research",
                    "topic": research_topic,
                    "findings": research_findings,
                }
            ],
            **self.log_action(
                state,
                action="research",
                findings=research_findings,
                reasoning=f"Compiled {len(references)} references for {research_topic}",
            ),
        }


# Node function for LangGraph integration
async def librarian_node(state: CyberState) -> Dict[str, Any]:
    """Librarian node for LangGraph workflow."""
    agent = LibrarianAgent()
    return await agent.call_llm(state)
