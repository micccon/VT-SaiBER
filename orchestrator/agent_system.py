"""
main.py - Multi-Agent System Entry Point
"""

import os
import asyncio
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner
from google.genai import types

from avengers.vision_agent import VisionAgent
from avengers.vuln_report_agent import VulnReportAgent
from avengers.nick_fury_agent import OrchestratorAgent

# Config
os.environ["GOOGLE_API_KEY"] = "YOUR API KEY"
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"


class AgentSystem:
    """Complete multi-agent system"""
    
    def __init__(self):
        # Initialize specialized agents
        self.scanner = VisionAgent()
        self.vuln_report = VulnReportAgent()
        
        # Initialize orchestrator with sub-agents
        self.orchestrator = OrchestratorAgent(
            sub_agents=[self.scanner, self.vuln_report]
        )
        
        # Setup session management
        self.session_service = InMemorySessionService()
        self.runner = None
    
    async def initialize(self):
        """Setup session and runner"""
        await self.session_service.create_session(
            app_name="agents",
            user_id="user1", 
            session_id="sess1"
        )
        self.runner = Runner(
            agent=self.orchestrator.agent,
            app_name="agents",
            session_service=self.session_service
        )
    
    async def run_query(self, query: str) -> str:
        """Execute a query through the orchestrator"""
        async for event in self.runner.run_async(
            user_id="user1",
            session_id="sess1",
            new_message=types.Content(role='user', parts=[types.Part(text=query)])
        ):
            if event.is_final_response():
                return event.content.parts[0].text if event.content else "No response"
        return "No response"