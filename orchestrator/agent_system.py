"""
agent_system.py - Multi-Agent System Entry Point
"""

from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner
from google.genai import types

# Import necessary types for event handling
# Assuming the file structure places these in a higher directory
from avengers.vision_agent import VisionAgent
from avengers.vuln_report_agent import VulnReportAgent
from avengers.nick_fury_agent import NickFuryAgent

class AgentSystem:
    """Complete multi-agent system"""
    
    def __init__(self):
        # Initialize specialized agents
        self.scanner = VisionAgent()
        self.vuln_report = VulnReportAgent()
        
        # Initialize orchestrator with sub-agents
        self.orchestrator = NickFuryAgent(
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
        """Execute a query through the orchestrator and log all events."""
        
        final_response_text = "No response"

        # The runner yields an async generator of Event objects
        async for event in self.runner.run_async(
            user_id="user1",
            session_id="sess1",
            new_message=types.Content(role='user', parts=[types.Part(text=query)])
        ):
            if event.content and event.content.parts:
                for part in event.content.parts:
                    
                    # 1. Log Agent/Tool Call Requests (Delegation)
                    if part.function_call:
                        call = part.function_call
                        print(f"[RUNNER EVENT] 📞 AGENT DECISION: Call Agent/Tool '{call.name}'")
                    
                    # 2. Log Agent/Tool Response Results
                    if part.function_response:
                        response = part.function_response
                        result_preview = str(response.response).replace('\n', ' ')[:100] + "..."
                        print(f"[RUNNER EVENT] ✅ TOOL RESULT: Received response from '{response.name}'. Result preview: {result_preview}")
                        
                    # 3. Capture the Final Response (from the Orchestrator)
                    if event.is_final_response() and part.text:
                        final_response_text = part.text
        
        return final_response_text