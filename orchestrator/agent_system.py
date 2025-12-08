"""
agent_system.py - Multi-Agent System Entry Point
"""

import os
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner
from google.genai import types

# Import necessary types for event handling
# Assuming the file structure places these in a higher directory
from avengers.vision_agent import VisionAgent
from avengers.vuln_report_agent import VulnReportAgent
from avengers.nick_fury_agent import NickFuryAgent
from interaction.api.thanos import process_user_input
from orchestrator.tony_stark import StarkPromptEngine
from utils.DrStrange import AgentLogger

# Config
os.environ["GOOGLE_API_KEY"] = "YOUR API KEY"
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"


class AgentSystem:
    """Complete multi-agent system"""
    
    def __init__(self):
        # Initialize agent logger
        self.logger = AgentLogger()
        
        # Initialize prompt engineer
        self.prompt_builder = StarkPromptEngine()
        
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
        self.logger._log_system("AgentSystem initialized", {"session": "sess1"})
    
    async def run_query(self, query: str) -> str:
        """
        Execute a query through the orchestrator with sanitization and prompt engineering
        
        Workflow:
        1. Log user query
        2. Sanitize and validate input (Thanos)
        3. Build optimized prompt (Tony Stark)
        4. Execute through orchestrator
        5. Log and return response
        """
        # Log original user query
        self.logger.log_user_query(query)
        
        try:
            # Step 1: Sanitize and validate input
            sanitized = process_user_input(query, output_context="dict")
            
            # Check for validation errors
            if sanitized.get("validation_errors"):
                error_msg = f"Input validation failed: {', '.join(sanitized['validation_errors'])}"
                self.logger.log_error(error_msg, {"raw_input": query})
                return error_msg
            
            # Log sanitization results
            self.logger._log_system("Input sanitized", {
                "action": sanitized.get("action"),
                "targets": sanitized.get("targets"),
                "ports": sanitized.get("ports")
            })
            
            # Step 2: Build optimized prompt using Tony Stark
            # ✋ FIX: Get real agent registry from orchestrator
            agent_registry = self.orchestrator.get_agent_registry()
            enhanced_prompt = self.prompt_builder.build_prompt(
                user_query=sanitized,
                agent_registry=agent_registry
            )
            
            self.logger._log_system("Prompt generated", {
                "action": sanitized.get("action"),
                "prompt_length": len(enhanced_prompt)
            })
            
            # Step 3: Execute through orchestrator with enhanced prompt
            final_response_text = None
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
        except Exception as e:
            self.logger.log_error(f"Query execution failed: {str(e)}", {"query": query})
            raise