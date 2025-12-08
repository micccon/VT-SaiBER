"""
orchestrator_agent.py - Multi-Agent Orchestration System
Google ADK pattern for modular agent architecture
"""

import os
import yaml
from pathlib import Path
from google.adk.agents import Agent
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import SseConnectionParams

# Config
os.environ["GOOGLE_API_KEY"] = "YOUR API KEY"
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"


class VisionAgent:
    """Network security scanner with nmap tools"""
    
    @staticmethod
    def _load_prompts():
        """Load agent instructions from YAML file"""
        prompt_path = Path(__file__).resolve().parents[1] / "database" / "avenger_prompts" / "agent_instructions.yaml"
        if not prompt_path.exists():
            prompt_path = Path.cwd() / "database" / "avenger_prompts" / "agent_instructions.yaml"
        
        with open(prompt_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    
    def __init__(self, mcp_url: str = "http://localhost:8000/sse"):
        prompts = self._load_prompts()
        vision_prompts = prompts["vision_agent"]
        
        self.agent = Agent(
            name="scanner",
            model="gemini-2.5-flash",
            description=vision_prompts["description"],
            instruction=vision_prompts["instruction"],
            tools=[McpToolset(connection_params=SseConnectionParams(url=mcp_url))],
        )
