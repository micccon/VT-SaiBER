"""
orchestrator_agent.py - Multi-Agent Orchestration System
Google ADK pattern for modular agent architecture
"""

import os
from google.adk.agents import Agent
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import SseConnectionParams

# Config
os.environ["GOOGLE_API_KEY"] = "YOUR API KEY"
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"


class VisionAgent:
    """Network security scanner with nmap tools"""
    
    def __init__(self, mcp_url: str = "http://localhost:8000/sse"):
        self.agent = Agent(
            name="scanner",
            model="gemini-2.5-flash",
            description="Network security scanner with nmap capabilities. Performs port scans, service detection, OS fingerprinting, and vulnerability assessment.",
            instruction="""You are an expert network security analyst with nmap tools.

Available scans:
• ping_scan - Quick host discovery
• quick_scan - Top 100 ports  
• port_scan - Specific ports
• service_scan - Service versions
• os_scan - OS detection
• script_scan - NSE scripts
• stealth_scan - SYN scan (needs root)
• comprehensive_scan - Full assessment (very noisy!)

Always explain scans before running. Warn about detection. Format results clearly.""",
            tools=[McpToolset(connection_params=SseConnectionParams(url=mcp_url))],
        )
