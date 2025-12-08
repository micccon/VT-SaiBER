"""
vision_agent.py - Network security scanner
"""

from google.adk.agents import Agent
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import SseConnectionParams
from typing import Dict, Any
from google.adk.tools import ToolContext

def scanner_tool_callback(tool, args: Dict[str, Any], tool_context: ToolContext) -> None:
    """Logs the details of the nmap tool being executed."""
    print(f"[{tool_context.agent_name.upper()} LOG] 🛠️  Executing NMAP tool: {tool.name}")
    print(f"[{tool_context.agent_name.upper()} LOG]   Args: {args}")
    return None

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
        
        # Workaround for ADK version where set_callbacks is unavailable
        if hasattr(self.agent, '_llm_agent'):
            self.agent._llm_agent.before_tool_callback = scanner_tool_callback
        else:
            self.agent.before_tool_callback = scanner_tool_callback