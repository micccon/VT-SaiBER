import os
import yaml
from pathlib import Path
from google.adk.agents import Agent
from google.adk.tools import ToolContext
from typing import Dict, Any

def vuln_report_callback(tool, args: Dict[str, Any], tool_context: ToolContext) -> None:
    """Logs the details of the nmap tool being executed."""
    print(f"[{tool_context.agent_name.upper()} LOG] 📝  Writing Vulnerability Report: {tool.name}")
    print(f"[{tool_context.agent_name.upper()} LOG]   Args: {args}")
    return None

class VulnReportAgent:
    """Vulnerability assessment report generator"""
    
    @staticmethod
    def _load_prompts():
        """Load agent instructions from YAML file"""
        prompt_path = Path(__file__).resolve().parents[1] / "database" / "avenger_prompts" / "agent_instructions.yaml"
        if not prompt_path.exists():
            prompt_path = Path.cwd() / "database" / "avenger_prompts" / "agent_instructions.yaml"
        
        with open(prompt_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    
    def __init__(self):
        prompts = self._load_prompts()
        vuln_prompts = prompts["vuln_report_agent"]
        
        self.agent = Agent(
            name="vuln_report",
            model="gemini-2.5-flash",
            description=vuln_prompts["description"],
            instruction=vuln_prompts["instruction"],
            tools=[],  # Report agent doesn't need external tools
        )

        if hasattr(self.agent, '_llm_agent'):
            self.agent._llm_agent.before_tool_callback = vuln_report_callback
        else:
            self.agent.before_tool_callback = vuln_report_callback