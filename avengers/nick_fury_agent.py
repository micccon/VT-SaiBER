"""
nick_fury_agent.py - Main Orchestrator
"""

import yaml
from pathlib import Path
from google.adk.agents import Agent
from typing import Dict, Any
from google.adk.tools import ToolContext, BaseTool

def orchestrator_tool_callback(tool: BaseTool, args: Dict[str, Any], tool_context: ToolContext) -> None:
    """Logs which sub-agent the orchestrator is calling."""
    print(f"[{tool_context.agent_name.upper()} LOG] ➡️  Delegating task to agent: {tool.name}")
    print(f"[{tool_context.agent_name.upper()} LOG]   Initial Args: {args}")
    return None

class NickFuryAgent:
    """Main orchestrator that delegates to specialized agents"""
    
    @staticmethod
    def _load_prompts():
        """Load agent instructions from YAML file"""
        prompt_path = Path(__file__).resolve().parents[1] / "database" / "avenger_prompts" / "agent_instructions.yaml"
        if not prompt_path.exists():
            prompt_path = Path.cwd() / "database" / "avenger_prompts" / "agent_instructions.yaml"
        
        with open(prompt_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    
    def __init__(self, sub_agents: list):
        self.sub_agents = {agent.agent.name: agent for agent in sub_agents}
        
        agent_descriptions = "\n".join([
            f"• {name}: {agent.agent.description}"
            for name, agent in self.sub_agents.items()
        ])
        
        agent_list = [agent.agent for agent in sub_agents]
        
        # Load orchestrator instructions from YAML
        prompts = self._load_prompts()
        orchestrator_prompts = prompts["orchestrator_agent"]
        base_instruction = orchestrator_prompts["instruction"]
        
        # Inject agent descriptions into the instruction
        instruction = f"""You are an intelligent orchestrator managing specialized agents.

Available agents:
{agent_descriptions}

{base_instruction}"""
        
        self.agent = Agent(
            name="orchestrator",
            model="gemini-2.5-flash",
            description=orchestrator_prompts["description"],
            instruction=instruction,
            sub_agents=agent_list,
        )

        # Workaround for ADK version where set_callbacks is unavailable
        if hasattr(self.agent, '_llm_agent'):
            self.agent._llm_agent.before_tool_callback = orchestrator_tool_callback
        else:
            self.agent.before_tool_callback = orchestrator_tool_callback