"""
nick_fury_agent.py - Main Orchestrator
"""

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
    
    def __init__(self, sub_agents: list):
        self.sub_agents = {agent.agent.name: agent for agent in sub_agents}
        
        agent_descriptions = "\n".join([
            f"• {name}: {agent.agent.description}"
            for name, agent in self.sub_agents.items()
        ])
        
        agent_list = [agent.agent for agent in sub_agents]
        
        self.agent = Agent(
            name="orchestrator",
            model="gemini-2.5-flash",
            description="Main coordinator that routes tasks to specialized agents",
            instruction=f"""You are an intelligent orchestrator managing specialized agents.

Available agents:
{agent_descriptions}

Your job:
1. Understand user requests
2. Determine which agent(s) can help
3. Delegate tasks to appropriate agents
4. Coordinate multi-agent workflows
5. Synthesize results for the user

Workflow patterns:
• For scanning requests → Use 'scanner' agent
• For vulnerability reports → First scan with 'scanner', then analyze with 'vuln_report'
• For comprehensive assessments → Coordinate both agents

Example workflow:
User: "Scan 192.168.1.1 and create a vulnerability report"
1. Call 'scanner' to perform scans
2. Pass scan results to 'vuln_report' for analysis
3. Return comprehensive report to user

Be helpful, clear, and efficient.""",
            sub_agents=agent_list,
        )

        # Workaround for ADK version where set_callbacks is unavailable
        if hasattr(self.agent, '_llm_agent'):
            self.agent._llm_agent.before_tool_callback = orchestrator_tool_callback
        else:
            self.agent.before_tool_callback = orchestrator_tool_callback