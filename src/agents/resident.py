"""
Resident Agent - Post-Exploitation
==================================
Privilege escalation, persistence, lateral movement.

Updated to use MCP bridge for dynamic tool discovery.
"""

from typing import Dict, Any
from datetime import datetime
from langchain.agents import create_react_agent
from langchain_anthropic import ChatAnthropic

from src.state.cyber_state import CyberState
from src.mcp.mcp_tool_bridge import get_mcp_bridge


# Define which tools Resident is allowed to use
RESIDENT_ALLOWED_TOOLS = {
    "execute_command",
    "upload_file",
    "download_file",
    "list_active_sessions",
}


async def resident_node(state: CyberState) -> Dict[str, Any]:
    """
    Resident agent node for LangGraph.
    
    Performs post-exploitation activities using MCP tools.
    """
    
    # 1. Check if we have active sessions
    if not state.get("active_sessions"):
        return {
            "errors": state.get("errors", []) + [{
                "agent": "resident",
                "error": "No active sessions for post-exploitation",
                "timestamp": datetime.now().isoformat()
            }],
            "iteration_count": state["iteration_count"] + 1
        }
    
    # 2. Get MCP bridge and discover tools
    bridge = await get_mcp_bridge()
    tools = bridge.get_tools_for_agent(RESIDENT_ALLOWED_TOOLS)
    
    # 3. Create ReAct agent with discovered tools
    llm = ChatAnthropic(model="claude-sonnet-4-20250514")
    
    agent = create_react_agent(
        llm,
        tools,
        state_modifier=f"""You are a post-exploitation specialist.

**Mission Goal:** {state['mission_goal']}

**Active Sessions:**
{state.get('active_sessions', {})}

**Your Job:**
- Escalate privileges (if not already root)
- Establish persistence mechanisms
- Gather sensitive information
- Enable lateral movement
- Document all actions

**Available Tools:**
You have {len(tools)} post-exploitation tools available.

Think step-by-step and document your actions."""
    )
    
    # 4. Run the agent
    result = await agent.ainvoke({
        "messages": [("user", """Perform post-exploitation activities.

1. Check current privilege level
2. Escalate to root if needed
3. Establish persistence (cron job, SSH key, etc.)
4. Gather useful information (users, network, processes)
5. Prepare for lateral movement

Document all actions taken.""")]
    })
    
    # 5. Extract results
    final_message = result["messages"][-1].content
    
    # 6. Update CyberState
    return {
        "agent_log": [{
            "agent": "resident",
            "action": "post_exploitation",
            "result": "Completed post-exploitation tasks",
            "timestamp": datetime.now().isoformat()
        }],
        "iteration_count": state["iteration_count"] + 1
    }