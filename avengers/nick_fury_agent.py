"""
orchestrator_agent.py - Main Orchestrator
"""

import yaml
from pathlib import Path
from google.adk.agents import Agent


class OrchestratorAgent:
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
        # Store sub-agents for reference
        self.sub_agents = {agent.agent.name: agent for agent in sub_agents}
        
        # Build agent descriptions for orchestrator
        agent_descriptions = "\n".join([
            f"• {name}: {agent.agent.description}"
            for name, agent in self.sub_agents.items()
        ])
        
        # Extract just the Agent objects (not the wrapper classes)
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
            sub_agents=agent_list,  # Use sub_agents parameter, not tools!
        )
    
    def get_agent_registry(self) -> dict:
        """
        Extract agent registry metadata for Tony Stark prompt engineering.
        Returns structured information about available agents and their capabilities.
        """
        registry = {}
        
        for agent_name, agent_wrapper in self.sub_agents.items():
            agent_obj = agent_wrapper.agent
            
            # Build capabilities list from agent description and tools
            capabilities = []
            
            # Extract tool capabilities if available
            if hasattr(agent_obj, 'tools') and agent_obj.tools:
                for tool in agent_obj.tools:
                    # MCP toolset capabilities
                    if hasattr(tool, 'get_tools'):
                        try:
                            mcp_tools = tool.get_tools()
                            for mcp_tool in mcp_tools:
                                capabilities.append({
                                    "action": mcp_tool.name if hasattr(mcp_tool, 'name') else str(mcp_tool),
                                    "description": mcp_tool.description if hasattr(mcp_tool, 'description') else "",
                                    "parameters": mcp_tool.input_schema if hasattr(mcp_tool, 'input_schema') else {}
                                })
                        except:
                            # If tool inspection fails, add generic entry
                            capabilities.append({
                                "action": agent_name + "_action",
                                "description": f"Tools available via {type(tool).__name__}",
                                "parameters": {}
                            })
            
            # If no tools found, infer from agent type
            if not capabilities:
                if "scanner" in agent_name or "vision" in agent_name.lower():
                    capabilities = [
                        {"action": "ping_scan", "description": "Quick host discovery", "parameters": {"targets": "list"}},
                        {"action": "quick_scan", "description": "Top 100 ports scan", "parameters": {"targets": "list"}},
                        {"action": "port_scan", "description": "Specific port scanning", "parameters": {"targets": "list", "ports": "string"}},
                        {"action": "service_scan", "description": "Service version detection", "parameters": {"targets": "list", "ports": "optional"}},
                        {"action": "os_scan", "description": "OS fingerprinting", "parameters": {"targets": "list"}},
                        {"action": "stealth_scan", "description": "SYN stealth scan", "parameters": {"targets": "list", "ports": "string"}},
                        {"action": "comprehensive_scan", "description": "Full security assessment", "parameters": {"targets": "list"}}
                    ]
                elif "vuln" in agent_name or "report" in agent_name:
                    capabilities = [
                        {"action": "generate_report", "description": "Create vulnerability assessment report", "parameters": {"scan_data": "object"}},
                        {"action": "analyze_vulnerabilities", "description": "Identify and prioritize vulnerabilities", "parameters": {"findings": "list"}}
                    ]
            
            registry[agent_name] = {
                "description": agent_obj.description if hasattr(agent_obj, 'description') else f"Agent: {agent_name}",
                "model": agent_obj.model if hasattr(agent_obj, 'model') else "unknown",
                "capabilities": capabilities
            }
        
        return registry