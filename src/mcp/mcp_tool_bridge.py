"""
MCP to LangGraph Bridge
=======================
Connects to MCP servers via SSE and exposes tools to LangGraph agents.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional, Set
from contextlib import AsyncExitStack

from mcp import ClientSession
from mcp.client.sse import sse_client
from langchain_core.tools import StructuredTool
from pydantic import Field, create_model

logger = logging.getLogger(__name__)


class MCPToolBridge:
    """
    Bridge between MCP servers and LangGraph agents.
    Connects via SSE and discovers tools dynamically.
    """
    
    def __init__(self):
        self.sessions: Dict[str, ClientSession] = {}
        self.exit_stack = AsyncExitStack()
        self.all_tools: List[StructuredTool] = []
        self.tools_by_server: Dict[str, List[StructuredTool]] = {}
    
    async def connect_server(self, name: str, url: str):
        """
        Connect to an MCP server via SSE and discover its tools.
        
        Args:
            name: Server name (e.g., "kali", "msf")
            url: Server URL (e.g., "http://kali-mcp:5001")
        """
        try:
            logger.info(f"Connecting to {name} MCP at {url}...")
            
            # Connect via SSE
            transport = await self.exit_stack.enter_async_context(
                sse_client(f"{url}/sse")
            )
            read, write = transport
            
            # Create session
            session = await self.exit_stack.enter_async_context(
                ClientSession(read, write)
            )
            await session.initialize()
            
            # Store session
            self.sessions[name] = session
            
            # Discover tools
            tools_result = await session.list_tools()
            
            logger.info(f"✅ {name}: Discovered {len(tools_result.tools)} tools")
            
            # Convert MCP tools to LangChain tools
            for mcp_tool in tools_result.tools:
                lc_tool = self._mcp_to_langchain(mcp_tool, name, session)
                self.all_tools.append(lc_tool)
                
                if name not in self.tools_by_server:
                    self.tools_by_server[name] = []
                self.tools_by_server[name].append(lc_tool)
            
            # Log discovered tools
            for tool in tools_result.tools:
                logger.debug(f"  - {tool.name}: {tool.description}")
            
            logger.info(f"✅ {name}: Connected successfully")
            
        except Exception as e:
            logger.error(f"Failed to connect to {name}: {e}")
            raise
    
    def _mcp_to_langchain(
        self, 
        mcp_tool, 
        server_name: str,
        session: ClientSession
    ) -> StructuredTool:
        """Convert MCP tool to LangChain StructuredTool."""
        
        input_schema = mcp_tool.inputSchema
        
        # Build fields for Pydantic model
        fields = {}
        required = input_schema.get("required", [])
        
        for prop_name, prop_schema in input_schema.get("properties", {}).items():
            field_type = self._json_type_to_python(prop_schema.get("type", "string"))
            field_required = prop_name in required
            field_description = prop_schema.get("description", "")
            
            if field_required:
                fields[prop_name] = (field_type, Field(description=field_description))
            else:
                fields[prop_name] = (Optional[field_type], Field(default=None, description=field_description))
        
        # Create dynamic Pydantic model
        from pydantic import BaseModel
        if fields:
            ArgsSchema = create_model(f"{mcp_tool.name}_args", **fields)
        else:
            ArgsSchema = create_model(f"{mcp_tool.name}_args", __base__=BaseModel)
        
        # Create execution function
        async def execute_tool(**kwargs) -> str:
            """Execute the MCP tool via SSE and return results."""
            try:
                logger.info(f"[{server_name}] Executing {mcp_tool.name} with args: {kwargs}")
                
                # Call MCP tool
                result = await session.call_tool(mcp_tool.name, kwargs)
                
                # Extract content
                if result.content:
                    content = result.content[0].text
                    
                    # Try to parse as JSON for cleaner output
                    try:
                        parsed = json.loads(content)
                        return json.dumps(parsed, indent=2)
                    except:
                        return content
                
                return "No output from tool"
                
            except Exception as e:
                logger.error(f"[{server_name}] Tool execution failed: {e}")
                return json.dumps({
                    "error": str(e),
                    "server": server_name,
                    "tool": mcp_tool.name
                })
        
        # Create LangChain tool with server prefix
        tool_name = f"{server_name}_{mcp_tool.name}"
        
        return StructuredTool(
            name=tool_name,
            description=f"[{server_name.upper()}] {mcp_tool.description}",
            func=execute_tool,
            coroutine=execute_tool,
            args_schema=ArgsSchema
        )
    
    def _json_type_to_python(self, json_type: str) -> type:
        """Convert JSON Schema type to Python type."""
        type_map = {
            "string": str,
            "integer": int,
            "number": float,
            "boolean": bool,
            "object": dict,
            "array": list
        }
        return type_map.get(json_type, str)
    
    def get_tools_for_agent(self, allowed_tools: Optional[Set[str]] = None) -> List[StructuredTool]:
        """
        Get tools filtered for a specific agent.
        
        Args:
            allowed_tools: Set of tool names agent is allowed to use.
                          If None, returns all tools.
        
        Returns:
            List of tools agent can use
        """
        if allowed_tools is None:
            return self.all_tools
        
        # Filter tools
        filtered = []
        for tool in self.all_tools:
            # Extract base tool name (remove server prefix)
            base_name = tool.name.split("_", 1)[1] if "_" in tool.name else tool.name
            
            if base_name in allowed_tools or tool.name in allowed_tools:
                filtered.append(tool)
        
        logger.info(f"Filtered {len(filtered)}/{len(self.all_tools)} tools for agent")
        return filtered
    
    async def disconnect(self):
        """Disconnect from all MCP servers."""
        await self.exit_stack.aclose()
        logger.info("Disconnected from all MCP servers")


# Global bridge instance
_bridge = None

async def get_mcp_bridge() -> MCPToolBridge:
    """Get or create the global MCP bridge."""
    global _bridge
    if _bridge is None:
        _bridge = MCPToolBridge()
        
        # Get URLs from environment
        kali_url = os.getenv("KALI_MCP_URL")  # Port 5000 for MCP bridge
        msf_url = os.getenv("MSF_MCP_URL")
        
        # Connect to both servers via SSE
        await _bridge.connect_server("kali", kali_url)
        await _bridge.connect_server("msf", msf_url)
    
    return _bridge