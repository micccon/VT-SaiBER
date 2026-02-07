"""
Metasploit MCP Client (SSE / Standard MCP)
==========================================
Standalone client for the Metasploit MCP server.
Uses the official Model Context Protocol (SSE) to communicate.
"""

import asyncio
import logging
import os
from contextlib import AsyncExitStack
from typing import Any, Dict, List, Optional, Set

# Official MCP SDK Imports
from mcp import ClientSession
from mcp.client.sse import sse_client

logger = logging.getLogger(__name__)

class MsfMCPClient:
    """
    Client for Metasploit using standard MCP (Server-Sent Events).
    """

    def __init__(self):
        # Default to the docker service name
        self.url = os.getenv("MSF_MCP_URL", "http://msf-mcp:8085").rstrip("/")
        self.name = "Metasploit"
        
        # Connection State
        self.session: Optional[ClientSession] = None
        self.exit_stack: Optional[AsyncExitStack] = None
        self.tools: Set[str] = set()
        
        # Concurrency Lock
        self._lock = asyncio.Lock()

    async def connect(self):
        """Establish the SSE connection to the MCP server."""
        async with self._lock:
            if self.session:
                return

            self.exit_stack = AsyncExitStack()
            
            try:
                logger.info(f"Connecting to {self.name} at {self.url}...")
                
                # 1. Connect via SSE
                transport = await self.exit_stack.enter_async_context(
                    sse_client(f"{self.url}/sse")
                )
                read_stream, write_stream = transport
                
                # 2. Initialize Session
                self.session = await self.exit_stack.enter_async_context(
                    ClientSession(read_stream, write_stream)
                )
                
                # 3. Handshake
                await self.session.initialize()
                
                # 4. Fetch Tools (Validation)
                tools_result = await self.session.list_tools()
                self.tools = {tool.name for tool in tools_result.tools}
                
                logger.info(f"✅ {self.name} Connected! Loaded {len(self.tools)} tools.")
                
            except Exception as e:
                logger.error(f"❌ {self.name} Connection Failed: {e}")
                await self.disconnect()
                raise e

    async def disconnect(self):
        """Cleanly close the connection."""
        if self.exit_stack:
            await self.exit_stack.aclose()
        self.session = None
        self.exit_stack = None

    async def list_tools(self) -> List[str]:
        """Return a list of available tools."""
        if not self.session:
            await self.connect()
        return sorted(list(self.tools))

    async def call(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute an MCP tool.
        """
        if not self.session:
            await self.connect()

        try:
            # MCP SDK Call
            result = await self.session.call_tool(tool, args)
            
            # Parse Result
            if result.content:
                # MCP returns a list of content blocks. We usually want the first text block.
                text_content = result.content[0].text
                
                # Try to parse JSON output if possible (common for MSF tools)
                import json
                try:
                    return json.loads(text_content)
                except json.JSONDecodeError:
                    return {"output": text_content}
            
            return {"output": "No content returned"}

        except Exception as e:
            logger.error(f"Tool execution failed [{tool}]: {e}")
            return {"error": str(e)}

# Singleton Instance
_msf_client = None

async def get_msf_client() -> MsfMCPClient:
    global _msf_client
    if _msf_client is None:
        _msf_client = MsfMCPClient()
        # Lazy connect: we don't await connect() here to let the app start faster
    return _msf_client