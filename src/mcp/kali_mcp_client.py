"""
Kali MCP Client (REST)
======================
Standalone client for the Kali Linux MCP server.
Communicates via standard HTTP REST API (POST/GET).
"""

import os
import httpx
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

class KaliMCPClient:
    """
    Client for Kali Linux security tools via REST API.
    """
    
    def __init__(self):
        # Default to the docker service name and port 5000
        self.url = os.getenv("KALI_MCP_URL", "http://kali-mcp:5000").rstrip("/")
        self.name = "Kali"
        
        # Tools supported by the REST API (derived from documentation)
        self.tools = {
            "nmap", 
            "gobuster", 
            "nikto", 
            "dirb", 
            "sqlmap", 
            "wpscan",
            "hydra",
            "john",
            "enum4linux",
            "metasploit", # The REST API calls this 'metasploit', acts as a wrapper
            "execute_command"
        }
        
        # Async HTTP Client
        self.http_client = httpx.AsyncClient(timeout=300.0) # 5 min timeout for long scans
    
    async def connect(self):
        """
        Check connection to the REST API.
        """
        try:
            logger.info(f"Connecting to {self.name} at {self.url}...")
            
            # Endpoint: /health
            resp = await self.http_client.get(f"{self.url}/health")
            
            if resp.status_code == 200:
                logger.info(f"✅ {self.name} REST API Connected")
            else:
                raise ConnectionError(f"Health check failed: {resp.status_code}")
                
        except Exception as e:
            logger.error(f"❌ {self.name} Connection Failed: {e}")
            raise e

    async def disconnect(self):
        """Close the HTTP client resource."""
        await self.http_client.aclose()

    async def list_tools(self) -> List[str]:
        """Return the list of supported tools."""
        return sorted(list(self.tools))

    async def call(self, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a tool via HTTP POST request.
        """
        # Validate tool existence
        if tool not in self.tools:
             return {"error": f"Tool '{tool}' not supported by client."}

        # ROUTING LOGIC (Based on your provided docs)
        if tool == "execute_command":
            # Generic command execution
            endpoint = f"{self.url}/api/command"
            # Ensure args has 'command' key
            if "command" not in args and "cmd" in args:
                args["command"] = args.pop("cmd")
        else:
            # Specific tools
            endpoint = f"{self.url}/api/tools/{tool}"

        try:
            # Send the arguments as JSON body
            response = await self.http_client.post(endpoint, json=args)
            
            if response.status_code == 200:
                try:
                    return response.json()
                except:
                    return {"output": response.text}
            else:
                return {
                    "error": f"HTTP {response.status_code}", 
                    "details": response.text
                }
                
        except Exception as e:
            logger.error(f"{self.name} call failed: {e}")
            return {"error": str(e)}

# Singleton Instance
_kali_client = None

async def get_kali_client() -> KaliMCPClient:
    global _kali_client
    if _kali_client is None:
        _kali_client = KaliMCPClient()
    return _kali_client