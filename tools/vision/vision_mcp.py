"""
Vision MCP Client - Connects to the Vision MCP Server

This module provides a client for the Vision Network Scanning MCP server.
It handles the MCP protocol communication and converts responses to VisionScanResult objects.
"""

import asyncio
import json
import uuid
from typing import Dict, Any, Optional, List
import httpx
from tools.vision.vision_scan_result import VisionScanResult


class VisionMcpTool:
    """
    MCP client for Vision network scanning tools.
    
    Connects to the Vision MCP server via HTTP/SSE transport and provides
    async methods for all scanning operations.
    """
    
    def __init__(self, timeout: int = 120, server_url: str = "http://localhost:8000"):
        """
        Initialize the MCP client.
        
        Args:
            timeout: Maximum time (seconds) for each scan operation
            server_url: Base URL of the MCP server
        """
        self.timeout = timeout
        self.server_url = server_url.rstrip('/')
        self.session = None
        self._available_tools = None
        
    async def _ensure_session(self):
        """Ensure we have an HTTP session."""
        if self.session is None:
            self.session = httpx.AsyncClient(timeout=self.timeout)
    
    async def _call_tool(self, tool_name: str, **kwargs) -> VisionScanResult:
        """
        Call an MCP tool and convert the response to VisionScanResult.
        
        Args:
            tool_name: Name of the tool to call
            **kwargs: Tool parameters
            
        Returns:
            VisionScanResult object
        """
        await self._ensure_session()
        
        try:
            # Call the MCP tool via HTTP POST
            response = await self.session.post(
                f"{self.server_url}/tools/{tool_name}",
                json=kwargs,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            
            result_data = response.json()
            
            # Convert MCP response to VisionScanResult
            return VisionScanResult(
                success=result_data.get("success", False),
                tool_name=result_data.get("tool_name", "nmap"),
                target=result_data.get("target", kwargs.get("target", "")),
                scan_type=result_data.get("scan_type", tool_name),
                hosts=result_data.get("hosts", []),
                command=result_data.get("command"),
                duration=result_data.get("duration"),
                error=result_data.get("error") if not result_data.get("success") else None
            )
            
        except httpx.TimeoutException:
            return VisionScanResult(
                success=False,
                tool_name="nmap",
                target=kwargs.get("target", ""),
                scan_type=tool_name,
                hosts=[],
                error=f"Request timed out after {self.timeout} seconds"
            )
        except httpx.HTTPStatusError as e:
            return VisionScanResult(
                success=False,
                tool_name="nmap",
                target=kwargs.get("target", ""),
                scan_type=tool_name,
                hosts=[],
                error=f"HTTP {e.response.status_code}: {e.response.text}"
            )
        except Exception as e:
            return VisionScanResult(
                success=False,
                tool_name="nmap",
                target=kwargs.get("target", ""),
                scan_type=tool_name,
                hosts=[],
                error=f"MCP client error: {str(e)}"
            )
    
    async def ping_scan(self, target: str) -> VisionScanResult:
        """
        Perform host discovery without port scanning.
        
        Args:
            target: IP address, hostname, or CIDR range
            
        Returns:
            VisionScanResult with host discovery results
        """
        return await self._call_tool("ping_scan", target=target)
    
    async def quick_scan(self, target: str) -> VisionScanResult:
        """
        Fast scan of top 100 most common ports.
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            VisionScanResult with port scan results
        """
        return await self._call_tool("quick_scan", target=target)
    
    async def port_scan(self, target: str, ports: str) -> VisionScanResult:
        """
        Scan specific ports or port ranges.
        
        Args:
            target: IP address or hostname to scan
            ports: Port specification (e.g., "22,80,443" or "1-1000")
            
        Returns:
            VisionScanResult with port scan results
        """
        return await self._call_tool("port_scan", target=target, ports=ports)
    
    async def service_scan(self, target: str, ports: Optional[str] = None) -> VisionScanResult:
        """
        Detect service versions on open ports.
        
        Args:
            target: IP address or hostname to scan
            ports: Optional port specification to limit scanning
            
        Returns:
            VisionScanResult with service detection results
        """
        kwargs = {"target": target}
        if ports:
            kwargs["ports"] = ports
        return await self._call_tool("service_scan", **kwargs)
    
    async def comprehensive_scan(self, target: str) -> VisionScanResult:
        """
        Perform comprehensive scan with OS detection, version detection, 
        script scanning, and traceroute.
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            VisionScanResult with comprehensive scan results
        """
        return await self._call_tool("comprehensive_scan", target=target)
    
    async def stealth_scan(self, target: str, ports: Optional[str] = None) -> VisionScanResult:
        """
        Perform stealth SYN scan (requires root privileges).
        
        Args:
            target: IP address or hostname to scan
            ports: Optional port specification
            
        Returns:
            VisionScanResult with stealth scan results
        """
        kwargs = {"target": target}
        if ports:
            kwargs["ports"] = ports
        return await self._call_tool("stealth_scan", **kwargs)
    
    async def udp_scan(self, target: str, ports: Optional[str] = None) -> VisionScanResult:
        """
        Scan UDP ports.
        
        Args:
            target: IP address or hostname to scan
            ports: Optional port specification
            
        Returns:
            VisionScanResult with UDP scan results
        """
        kwargs = {"target": target}
        if ports:
            kwargs["ports"] = ports
        return await self._call_tool("udp_scan", **kwargs)
    
    async def full_tcp_scan(self, target: str) -> VisionScanResult:
        """
        Scan all 65,535 TCP ports.
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            VisionScanResult with full TCP scan results
        """
        return await self._call_tool("full_tcp_scan", target=target)
    
    async def os_scan(self, target: str) -> VisionScanResult:
        """
        Detect operating system using TCP/IP fingerprinting.
        
        Args:
            target: IP address or hostname to scan
            
        Returns:
            VisionScanResult with OS detection results
        """
        return await self._call_tool("os_scan", target=target)
    
    async def script_scan(self, target: str, script: str = "default") -> VisionScanResult:
        """
        Run Nmap Scripting Engine scripts.
        
        Args:
            target: IP address or hostname to scan
            script: NSE script or category to run
            
        Returns:
            VisionScanResult with script scan results
        """
        return await self._call_tool("script_scan", target=target, script=script)
    
    async def close(self):
        """Close the HTTP session."""
        if self.session:
            await self.session.aclose()
            self.session = None
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
