"""
Class that will be exposed to mcp for use in our agentic AI system
This class is basically an async wrapper for our synchronous vision.py

This module is responsible for
1. Hosting the methods that will be exposed to our LLM
2. using an event loop so the nmap processes don't overlap
"""

import asyncio
from typing import Optional
from vision_scan_result import VisionScanResult
from vision import VisionNmapScanner

# Intended to be an async wrapper tool for use with mcp
class VisionMcpTool:

    # Initialize mcp tool wrapper
    def __init__(self, timeout: int = 120):
        self.scanner = VisionNmapScanner(timeout=timeout)

    # Core async method, all other methods call this one
    # uses thread asyncio event loop to avoid blocking threads
    async def scan(self, target: str, scan_type: str, *args) -> VisionScanResult:
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            lambda: self.scanner.scan(target, scan_type, *args)
    )
    
# ====================== EXPOSE THESE METHODS TO MCP ==========================

    # performs a ping scan
    async def ping_scan(self, target: str) -> VisionScanResult:
        return await self.scan(target, "ping", "-sn")
    
    # quick scan of top 100 ports
    async def quick_scan(self, target: str) -> VisionScanResult:
        return await self.scan(target, "quick", "-F", "-T4")
    
    # scans ports
    async def port_scan(self, target: str, ports: str) -> VisionScanResult:
        return await self.scan(target, "port", "-p", ports)
    
    # detects service versions and open ports
    async def service_scan(self, target: str, ports: Optional[str] = None) -> VisionScanResult:
        if ports:
            return await self.scan(target, "service", "-sV", "-p", ports)
        return await self.scan(target, "service", "-sV")
    
    # aggressive scan with os detection, version detection, and more
    async def comprehensive_scan(self, target: str) -> VisionScanResult:
        return await self.scan(target, "comprehensive", "-A", "-T4")
    
    # SYN stealth scan (requires admin priviledges)
    async def stealth_scan(self, target: str, ports: Optional[str] = None) -> VisionScanResult:
        if ports:
            return await self.scan(target, "stealth", "-sS", "-p", ports)
        return await self.scan(target, "stealth", "-sS")

# =============================================================================

async def test_mcp_scan():
    scanner = VisionMcpTool(timeout = 60)
    result = await scanner.quick_scan("scanme.nmap.org")
    print(result.to_json())

asyncio.run(test_mcp_scan())
