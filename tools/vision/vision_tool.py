"""
Class that will be exposed to mcp for use in our agentic AI system
This class is basically an async wrapper for our synchronous vision.py

This module is responsible for
1. Hosting the methods that will be exposed to our LLM
2. using an event loop so the nmap processes don't overlap
"""

import asyncio
from pathlib import Path
from tools.vision.vision_scan_result import VisionScanResult
from tools.vision.vision_scanner import VisionScanner
from tools.tool_result import ToolResult
from tools.base_tool import BaseTool

class VisionTool(BaseTool):
    """Vision network scanning tool."""
    
    def __init__(self, timeout: int = 120):
        schema_path = Path(__file__).parent.parent.parent / "database" / "avenger_tools" / "vision_tools.json"
        super().__init__(name="vision", schema_path=str(schema_path))
        self._scanner = VisionScanner(timeout=timeout)
    
    async def execute(self, method: str, **params) -> ToolResult:
        """Execute scan method."""
        
        target = params.get("target")
        
        # Build scan configs dynamically to avoid premature params.pop()
        if method == "ping_scan":
            scan_type, args = "ping", ["-sn"]
        elif method == "quick_scan":
            scan_type, args = "quick", ["-F", "-T4"]
        elif method == "port_scan":
            ports = params.get("ports")
            if not ports:
                return VisionScanResult(
                    success=False,
                    tool_name=f"vision.{method}",
                    target=target or "unknown",
                    scan_type="port",
                    hosts=[],
                    error="Missing required parameter: ports"
                )
            scan_type, args = "port", ["-p", ports]
        elif method == "service_scan":
            ports = params.get("ports")
            args = ["-sV"]
            if ports:
                args.extend(["-p", ports])
            scan_type = "service"
        elif method == "comprehensive_scan":
            scan_type, args = "comprehensive", ["-A", "-T4"]
        elif method == "stealth_scan":
            ports = params.get("ports")
            args = ["-sS"]
            if ports:
                args.extend(["-p", ports])
            scan_type = "stealth"
        else:
            return VisionScanResult(
                success=False,
                tool_name=f"vision.{method}",
                target=target or "unknown",
                scan_type="unknown",
                hosts=[],
                error=f"Unknown method: {method}"
            )
        
        if not target:
            return VisionScanResult(
                success=False,
                tool_name=f"vision.{method}",
                target="unknown",
                scan_type=scan_type,
                hosts=[],
                error="Missing required parameter: target"
            )
        
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._scanner.scan,
            target,
            scan_type,
            *args
        )