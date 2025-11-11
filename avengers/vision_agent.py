"""
VisionAgent - Network reconnaissance agent using Nmap

This agent executes network scanning tasks using the VisionMcpTool.
It implements the BaseAvenger interface to work with the orchestrator.
"""
from typing import Dict, Any
from avengers.base_avenger import BaseAvenger
from blueprints.schemas import Task, AvengerResult
from tools.vision.vision_mcp import VisionMcpTool


class VisionAgent(BaseAvenger):
    """
    Agent specialized in network reconnaissance using Nmap.
    
    Supports actions:
    - ping_scan: Host discovery
    - quick_scan: Fast top-100 port scan
    - port_scan: Specific port scanning
    - service_scan: Service version detection
    - comprehensive_scan: Aggressive scan with OS detection
    - stealth_scan: SYN stealth scan (requires privileges)
    """
    
    def __init__(self, timeout: int = 120):
        """
        Initialize the VisionAgent.
        
        Args:
            timeout: Maximum time (seconds) for each scan operation
        """
        self.tool = VisionMcpTool(timeout=timeout)
        self.supported_actions = {
            "ping_scan",
            "quick_scan", 
            "port_scan",
            "service_scan",
            "comprehensive_scan",
            "stealth_scan"
        }
    
    async def execute(self, task: Task) -> AvengerResult:
        """
        Execute a network scanning task.
        
        Args:
            task: Task object with action, target, and params
            
        Returns:
            AvengerResult with scan results or error information
        """
        # Validate action is supported
        if task.action not in self.supported_actions:
            return AvengerResult(
                task_id=task.task_id,
                status="failure",
                output=None,
                error_message=f"Unsupported action: {task.action}. Supported: {self.supported_actions}"
            )
        
        try:
            # Route to appropriate scan method
            result = await self._execute_scan(task.action, task.target, task.params)
            
            # Convert VisionScanResult to AvengerResult
            if result.success:
                return AvengerResult(
                    task_id=task.task_id,
                    status="success",
                    output=result.to_dict(),
                    error_message=None
                )
            else:
                return AvengerResult(
                    task_id=task.task_id,
                    status="failure",
                    output=result.to_dict(),
                    error_message=result.error
                )
                
        except Exception as e:
            return AvengerResult(
                task_id=task.task_id,
                status="failure",
                output=None,
                error_message=f"Agent execution error: {str(e)}"
            )
    
    async def _execute_scan(self, action: str, target: str, params: Dict[str, Any]):
        """
        Route action to the appropriate VisionMcpTool method.
        
        Args:
            action: The scan type to perform
            target: IP address or hostname to scan
            params: Additional parameters for the scan
            
        Returns:
            VisionScanResult from the tool
        """
        # Map actions to tool methods
        if action == "ping_scan":
            return await self.tool.ping_scan(target)
        
        elif action == "quick_scan":
            return await self.tool.quick_scan(target)
        
        elif action == "port_scan":
            ports = params.get("ports", "1-1000")  # Default to first 1000 ports
            return await self.tool.port_scan(target, ports)
        
        elif action == "service_scan":
            ports = params.get("ports")  # Optional port specification
            return await self.tool.service_scan(target, ports)
        
        elif action == "comprehensive_scan":
            return await self.tool.comprehensive_scan(target)
        
        elif action == "stealth_scan":
            ports = params.get("ports")  # Optional port specification
            return await self.tool.stealth_scan(target, ports)
        
        else:
            # Should never reach here due to validation above
            raise ValueError(f"Unknown action: {action}")