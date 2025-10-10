"""
Nmap Scanner Agent ("Vision").

This agent specializes in performing port scans using the Nmap tool.
It interacts with the Nmap tool wrapper in the MCP layer.
"""
from .base_avenger import BaseAvenger

class NmapScannerAgent(BaseAvenger):
    """An agent that uses Nmap to perform network scans."""

    async def execute(self, task: Task) -> AgentResult:
        ...