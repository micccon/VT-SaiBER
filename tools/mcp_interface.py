"""
MCP (Model-Controller-Parser) Unified Interface.

This provides a simple, centralized access point to all available tool wrappers.
The agents should interact with this interface rather than importing individual
tool modules directly.
"""

from . import nmap_tool

class ToolRegistry:
    """A simple class to hold instances of tool wrappers."""
    def __init__(self):
        self.nmap = nmap_tool.NmapTool()
        # To add a new tool (e.g., openvas):
        # self.openvas = openvas_tool.OpenVASTool()

# Global instance that can be imported by agents.
tools = ToolRegistry()
