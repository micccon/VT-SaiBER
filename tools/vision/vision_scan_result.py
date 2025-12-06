"""
Vision scan result object, basically a good serializable structure for mcp use

This module is responsible for:
1. Hosting all nmap output into an object that mcp can use
"""
import sys
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


# Handle imports for both package imports and direct execution
try:
    # Try relative import (works when imported as part of package)
    from ..tool_result import ToolResult
except ImportError:
    # Fallback to absolute import (works when run directly)
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from tools.tool_result import ToolResult

# Structure thats serializable that mcp can use
@dataclass(kw_only=True)
class VisionScanResult(ToolResult):
    target: str
    scan_type: str
    hosts: List[Dict[str, Any]]
    command: Optional[str] = None
    duration: Optional[float] = None