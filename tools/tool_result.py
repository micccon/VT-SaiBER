"""
This class provides a base for returning results from tools that agents exec

This module aims to:
1. Centralize the output of all tool execution
2. Provide a template for further tools to be implemented
"""

from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, Any
import json
import time

@dataclass
class ToolResult:
    success: bool
    tool_name: str
    message: Optional[str] = None
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    # make to dictionary for mcp response
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    # make to json for mcp and printing output
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    # pretty print
    def __str__(self) -> str:
        return self.to_json()