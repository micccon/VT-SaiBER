"""
Vision scan result object, basically a good serializable structure for mcp use

This module is responsible for:
1. Hosting all nmap output into an object that mcp can use
"""
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any  
import json
from dataclasses import dataclass, asdict

# Structure thats serializable that mcp can use
@dataclass
class VisionScanResult:
    success: bool
    target: str
    scan_type: str
    hosts: List[Dict[str, Any]]
    error: Optional[str] = None
    command: Optional[str] = None
    duration: Optional[float] = None

    # make to dictionary for mcp response
    def to_dict(self) -> Dict:
        return asdict(self)
    
    # make to json for mcp and printing output
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
    
    