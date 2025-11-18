"""
Base tool interface. All tools must implement this.
"""

import json
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from tools.tool_result import ToolResult
from tools.tool_metadata import ToolMetadata


class BaseTool(ABC):
    """Abstract base for all tools."""
    
    def __init__(self, name: str, schema_path: Optional[str] = None):
        self.tool_name = name  # Fixed: Added tool_name attribute for registry
        self._schema = self._load_schema(schema_path) if schema_path else []
    
    @abstractmethod
    async def execute(self, method: str, **params) -> ToolResult:
        """Execute tool method. Must be implemented by subclass."""
        pass
    
    def _load_schema(self, path: str) -> List[Dict[str, Any]]:
        """Load tool schema from JSON."""
        with open(path) as f:
            return json.load(f)
    
    def get_schema(self) -> List[Dict[str, Any]]:
        """Return tool schema for discovery."""
        return self._schema
    
    def get_metadata(self) -> List[ToolMetadata]:
        """Convert schema to ToolMetadata objects for registry."""
        return [
            ToolMetadata.from_json_schema(schema_item)
            for schema_item in self._schema
        ]
    
    def validate_parameters(self, method: str, params: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """
        Validate params against schema. Returns (is_valid, error_message).
        Compatible with ToolRegistry expectations.
        """
        error = self._validate_params_internal(method, params)
        if error:
            return (False, error)
        return (True, None)
    
    def _validate_params_internal(self, method: str, params: Dict[str, Any]) -> Optional[str]:
        """Internal validation logic. Returns error string if invalid."""
        method_schema = next((s for s in self._schema if s["name"] == method), None)
        if not method_schema:
            return f"Unknown method: {method}"
        
        schema = method_schema["inputSchema"]
        required = set(schema.get("required", []))
        properties = set(schema.get("properties", {}).keys())
        
        missing = required - params.keys()
        if missing:
            return f"Missing required: {', '.join(missing)}"
        
        unexpected = params.keys() - properties
        if unexpected:
            return f"Unexpected params: {', '.join(unexpected)}"
        
        return None