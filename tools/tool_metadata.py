from typing import Dict, Any
from dataclasses import dataclass, field

@dataclass
class ToolMetadata:
    """Metadata describing a tool for AI consumption"""
    name: str
    description: str
    input_schema: Dict[str, Any]
    category: str = "general"
    requires_admin: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
            "category": self.category,
            "requires_admin": self.requires_admin
        }
    
    @classmethod
    def from_json_schema(cls, data: Dict[str, Any], category: str = "general", requires_admin: bool = False) -> "ToolMetadata":
        """Create ToolMetadata from JSON schema format"""
        return cls(
            name=data["name"],
            description=data["description"],
            input_schema=data["inputSchema"],
            category=category,
            requires_admin=requires_admin
        )