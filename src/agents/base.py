from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseAgent(ABC):
    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self.db = DatabaseManager()  # Shared DB access
        self.mcp = MCPClient()        # Shared tool access
    
    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """Each agent defines its own personality/goals"""
        pass
    
    @abstractmethod
    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """Core reasoning loop - must be implemented by each agent"""
        pass
    
    def log_finding(self, finding_type: str, data: Any):
        """Standard logging interface"""
        self.db.insert_finding(agent=self.name, type=finding_type, data=data)
    
    def validate_scope(self, target_ip: str) -> bool:
        """Global safety check"""
        return target_ip in allowed_subnets