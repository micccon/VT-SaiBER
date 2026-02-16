from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from datetime import datetime

from src.state.cyber_state import CyberState
from src.state.models import AgentLogEntry, AgentError


class BaseAgent(ABC):
    """Abstract base class for all specialized agents.

    All agent implementations must inherit from this class and implement
    the required abstract methods.
    """

    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self._db = None  # Lazy initialization
        self._mcp = None  # Lazy initialization

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """Return the agent's system prompt defining its personality and goals."""
        pass

    @abstractmethod
    async def call_llm(self, state: CyberState) -> Dict[str, Any]:
        """Core reasoning loop - must be implemented by each agent.

        Args:
            state: The current CyberState containing all mission data.

        Returns:
            Dict with state updates to be merged into the shared state.
        """
        pass

    @property
    def db(self):
        """Lazy load database manager. load postgres database manager."""
        
        # if self._db is None:
        #     from database.manager import DatabaseManager
        #     self._db = DatabaseManager()
        # return self._db
        pass

    @property
    def mcp(self):
        """Lazy load MCP client."""
        if self._mcp is None:
            from mcp.client import MCPClient
            self._mcp = MCPClient()
        return self._mcp

    def log_action(
        self,
        state: CyberState,
        action: str,
        target: Optional[str] = None,
        findings: Optional[Dict[str, Any]] = None,
        decision: Optional[str] = None,
        reasoning: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a log entry for the agent's actions.

        Args:
            state: Current CyberState (used to append to agent_log).
            action: The action performed (e.g., "nmap_scan", "run_exploit").
            target: Optional target IP/hostname.
            findings: Optional findings data.
            decision: Optional decision made.
            reasoning: Optional reasoning for the action.

        Returns:
            State update dict with the new log entry.
        """
        entry = AgentLogEntry(
            agent=self.name,
            action=action,
            target=target,
            findings=findings,
            decision=decision,
            reasoning=reasoning,
        )
        return {"agent_log": [entry]}

    def log_error(
        self,
        state: CyberState,
        error_type: str,
        error: str,
        recoverable: bool = True,
    ) -> Dict[str, Any]:
        """Log an error encountered during execution.

        Args:
            state: Current CyberState.
            error_type: Type/category of error.
            error: Error message/details.
            recoverable: Whether the error is recoverable.

        Returns:
            State update dict with the error entry.
        """
        err = AgentError(
            agent=self.name,
            error_type=error_type,
            error=error,
            recoverable=recoverable,
        )
        return {"errors": [err]}

    def add_critical_finding(self, state: CyberState, finding: str) -> Dict[str, Any]:
        """Add a critical finding to the state.

        Args:
            state: Current CyberState.
            finding: The critical finding text.

        Returns:
            State update dict with the critical finding.
        """
        return {"critical_findings": [finding]}

    def validate_scope(self, target_ip: str, target_scope: list[str]) -> bool:
        """Validate that a target is within the authorized scope.

        Args:
            target_ip: IP address to validate.
            target_scope: List of allowed CIDR blocks or IPs.

        Returns:
            True if target is in scope, False otherwise.
        """
        from ipaddress import ip_address, ip_network

        try:
            target = ip_address(target_ip)
            for cidr in target_scope:
                if target in ip_network(cidr, strict=False):
                    return True
            return False
        except ValueError:
            return False

    async def run_with_error_handling(
        self,
        state: CyberState,
        operation_name: str,
        operation,
    ) -> Dict[str, Any]:
        """Run an operation with standardized error handling.

        Args:
            state: Current CyberState.
            operation_name: Name of the operation for logging.
            operation: Async callable to execute.

        Returns:
            State update dict with results or error.
        """
        try:
            result = await operation()
            return {
                **result,
                **self.log_action(
                    state,
                    action=operation_name,
                    findings=result,
                ),
            }
        except Exception as e:
            return self.log_error(
                state,
                error_type=type(e).__name__,
                error=str(e),
            )
