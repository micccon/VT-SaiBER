"""
Abstract Base Class for all Agents.

All specialized agents (e.g., NmapScannerAgent, DiscoveryAgent) must inherit
from this class and implement the `execute` method. This ensures a consistent
interface for the Agent Controller to interact with.
"""
from abc import ABC, abstractmethod
from core.schemas import Task, AgentResult

class BaseAgent(ABC):
    """
    Abstract Base Class for an agent.
    It defines the standard interface for agent execution.
    """

    @abstractmethod
    async def execute(self, task: Task) -> AgentResult:
        """
        The main execution method for the agent.

        This method receives a task, performs the required action using its
        specialized tools, and returns a structured result.

        Args:
            task: The task object containing details about the action to perform.

        Returns:
            An AgentResult object with the status and output of the task.
        """
        pass
