"""
Agent Controller ("Avenger Controller")

This module is responsible for managing the lifecycle and execution of agents.
It receives an execution plan from the orchestrator and dispatches tasks to the
appropriate agents.
"""

class FuryAgentController:
    ...

    def __init__(self, agent_registry_path: str):
        """
        Initializes the AgentController.

        Args:
            agent_registry_path: Path to the JSON file describing available agents.
        """