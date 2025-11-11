"""
Communication Interfaces for Orchestrator Components

These abstract classes define the contracts between different parts
of the system, allowing teams to work independently.
"""
from abc import ABC, abstractmethod
from blueprints.schemas import ExecutionPlan


class IPromptBuilder(ABC):
    """
    Interface for the Prompt Engineering component.
    
    The prompt person implements this to provide formatted prompts
    to the LLM component.
    """
    
    @abstractmethod
    def build_prompt(self, user_query: str, agent_registry: dict, context: dict = None) -> str:
        """
        Build a formatted prompt for the LLM.
        
        Args:
            user_query: The raw user input
            agent_registry: Available agents and their capabilities
            context: Optional additional context (session history, etc.)
            
        Returns:
            Formatted prompt string ready for LLM
        """
        pass


class ILLMClient(ABC):
    """
    Interface for the LLM integration component.
    
    The LLM person implements this to handle API calls to
    OpenAI/Anthropic/etc and return structured plans.
    """
    
    @abstractmethod
    async def generate_plan(self, prompt: str) -> ExecutionPlan:
        """
        Send prompt to LLM and get back a structured execution plan.
        
        Args:
            prompt: The formatted prompt from PromptBuilder
            
        Returns:
            ExecutionPlan with list of tasks
            
        Raises:
            Exception: If LLM call fails
        """
        pass


class IReportGenerator(ABC):
    """
    Interface for report generation.
    
    Can be implemented by the UI/API person or as part of orchestrator.
    """
    
    @abstractmethod
    def generate_summary(self, results: list, user_query: str) -> str:
        """
        Generate a human-readable summary from agent results.
        
        Args:
            results: List of AvengerResult objects
            user_query: Original user query for context
            
        Returns:
            Natural language summary string
        """
        pass