"""
Agent Controller ("Avenger Controller")

This module is responsible for managing the lifecycle and execution of agents.
It receives an execution plan from the orchestrator and dispatches tasks to the
appropriate agents.
"""
import json
import logging
from typing import List, Dict
from blueprints.schemas import ExecutionPlan, Task, AvengerResult
from avengers.base_avenger import BaseAvenger

# Import available agents
from avengers.vision_agent import VisionAgent

logger = logging.getLogger(__name__)


class FuryAgentController:
    """
    Manages agent lifecycle and task execution.
    
    Responsibilities:
    - Load agent registry
    - Instantiate agents on demand
    - Execute tasks in correct order (respecting dependencies)
    - Collect and return results
    """
    
    def __init__(self, agent_registry_path: str):
        """
        Initializes the AgentController.

        Args:
            agent_registry_path: Path to the JSON file describing available agents.
        """
        self.agent_registry_path = agent_registry_path
        self.agent_registry = self._load_registry()
        self.agent_instances: Dict[str, BaseAvenger] = {}
        logger.info(f"FuryAgentController initialized with {len(self.agent_registry)} agents")
    
    def _load_registry(self) -> dict:
        """
        Load the agent registry from JSON file.
        
        Returns:
            Dictionary mapping agent names to their metadata
        """
        try:
            with open(self.agent_registry_path, 'r') as f:
                registry = json.load(f)
                logger.info(f"Loaded agent registry: {list(registry.keys())}")
                return registry
        except FileNotFoundError:
            logger.error(f"Agent registry not found at {self.agent_registry_path}")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in agent registry: {e}")
            return {}
    
    def _get_agent(self, agent_name: str) -> BaseAvenger:
        """
        Get or create an agent instance.
        
        Args:
            agent_name: Name of the agent (e.g., "VisionAgent")
            
        Returns:
            Instance of the requested agent
            
        Raises:
            ValueError: If agent is not found in registry
        """
        # Return cached instance if exists
        if agent_name in self.agent_instances:
            return self.agent_instances[agent_name]
        
        # Check if agent exists in registry
        if agent_name not in self.agent_registry:
            raise ValueError(f"Agent '{agent_name}' not found in registry")
        
        # Instantiate the agent (hardcoded for now, can make dynamic later)
        if agent_name == "VisionAgent":
            agent = VisionAgent(timeout=120)
        else:
            raise ValueError(f"Agent '{agent_name}' not implemented yet")
        
        # Cache the instance
        self.agent_instances[agent_name] = agent
        logger.info(f"Instantiated agent: {agent_name}")
        
        return agent
    
    async def execute_plan(self, plan: ExecutionPlan) -> List[AvengerResult]:
        """
        Execute all tasks in the execution plan.
        
        Tasks are executed in order, respecting dependencies.
        If a task fails and other tasks depend on it, those tasks are skipped.
        
        Args:
            plan: ExecutionPlan containing list of tasks
            
        Returns:
            List of AvengerResult objects (one per task)
        """
        results: List[AvengerResult] = []
        completed_task_ids = set()
        failed_task_ids = set()
        
        logger.info(f"Executing plan with {len(plan.tasks)} tasks")
        
        # Sort tasks by dependencies
        sorted_tasks = self._sort_by_dependencies(plan.tasks)
        
        for task in sorted_tasks:
            logger.info(f"Executing task {task.task_id}: {task.action} on {task.target}")
            
            # Check if dependencies are met
            if not self._dependencies_met(task, completed_task_ids, failed_task_ids):
                logger.warning(f"Task {task.task_id} skipped due to failed dependencies")
                result = AvengerResult(
                    task_id=task.task_id,
                    status="skipped",
                    output=None,
                    error_message="Dependency task failed or was skipped"
                )
                results.append(result)
                failed_task_ids.add(task.task_id)
                continue
            
            # Execute the task
            result = await self._execute_task(task)
            results.append(result)
            
            # Track completion status
            if result.status == "success":
                completed_task_ids.add(task.task_id)
                logger.info(f"Task {task.task_id} completed successfully")
            else:
                failed_task_ids.add(task.task_id)
                logger.error(f"Task {task.task_id} failed: {result.error_message}")
        
        logger.info(f"Plan execution complete. {len(completed_task_ids)} succeeded, {len(failed_task_ids)} failed")
        return results
    
    async def _execute_task(self, task: Task) -> AvengerResult:
        """
        Execute a single task on the appropriate agent.
        
        Args:
            task: Task to execute
            
        Returns:
            AvengerResult from the agent
        """
        try:
            agent = self._get_agent(task.agent)
            result = await agent.execute(task)
            return result
        except Exception as e:
            logger.error(f"Error executing task {task.task_id}: {e}")
            return AvengerResult(
                task_id=task.task_id,
                status="failure",
                output=None,
                error_message=f"Controller error: {str(e)}"
            )
    
    def _sort_by_dependencies(self, tasks: List[Task]) -> List[Task]:
        """
        Sort tasks in execution order based on dependencies.
        
        Simple implementation: Sort by task_id (assumes dependencies have lower IDs)
        More complex: Implement topological sort for DAG
        
        Args:
            tasks: List of tasks to sort
            
        Returns:
            Sorted list of tasks
        """
        # For now, simple sort by task_id
        # Assumes LLM generates task_ids in dependency order
        return sorted(tasks, key=lambda t: t.task_id)
    
    def _dependencies_met(self, task: Task, completed: set, failed: set) -> bool:
        """
        Check if all dependencies for a task are met.
        
        Args:
            task: Task to check
            completed: Set of successfully completed task IDs
            failed: Set of failed/skipped task IDs
            
        Returns:
            True if all dependencies completed successfully, False otherwise
        """
        for dep_id in task.dependencies:
            if dep_id in failed:
                return False
            if dep_id not in completed:
                return False
        return True