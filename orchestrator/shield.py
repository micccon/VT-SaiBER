"""
The main Orchestrator class.

This class is the central hub that connects all other components.
It takes a user query and manages the entire workflow from prompt engineering
to plan execution and final reporting.
"""
import yaml
import logging
from typing import Optional
from orchestrator.interfaces import IPromptBuilder, ILLMClient, IReportGenerator
from orchestrator.nick_fury import FuryAgentController
from blueprints.schemas import UserQueryRequest, FinalReport
from interaction.api.thanos import process_user_input
from orchestrator.tony_stark import StarkPromptEngine

logger = logging.getLogger(__name__)


class ShieldOrchestrator:
    """
    Central orchestrator that coordinates the entire workflow.
    
    Workflow:
    1. Receive user query
    2. Build prompt (via PromptBuilder)
    3. Get execution plan (via LLMClient)
    4. Execute tasks (via AgentController)
    5. Generate report (via ReportGenerator)
    """

    def __init__(
        self, 
        config_path: str,
        prompt_builder: StarkPromptEngine,
        llm_client: ILLMClient,
        report_generator: IReportGenerator
    ):
        """
        Initializes the Orchestrator and its sub-components.

        Args:
            config_path: Path to the main configuration YAML file
            prompt_builder: Implementation of IPromptBuilder (from prompt person)
            llm_client: Implementation of ILLMClient (from LLM person)
            report_generator: Implementation of IReportGenerator
        """
        self.config = self._load_config(config_path)
        
        # Components (injected dependencies)
        self.prompt_builder = prompt_builder
        self.llm_client = llm_client
        self.report_generator = report_generator
        
        # Initialize agent controller
        agent_registry_path = self.config.get('database', {}).get('agent_registry_path', './database/avenger_registry.json')
        self.agent_controller = FuryAgentController(agent_registry_path)
        
        logger.info("ShieldOrchestrator initialized successfully")
    
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                logger.info(f"Configuration loaded from {config_path}")
                return config
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}
    
    async def execute(self, user_query: UserQueryRequest) -> FinalReport:
        """
        Main orchestration method - executes the full workflow.
        
        Args:
            user_query: User's query with prompt and optional session_id
            
        Returns:
            FinalReport with summary and detailed results
        """
        logger.info(f"Orchestrator received query: {user_query.prompt[:100]}")
        
        try:
            # Step 1: Extract structured command using thanos (sanitization + parsing)
            logger.info("Sanitizing and validating...")
            processed_json = process_user_input(
                raw_input=user_query.prompt,
                output_context="json"
            )
            logger.info(f"processed_json: {str(processed_json)[:200]}")

            # Step 2: Build prompt using the structured command
            logger.info("Building prompt...")
            prompt = self.prompt_builder.build_prompt(
                user_query=processed_json,
                agent_registry=self.agent_controller.agent_registry,
                context={"session_id": user_query.session_id}
            )
            logger.debug(f"Generated prompt (first 200 chars): {prompt[:200]}")
            
            # Step 3: Get execution plan from LLM
            logger.info("Generating execution plan via LLM...")
            execution_plan = await self.llm_client.generate_plan(prompt)
            logger.info(f"LLM generated plan with {len(execution_plan.tasks)} tasks")
            
            # Step 4: Execute the plan
            logger.info("Executing plan via agent controller...")
            results = await self.agent_controller.execute_plan(execution_plan)
            logger.info(f"Plan execution complete. {len(results)} results returned.")
            
            # Step 5: Generate final report
            logger.info("Generating final report...")
            summary = self.report_generator.generate_summary(results, user_query.prompt)
            
            final_report = FinalReport(
                summary=summary,
                results=results,
                session_id=user_query.session_id or "default"
            )
            
            logger.info("Orchestration complete. Returning final report.")
            return final_report
            
        except Exception as e:
            logger.error(f"Orchestration failed: {e}", exc_info=True)
            # Return error report
            return FinalReport(
                summary=f"Orchestration failed: {str(e)}",
                results=[],
                session_id=user_query.session_id or "default"
            )