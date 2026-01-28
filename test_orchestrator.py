"""
End-to-end test of the orchestrator communication layer.

Tests the full workflow with mock LLM/Prompt components.
"""
import asyncio
import logging
from orchestrator.shield import ShieldOrchestrator
from orchestrator.mocks import MockPromptBuilder, MockLLMClient, MockReportGenerator
from blueprints.schemas import UserQueryRequest

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

async def test_full_workflow():
    """Test the complete orchestrator workflow."""
    
    print("=" * 60)
    print("Testing VT-SaiBER Orchestrator Communication Layer")
    print("=" * 60)
    
    # Initialize orchestrator with mock components
    orchestrator = ShieldOrchestrator(
        config_path="./config.yaml",
        prompt_builder=MockPromptBuilder(),
        llm_client=MockLLMClient(),
        report_generator=MockReportGenerator()
    )
    
    # Test query
    query = UserQueryRequest(
        prompt="Scan scanme.nmap.org for open ports",
        session_id="test_session_001"
    )
    
    print(f"\nUser Query: {query.prompt}")
    print(f"Session ID: {query.session_id}\n")
    
    # Execute
    print("Executing orchestrator workflow...\n")
    report = await orchestrator.execute(query)
    
    # Display results
    print("\n" + "=" * 60)
    print("FINAL REPORT")
    print("=" * 60)
    print(report.summary)
    print("\n" + "=" * 60)
    print(f"Total tasks executed: {len(report.results)}")
    print(f"Successful: {sum(1 for r in report.results if r.status == 'success')}")
    print(f"Failed: {sum(1 for r in report.results if r.status == 'failure')}")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test_full_workflow())