"""
End-to-end test of the AgentSystem orchestration layer.

Tests the full workflow with the modern Google ADK-based architecture.
NOTE: Requires MCP server running (python tools/vision/vision_mcp_server.py)
      and a valid GOOGLE_API_KEY environment variable.
"""
import asyncio
import logging
import os

from orchestrator.agent_system import AgentSystem

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


async def test_full_workflow():
    """Test the complete AgentSystem workflow."""
    
    print("=" * 60)
    print("Testing VT-SaiBER AgentSystem (ADK-based)")
    print("=" * 60)
    
    # Check for API key
    if not os.environ.get("GOOGLE_API_KEY") or os.environ.get("GOOGLE_API_KEY") == "YOUR API KEY":
        print("\n⚠️  WARNING: GOOGLE_API_KEY not set or is placeholder.")
        print("   Set it via: export GOOGLE_API_KEY='your-key-here'")
        print("   Or the test will fail when calling the LLM.\n")
    
    # Initialize the modern AgentSystem
    system = AgentSystem()
    
    print("\nInitializing AgentSystem...")
    await system.initialize()
    print("✅ AgentSystem initialized successfully\n")
    
    # Test query
    test_query = "Scan scanme.nmap.org for open ports"
    
    print(f"User Query: {test_query}")
    print("-" * 60)
    
    # Execute
    print("\nExecuting query through AgentSystem...\n")
    
    try:
        response = await system.run_query(test_query)
        
        # Display results
        print("\n" + "=" * 60)
        print("FINAL RESPONSE")
        print("=" * 60)
        print(response if response else "(No response received)")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Error during execution: {e}")
        print("\nTroubleshooting:")
        print("1. Ensure MCP server is running: python tools/vision/vision_mcp_server.py")
        print("2. Ensure GOOGLE_API_KEY is set correctly")
        print("3. Check network connectivity to scanme.nmap.org")
        raise


async def test_input_validation():
    """Test the input sanitization (Thanos) layer."""
    
    print("\n" + "=" * 60)
    print("Testing Input Validation (Thanos)")
    print("=" * 60)
    
    system = AgentSystem()
    await system.initialize()
    
    # Test with potentially dangerous input
    dangerous_inputs = [
        "scan 192.168.1.1; rm -rf /",  # Command injection attempt
        "scan <script>alert('xss')</script>",  # XSS attempt
        "scan {{template_injection}}",  # Template injection
    ]
    
    for dangerous_input in dangerous_inputs:
        print(f"\nTesting: {dangerous_input[:50]}...")
        try:
            response = await system.run_query(dangerous_input)
            print(f"Response: {response[:100] if response else 'None'}...")
        except Exception as e:
            print(f"Caught exception (expected for some inputs): {e}")


if __name__ == "__main__":
    print("\n🚀 Starting VT-SaiBER AgentSystem Tests\n")
    
    # Run main workflow test
    asyncio.run(test_full_workflow())
    
    # Optionally run validation tests
    # asyncio.run(test_input_validation())
    
    print("\n✅ Tests completed!")
