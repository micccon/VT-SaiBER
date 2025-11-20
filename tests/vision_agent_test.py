"""
vision_agent_test.py - Using Managed Approach
"""

import time
from strands.agent import Agent
from strands.tools.mcp import MCPClient
from mcp.client.sse import sse_client
from strands.models.gemini import GeminiModel

MCP_SERVER_URL = "http://localhost:8000"

def run_strands_agent():
    print("--- 🤖 Initializing Strands Agent ---")
    
    print("Waiting 5 seconds for server routes to initialize...")
    time.sleep(5)
    
    try:
        # Create MCP client
        mcp_client = MCPClient(lambda: sse_client("http://localhost:8000/sse"))
        
        # Initialize the Gemini Model
        model = GeminiModel(
            client_args={
                "api_key": "YOUR GOOGLE API KEY",
            },
            model_id="gemini-2.5-flash",
            params={
                "temperature": 0.7,
                "max_output_tokens": 2048,
                "top_p": 0.9,
                "top_k": 40
            }
        )

        # Managed approach - pass the client directly
        agent = Agent(model=model, tools=[mcp_client])
        
        print("\n✅ Agent is ready with MCP tools!")
        print("--------------------------------------------------")
        
        # Run the agent with a task
        while True:
            user_input = input("\n🤖 Enter your task (or 'quit' to exit): ")
            if user_input.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break
            
            print("\n🔄 Processing...")
            result = agent(user_input)
            print(f"\n✅ Result: {result}")

    except Exception as e:
        print(f"❌ Agent failed to run: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    run_strands_agent()