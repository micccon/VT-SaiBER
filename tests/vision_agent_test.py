"""
vision_agent_test.py - Google ADK with FastMCP
"""

import os
import asyncio
from google.adk.agents import Agent
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import SseConnectionParams
from google.genai import types

os.environ["GOOGLE_API_KEY"] = "YOUR API KEY"
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"

async def main():
    agent = Agent(
        name="vision_agent",
        model="gemini-2.0-flash",  # Stable model with better quota
        description="Network security scanner",
        instruction="Network security expert. Use nmap tools. Explain scans, warn about detection.",
        tools=[McpToolset(connection_params=SseConnectionParams(url="http://localhost:8000/sse"))],
    )

    session_service = InMemorySessionService()
    await session_service.create_session(app_name="agents", user_id="user1", session_id="sess1")
    runner = Runner(agent=agent, app_name="agents", session_service=session_service)

    print("✅ Ready!\n")

    while True:
        query = input("🤖 Query: ")
        if query.lower() in ['quit', 'exit', 'q']:
            break

        async for event in runner.run_async(
            user_id="user1",
            session_id="sess1",
            new_message=types.Content(role='user', parts=[types.Part(text=query)])
        ):
            if event.is_final_response():
                print(f"\n✅ {event.content.parts[0].text if event.content else 'No response'}\n")
                break

if __name__ == "__main__":
    asyncio.run(main())