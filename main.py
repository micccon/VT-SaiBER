"""
main.py - CLI Entry Point

Prerequisites:
1. Start MCP server: python mcp_server.py (in another terminal)
2. Run this: python main.py
"""

import os
import asyncio
from orchestrator.agent_system import AgentSystem

# Config
os.environ["GOOGLE_API_KEY"] = "YOUR API KEY"
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"


async def main():
    print("🔄 Initializing Multi-Agent System...")
    print("⚠️  Make sure MCP server is running: python mcp_server.py\n")
    # Initialize agent system
    system = AgentSystem()
    await system.initialize()
    
    print("✅ Multi-Agent System Ready!")
    print("📋 Available Agents:")
    print("   • Scanner: Network security scanning (nmap)")
    print("   • Vuln Report: Vulnerability assessment reports")
    print("   • Orchestrator: Coordinates workflows\n")
    
    print("💡 Example queries:")
    print('   "Scan 192.168.1.1"')
    print('   "Scan scanme.nmap.org and create a vulnerability report"')
    print('   "Generate a security assessment for 10.0.0.0/24"\n')
    
    # Interactive loop
    while True:
        query = input("🤖 Query: ")
        if query.lower() in ['quit', 'exit', 'q']:
            break
        
        response = await system.run_query(query)
        print(f"\n✅ {response}\n")


if __name__ == "__main__":
    asyncio.run(main())