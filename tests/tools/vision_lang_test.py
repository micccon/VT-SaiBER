"""
Vision Agent CLI
----------------
An interactive command-line interface for the Vision Agent using LangGraph and Google Gemini.
Features:
- persistent memory (MemorySaver)
- interactive chat loop
- robust Ctrl+C interrupt handling
- clean output parsing
- multiple scan tool support

TO RUN:
1. go to project root
2. pip install all requirements (langgraph, langchain-google-genai, etc)
3. python -m tests.tools.vision_lang_test
4. enter GOOGLE_API_KEY when prompted (or set as env var)
"""

import asyncio
import os
import getpass
from typing import Dict, Any, Union, List

# --- Third-Party Imports ---
from langchain_core.messages import HumanMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import StateGraph, MessagesState, START
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.memory import MemorySaver
from tools.vision.vision_tools import vision_tools


# ==========================================
# 1. CONFIGURATION & CONSTANTS
# ==========================================
MODEL_NAME = "gemini-2.5-flash"  # As requested
TEMPERATURE = 0
THREAD_ID = "1"  # Persistent conversation ID

# ==========================================
# 2. OUTPUT HELPERS
# ==========================================
def _clean_agent_content(content: Union[str, List[Dict[str, Any]]]) -> str:
    """Parses and cleans the raw content from Gemini (handles text vs. blocks)."""
    text_to_print = ""

    # Case A: Content is a simple string
    if isinstance(content, str):
        text_to_print = content

    # Case B: Content is a list of blocks (common in tool-use responses)
    elif isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text_to_print += block.get("text", "")
    
    return text_to_print

def _print_tool_update():
    """Prints a minimal confirmation when a tool finishes."""
    print(f"\n🛠️  TOOL: Scan finished.")

def _print_agent_response(content: str):
    """Prints the cleaned agent response."""
    if content.strip():
        print(f"\n🤖 GEMINI: {content}\n")

# ==========================================
# 3. GRAPH CONSTRUCTION
# ==========================================
def create_vision_graph():
    """Initializes the LLM, binds tools, and builds the StateGraph."""
    
    # 1. API Key Check
    if "GOOGLE_API_KEY" not in os.environ:
        os.environ["GOOGLE_API_KEY"] = getpass.getpass("Enter Google API Key: ")

    # 2. Initialize LLM & Tools
    llm = ChatGoogleGenerativeAI(model=MODEL_NAME, temperature=TEMPERATURE)
    llm_with_tools = llm.bind_tools(vision_tools)
    
    # 3. Define Nodes
    async def agent_node(state: MessagesState):
        result = await llm_with_tools.ainvoke(state["messages"])
        return {"messages": [result]}

    tool_node = ToolNode(vision_tools)

    # 4. Build Workflow
    workflow = StateGraph(MessagesState)
    workflow.add_node("agent", agent_node)
    workflow.add_node("tools", tool_node)

    # 5. Define Edges
    workflow.add_edge(START, "agent")
    workflow.add_conditional_edges("agent", tools_condition)
    workflow.add_edge("tools", "agent")

    # 6. Compile with Memory
    memory = MemorySaver()
    return workflow.compile(checkpointer=memory)

# ==========================================
# 4. STREAMING EXECUTION LOGIC
# ==========================================
async def run_interaction_stream(graph, user_input: str, config: Dict[str, Any]):
    """Runs a single interaction turn with the graph and streams output."""
    initial_state = {"messages": [HumanMessage(content=user_input)]}

    async for event in graph.astream(initial_state, config=config):
        for node_name, value in event.items():
            
            # --- Handle Tool Node Output ---
            if node_name == "tools":
                msgs = value.get("messages", [])
                if msgs:
                    _print_tool_update()

            # --- Handle Agent Node Output ---
            elif node_name == "agent":
                msgs = value.get("messages", [])
                if msgs:
                    last_msg = msgs[-1]
                    clean_text = _clean_agent_content(last_msg.content)
                    _print_agent_response(clean_text)

# ==========================================
# 5. MAIN APPLICATION LOOP
# ==========================================
async def main():
    graph = create_vision_graph()
    config = {"configurable": {"thread_id": THREAD_ID}}
    
    print("\n" + "="*50)
    print("🤖 VISION AGENT CLI")
    print("="*50)
    print("ℹ️  To EXIT: Type 'quit' or hit Ctrl+C when idle.")
    print("ℹ️  To CANCEL SCAN: Hit Ctrl+C while scanning.\n")
    
    while True:
        try:
            # --- 1. User Input Phase ---
            try:
                # Use to_thread to keep the event loop active (allows Ctrl+C to interrupt)
                user_input = await asyncio.to_thread(input, "👤 USER: ")
                user_input = user_input.strip()
            except EOFError:
                break # Handle Ctrl+D
                
            if not user_input:
                continue
                
            if user_input.lower() in ["quit", "exit", "q"]:
                print("👋 Exiting...")
                break

            # --- 2. Execution Phase ---
            try:
                await run_interaction_stream(graph, user_input, config)
                print("✅ Ready for next command.")
                
            except asyncio.CancelledError:
                print("🛑 Task Cancelled by system.")
                
        except KeyboardInterrupt:
            # --- 3. Interrupt Handling ---
            # If we catch KeyboardInterrupt here, it means the user hit Ctrl+C.
            # Depending on WHERE we were (input vs execution), the behavior is the same:
            # Cancel the current operation and reset the loop.
            print("\n\n🛑 OPERATION CANCELLED BY USER.")
            print("   (Enter new command or Ctrl+C again to quit)\n")
            continue

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")