"""
LangGraph Workflow Builder
==========================
Constructs the agent workflow graph with proper routing.
"""

from langgraph.graph import StateGraph, END
# from langgraph.checkpoint.postgres import PostgresSaver

from src.graph.router import route_next_agent

from src.state.cyber_state import CyberState
from src.agents.supervisor import supervisor_node
from src.agents.scout import scout_node
from src.agents.fuzzer import fuzzer_node
from src.agents.librarian import librarian_node
from src.agents.striker import striker_node
from src.agents.resident import resident_node

def build_graph(checkpointer=None):
    """
    Build the LangGraph workflow.
    
    Args:
        checkpointer: Optional PostgresSaver for state persistence
    
    Returns:
        Compiled LangGraph
    """
    
    # Create graph
    workflow = StateGraph(CyberState)
    
    # Add nodes
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("scout", scout_node)
    workflow.add_node("fuzzer", fuzzer_node)
    workflow.add_node("librarian", librarian_node)
    workflow.add_node("striker", striker_node)
    workflow.add_node("resident", resident_node)
    
    # Set entry point
    workflow.set_entry_point("supervisor")
    
    # All specialist agents return to supervisor
    workflow.add_edge("scout", "supervisor")
    workflow.add_edge("fuzzer", "supervisor")
    workflow.add_edge("librarian", "supervisor")
    workflow.add_edge("striker", "supervisor")
    workflow.add_edge("resident", "supervisor")
    
    # Supervisor routes to next agent
    workflow.add_conditional_edges(
        "supervisor",
        route_next_agent,
        {
            "scout": "scout",
            "fuzzer": "fuzzer",
            "librarian": "librarian",
            "striker": "striker",
            "resident": "resident",
            END: END
        }
    )
    
    # Compile graph
    if checkpointer:
        return workflow.compile(checkpointer=checkpointer)
    else:
        return workflow.compile()
