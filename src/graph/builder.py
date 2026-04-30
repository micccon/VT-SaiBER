"""Production LangGraph workflow builder."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from src.agents.fuzzer import fuzzer_node
from src.agents.librarian import librarian_node
from src.agents.resident import resident_node
from src.agents.scout import scout_node
from src.agents.striker import striker_node
from src.agents.supervisor import supervisor_node
from src.graph.router import route_next_agent
from src.state.cyber_state import CyberState


def build_graph(checkpointer=None):
    """Build the single supervisor-led production workflow."""

    workflow = StateGraph(CyberState)
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("scout", scout_node)
    workflow.add_node("fuzzer", fuzzer_node)
    workflow.add_node("librarian", librarian_node)
    workflow.add_node("striker", striker_node)
    workflow.add_node("resident", resident_node)
    workflow.set_entry_point("supervisor")

    for node in ("scout", "fuzzer", "librarian", "striker", "resident"):
        workflow.add_edge(node, "supervisor")

    workflow.add_conditional_edges(
        "supervisor",
        route_next_agent,
        {
            "scout": "scout",
            "fuzzer": "fuzzer",
            "librarian": "librarian",
            "striker": "striker",
            "resident": "resident",
            END: END,
        },
    )

    if checkpointer:
        return workflow.compile(checkpointer=checkpointer)
    return workflow.compile()

