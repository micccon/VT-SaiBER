"""Isolated graph entrypoints for validating v2 agents."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from src.state.cyber_state import CyberState
from src.v2.agents.fuzzer import fuzzer_v2_node
from src.v2.agents.librarian import librarian_v2_node
from src.v2.agents.resident import resident_v2_node
from src.v2.agents.scout import scout_v2_node
from src.v2.agents.striker import striker_v2_node
from src.v2.agents.supervisor import supervisor_v2_node
from src.v2.graph.router import route_next_agent_v2


def build_striker_v2_graph(checkpointer=None):
    """Build a minimal graph that runs only the Striker v2 node."""

    workflow = StateGraph(CyberState)
    workflow.add_node("striker_v2", striker_v2_node)
    workflow.set_entry_point("striker_v2")
    workflow.add_edge("striker_v2", END)
    if checkpointer:
        return workflow.compile(checkpointer=checkpointer)
    return workflow.compile()


def build_resident_v2_graph(checkpointer=None):
    """Build a minimal graph that runs only the resident v2 node."""

    workflow = StateGraph(CyberState)
    workflow.add_node("resident_v2", resident_v2_node)
    workflow.set_entry_point("resident_v2")
    workflow.add_edge("resident_v2", END)
    if checkpointer:
        return workflow.compile(checkpointer=checkpointer)
    return workflow.compile()


def build_librarian_v2_graph(checkpointer=None):
    """Build a minimal graph that runs only the librarian v2 node."""

    workflow = StateGraph(CyberState)
    workflow.add_node("librarian_v2", librarian_v2_node)
    workflow.set_entry_point("librarian_v2")
    workflow.add_edge("librarian_v2", END)
    if checkpointer:
        return workflow.compile(checkpointer=checkpointer)
    return workflow.compile()


def build_v2_validation_graph(checkpointer=None):
    """Build an isolated sequential v2 workflow for validation runs."""

    workflow = StateGraph(CyberState)
    workflow.add_node("scout_v2", scout_v2_node)
    workflow.add_node("fuzzer_v2", fuzzer_v2_node)
    workflow.add_node("striker_v2", striker_v2_node)
    workflow.set_entry_point("scout_v2")
    workflow.add_edge("scout_v2", "fuzzer_v2")
    workflow.add_edge("fuzzer_v2", "striker_v2")
    workflow.add_edge("striker_v2", END)
    if checkpointer:
        return workflow.compile(checkpointer=checkpointer)
    return workflow.compile()


def build_supervisor_v2_graph(checkpointer=None):
    """Build the first full supervisor-led isolated v2 workflow."""

    workflow = StateGraph(CyberState)
    workflow.add_node("supervisor_v2", supervisor_v2_node)
    workflow.add_node("scout_v2", scout_v2_node)
    workflow.add_node("fuzzer_v2", fuzzer_v2_node)
    workflow.add_node("librarian_v2", librarian_v2_node)
    workflow.add_node("striker_v2", striker_v2_node)
    workflow.add_node("resident_v2", resident_v2_node)
    workflow.set_entry_point("supervisor_v2")

    workflow.add_edge("scout_v2", "supervisor_v2")
    workflow.add_edge("fuzzer_v2", "supervisor_v2")
    workflow.add_edge("librarian_v2", "supervisor_v2")
    workflow.add_edge("striker_v2", "supervisor_v2")
    workflow.add_edge("resident_v2", "supervisor_v2")

    workflow.add_conditional_edges(
        "supervisor_v2",
        route_next_agent_v2,
        {
            "scout_v2": "scout_v2",
            "fuzzer_v2": "fuzzer_v2",
            "librarian_v2": "librarian_v2",
            "striker_v2": "striker_v2",
            "resident_v2": "resident_v2",
            END: END,
        },
    )

    if checkpointer:
        return workflow.compile(checkpointer=checkpointer)
    return workflow.compile()
