# pytest tests/db_tests/test_attack_graph_reporting.py

from src.database.reporting.attack_graph import (
    build_attack_graph_data,
    render_dot,
    render_mermaid,
)


def test_attack_graph_builds_steps_and_sessions():
    graph = build_attack_graph_data(
        mission_id="mission-graph-001",
        attack_chain=[
            {
                "step_number": 1,
                "agent_name": "scout",
                "action": "recon_scan",
                "target": "10.0.0.10",
                "outcome": "success",
            },
            {
                "step_number": 2,
                "agent_name": "striker",
                "action": "run_exploit",
                "target": "10.0.0.10",
                "outcome": "success",
            },
        ],
        sessions=[
            {
                "session_id": 7,
                "target_ip": "10.0.0.10",
                "session_type": "meterpreter",
                "closed_at": None,
            }
        ],
    )

    node_ids = {node["id"] for node in graph["nodes"]}
    assert "mission" in node_ids
    assert "step_1" in node_ids
    assert "step_2" in node_ids
    assert "session_7" in node_ids
    assert any(edge["to"] == "session_7" for edge in graph["edges"])


def test_attack_graph_renderers_include_expected_tokens():
    graph = build_attack_graph_data(
        mission_id="mission-graph-002",
        attack_chain=[
            {
                "step_number": 1,
                "agent_name": "supervisor",
                "action": "route_decision",
                "target": "scout",
                "outcome": "routed",
            }
        ],
        sessions=[],
    )

    mermaid = render_mermaid(graph)
    dot = render_dot(graph)

    assert "flowchart TD" in mermaid
    assert "step_1" in mermaid
    assert "digraph attack_path" in dot
    assert "route_decision" in dot
