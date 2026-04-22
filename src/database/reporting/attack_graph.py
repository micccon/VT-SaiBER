from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List


def build_attack_graph_data(
    mission_id: str,
    attack_chain: List[Dict[str, Any]],
    sessions: List[Dict[str, Any]],
) -> Dict[str, Any]:
    nodes: List[Dict[str, Any]] = [
        {
            "id": "mission",
            "label": f"Mission\\n{mission_id}",
            "kind": "mission",
            "status": "neutral",
        }
    ]
    edges: List[Dict[str, Any]] = []

    previous_node = "mission"
    target_last_step: Dict[str, str] = {}
    for step in sorted(attack_chain, key=lambda item: int(item.get("step_number") or 0)):
        step_id = f"step_{int(step.get('step_number') or 0)}"
        target = str(step.get("target") or "").strip()
        label_lines = [
            f"{step.get('step_number', '?')}. {step.get('agent_name', 'agent')}",
            str(step.get("action") or "action"),
        ]
        if target:
            label_lines.append(target)
        if step.get("outcome"):
            label_lines.append(f"[{step['outcome']}]")

        nodes.append(
            {
                "id": step_id,
                "label": "\\n".join(label_lines),
                "kind": "step",
                "status": _normalize_status(step.get("outcome")),
            }
        )
        edges.append({"from": previous_node, "to": step_id, "label": ""})
        previous_node = step_id
        if target:
            target_last_step[target] = step_id

    for session in sessions:
        session_id = session.get("session_id")
        if session_id is None:
            continue
        target_ip = str(session.get("target_ip") or "unknown")
        session_node = f"session_{session_id}"
        nodes.append(
            {
                "id": session_node,
                "label": "\\n".join(
                    [
                        f"Session {session_id}",
                        target_ip,
                        str(session.get("session_type") or "session"),
                    ]
                ),
                "kind": "session",
                "status": "success" if session.get("closed_at") is None else "closed",
            }
        )
        source_node = target_last_step.get(target_ip, previous_node)
        edges.append({"from": source_node, "to": session_node, "label": "opened"})

    return {
        "mission_id": mission_id,
        "nodes": nodes,
        "edges": edges,
    }


def render_mermaid(graph: Dict[str, Any]) -> str:
    lines = [
        "flowchart TD",
        "  classDef success fill:#d9f99d,stroke:#3f6212,color:#1a2e05;",
        "  classDef failed fill:#fecaca,stroke:#991b1b,color:#450a0a;",
        "  classDef neutral fill:#dbeafe,stroke:#1d4ed8,color:#172554;",
        "  classDef closed fill:#e5e7eb,stroke:#6b7280,color:#111827;",
    ]

    for node in graph["nodes"]:
        lines.append(f"  {node['id']}[\"{node['label']}\"]")
    for edge in graph["edges"]:
        label = f"|{edge['label']}|" if edge.get("label") else ""
        lines.append(f"  {edge['from']} -->{label} {edge['to']}")
    for node in graph["nodes"]:
        lines.append(f"  class {node['id']} {node['status']};")
    return "\n".join(lines) + "\n"


def render_dot(graph: Dict[str, Any]) -> str:
    lines = [
        "digraph attack_path {",
        '  rankdir=LR;',
        '  graph [fontname="Helvetica"];',
        '  node [shape=box, style=filled, fontname="Helvetica"];',
        '  edge [fontname="Helvetica"];',
    ]
    for node in graph["nodes"]:
        fill = {
            "success": "#d9f99d",
            "failed": "#fecaca",
            "closed": "#e5e7eb",
        }.get(node["status"], "#dbeafe")
        label = node["label"].replace("\\n", "\\n")
        lines.append(f'  {node["id"]} [label="{label}", fillcolor="{fill}"];')
    for edge in graph["edges"]:
        label = f' [label="{edge["label"]}"]' if edge.get("label") else ""
        lines.append(f'  {edge["from"]} -> {edge["to"]}{label};')
    lines.append("}")
    return "\n".join(lines) + "\n"


def maybe_render_svg(dot_text: str) -> str | None:
    if shutil.which("dot") is None:
        return None

    with tempfile.NamedTemporaryFile("w", suffix=".dot", delete=False, encoding="utf-8") as dot_file:
        dot_file.write(dot_text)
        dot_path = dot_file.name

    with tempfile.NamedTemporaryFile("r", suffix=".svg", delete=False, encoding="utf-8") as svg_file:
        svg_path = svg_file.name

    try:
        subprocess.run(
            ["dot", "-Tsvg", dot_path, "-o", svg_path],
            check=True,
            capture_output=True,
            text=True,
        )
        with open(svg_path, "r", encoding="utf-8") as handle:
            return handle.read()
    except Exception:
        return None


def render_graph_json(graph: Dict[str, Any]) -> str:
    return json.dumps(graph, indent=2, default=str)


def _normalize_status(value: Any) -> str:
    raw = str(value or "").lower()
    if raw in {"success", "succeeded", "opened"}:
        return "success"
    if raw in {"failed", "error", "aborted", "blocked"}:
        return "failed"
    if raw == "closed":
        return "closed"
    return "neutral"
