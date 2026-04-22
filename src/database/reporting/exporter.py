from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List

from dotenv import load_dotenv

from src.config import get_runtime_config
from src.database.manager import (
    ensure_runtime_indexes,
    get_agent_logs_by_mission,
    get_attack_chain_by_mission,
    get_findings_by_mission,
    get_services_by_mission,
    get_sessions_by_mission,
    get_targets_by_mission,
)
from .attack_graph import (
    build_attack_graph_data,
    maybe_render_svg,
    render_dot,
    render_graph_json,
    render_mermaid,
)


def export_mission_bundle(mission_id: str, output_dir: str) -> Dict[str, str]:
    ensure_runtime_indexes()

    output_path = Path(output_dir).expanduser().resolve() / mission_id
    output_path.mkdir(parents=True, exist_ok=True)

    targets = get_targets_by_mission(mission_id)
    services = get_services_by_mission(mission_id)
    findings = get_findings_by_mission(mission_id)
    sessions = get_sessions_by_mission(mission_id)
    agent_logs = get_agent_logs_by_mission(mission_id)
    attack_chain = get_attack_chain_by_mission(mission_id)

    summary = {
        "mission_id": mission_id,
        "targets_count": len(targets),
        "services_count": len(services),
        "findings_count": len(findings),
        "sessions_count": len(sessions),
        "open_sessions_count": sum(1 for item in sessions if item.get("closed_at") is None),
        "agent_log_count": len(agent_logs),
        "attack_chain_steps": len(attack_chain),
    }

    snapshot = {
        "summary": summary,
        "targets": targets,
        "services": services,
        "findings": findings,
        "sessions": sessions,
        "agent_logs": agent_logs,
        "attack_chain": attack_chain,
    }

    written = {
        "summary_json": _write_json(output_path / "summary.json", summary),
        "snapshot_json": _write_json(output_path / "snapshot.json", snapshot),
        "report_md": _write_text(output_path / "report.md", _build_markdown_report(snapshot)),
        "report_html": _write_text(output_path / "report.html", _build_html_report(snapshot)),
        "findings_csv": _write_csv(output_path / "findings.csv", findings),
        "sessions_csv": _write_csv(output_path / "sessions.csv", sessions),
        "agent_logs_csv": _write_csv(output_path / "agent_logs.csv", agent_logs),
        "attack_chain_csv": _write_csv(output_path / "attack_chain.csv", attack_chain),
        "targets_csv": _write_csv(output_path / "targets.csv", targets),
        "services_csv": _write_csv(output_path / "services.csv", services),
    }

    graph = build_attack_graph_data(mission_id, attack_chain, sessions)
    dot_text = render_dot(graph)
    written["attack_graph_json"] = _write_text(output_path / "attack_path.json", render_graph_json(graph))
    written["attack_graph_mermaid"] = _write_text(output_path / "attack_path.mmd", render_mermaid(graph))
    written["attack_graph_dot"] = _write_text(output_path / "attack_path.dot", dot_text)

    svg = maybe_render_svg(dot_text)
    if svg is not None:
        written["attack_graph_svg"] = _write_text(output_path / "attack_path.svg", svg)

    return written


def resolve_export_dir(output_dir: str | None = None) -> str:
    explicit = (output_dir or "").strip()
    if explicit:
        return explicit
    return get_runtime_config().report_export_dir or "exports"


def _write_json(path: Path, payload: Any) -> str:
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return str(path)


def _write_text(path: Path, content: str) -> str:
    path.write_text(content, encoding="utf-8")
    return str(path)


def _write_csv(path: Path, rows: Iterable[Dict[str, Any]]) -> str:
    rows = list(rows)
    fieldnames = _collect_fieldnames(rows)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _flatten_value(row.get(key)) for key in fieldnames})
    return str(path)


def _collect_fieldnames(rows: List[Dict[str, Any]]) -> List[str]:
    fieldnames: List[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)
    return fieldnames or ["empty"]


def _flatten_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return "" if value is None else str(value)


def _build_markdown_report(snapshot: Dict[str, Any]) -> str:
    summary = snapshot["summary"]
    findings = snapshot["findings"]
    sessions = snapshot["sessions"]
    attack_chain = snapshot["attack_chain"]

    lines = [
        f"# Mission Report: {summary['mission_id']}",
        "",
        "## Summary",
        f"- Targets: {summary['targets_count']}",
        f"- Services: {summary['services_count']}",
        f"- Findings: {summary['findings_count']}",
        f"- Sessions: {summary['sessions_count']} ({summary['open_sessions_count']} open)",
        f"- Attack chain steps: {summary['attack_chain_steps']}",
        "",
        "## Key Findings",
    ]

    if findings:
        for finding in findings[:20]:
            lines.append(
                f"- [{finding.get('severity', 'info')}] {finding.get('title', 'finding')} "
                f"({finding.get('agent_name', 'agent')})"
            )
    else:
        lines.append("- None")

    lines.extend(["", "## Sessions"])
    if sessions:
        for session in sessions:
            lines.append(
                f"- Session {session.get('session_id')} on {session.get('target_ip')} "
                f"via {session.get('exploit_used') or 'unknown'}"
            )
    else:
        lines.append("- None")

    lines.extend(["", "## Attack Chain"])
    if attack_chain:
        for step in attack_chain:
            lines.append(
                f"{step.get('step_number')}. {step.get('agent_name')} -> "
                f"{step.get('action')} [{step.get('outcome') or 'n/a'}]"
            )
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Artifacts",
            "- `summary.json` and `snapshot.json` contain structured export data.",
            "- `attack_path.mmd` and `attack_path.dot` contain graph visualizations.",
        ]
    )
    return "\n".join(lines) + "\n"


def _build_html_report(snapshot: Dict[str, Any]) -> str:
    summary = snapshot["summary"]
    findings_rows = "".join(
        f"<tr><td>{finding.get('severity', '')}</td><td>{finding.get('agent_name', '')}</td><td>{finding.get('title', '')}</td></tr>"
        for finding in snapshot["findings"][:50]
    ) or "<tr><td colspan='3'>No findings</td></tr>"
    session_rows = "".join(
        f"<tr><td>{session.get('session_id', '')}</td><td>{session.get('target_ip', '')}</td><td>{session.get('exploit_used', '')}</td></tr>"
        for session in snapshot["sessions"]
    ) or "<tr><td colspan='3'>No sessions</td></tr>"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Mission Report {summary['mission_id']}</title>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; margin: 2rem; color: #14213d; background: linear-gradient(180deg, #f8fafc, #e2e8f0); }}
    h1, h2 {{ color: #0f172a; }}
    table {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; background: white; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 0.6rem; text-align: left; }}
    th {{ background: #dbeafe; }}
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
    .card {{ background: white; padding: 1rem; border: 1px solid #cbd5e1; border-radius: 12px; }}
  </style>
</head>
<body>
  <h1>Mission Report: {summary['mission_id']}</h1>
  <div class="summary">
    <div class="card"><strong>Targets</strong><br>{summary['targets_count']}</div>
    <div class="card"><strong>Services</strong><br>{summary['services_count']}</div>
    <div class="card"><strong>Findings</strong><br>{summary['findings_count']}</div>
    <div class="card"><strong>Sessions</strong><br>{summary['sessions_count']}</div>
  </div>
  <h2>Findings</h2>
  <table>
    <thead><tr><th>Severity</th><th>Agent</th><th>Title</th></tr></thead>
    <tbody>{findings_rows}</tbody>
  </table>
  <h2>Sessions</h2>
  <table>
    <thead><tr><th>Session ID</th><th>Target</th><th>Exploit</th></tr></thead>
    <tbody>{session_rows}</tbody>
  </table>
</body>
</html>
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export VT-SaiBER mission reporting bundle")
    parser.add_argument("--mission-id", required=True, help="Mission identifier to export")
    parser.add_argument(
        "--output-dir",
        default="",
        help="Directory to write export artifacts into. Defaults to REPORT_EXPORT_DIR or ./exports",
    )
    return parser


def main() -> int:
    load_dotenv()
    args = _build_parser().parse_args()
    written = export_mission_bundle(args.mission_id, resolve_export_dir(args.output_dir))
    print(json.dumps(written, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
