# Reference

This page gathers the main human-facing entrypoints and core repo terminology.

## Entry Points

### Main Orchestrator

```bash
python -m src.main
```

Important flags:

- `--mission-goal`
- `--target-scope`
- `--mission-id`
- `--thread-id`
- `--resume`
- `--checkpoint-id`
- `--export-dir`
- `--json`

### Report Exporter

```bash
python -m src.database.reporting.exporter
```

Important flag:

- `--mission-id`

### Demo Scenario Runner

```bash
python scripts/run_scenario.py
```

Important flags:

- `--list`
- `--scenario`
- `--live`
- `--dry-run`

### Interactive CLI

```bash
python cli.py
```

Used for:

- setup
- demos
- status checks
- test entrypoints
- utility commands

## Glossary

Mission:

- one scoped orchestration run driven by a mission goal and target scope

`CyberState`:

- the shared mission state passed through the graph

Runtime lane:

- one of the two execution styles in `src/runtime/`: chat or execution

Attackbox:

- the unified MCP-backed offensive tooling service

MCP:

- the tool-exposure protocol used by the attackbox service

Knowledge base sync:

- the ingest of `src/database/testbed_docs` into the persisted retrieval store

Intelligence brief:

- a structured librarian-produced finding used by routing, exploitation planning, and reporting

Attack chain:

- the persisted record of agent-level actions and mission progression

Report bundle:

- the exported set of JSON, CSV, markdown, HTML, and graph artifacts for a mission
