# VT-SaiBER

VT-SaiBER is a multi-agent offensive security orchestration framework for scoped, repeatable cyber-physical security workflows. It combines a supervisor-led graph, specialized agents, PostgreSQL-backed persistence, RAG-assisted research, and a unified attackbox MCP surface for Kali and Metasploit tooling.

## What It Does

- Orchestrates reconnaissance, web testing, exploit research, exploitation, and post-exploitation through specialized agents.
- Persists mission state, findings, sessions, agent logs, and attack-chain history in PostgreSQL.
- Uses a knowledge base plus external enrichment to support research-heavy decisions through the Librarian agent.
- Produces structured export bundles for mission review, reporting, and downstream analysis.

## Core Components

- `src/main.py`: main orchestration entrypoint
- `src/graph/`: LangGraph workflow assembly and routing
- `src/runtime/`: promoted runtime surface for chat, execution, approvals, and tracing
- `src/agents/`: supervisor, scout, fuzzer, librarian, striker, and resident agents
- `src/database/`: persistence, reporting, and RAG subsystems
- `src/mcp/`: unified attackbox MCP server and Metasploit integration
- `scripts/setup/`: Docker and automotive testbed setup helpers
- `scripts/tests/`: test suites

## Quick Start

1. Copy the environment template.

```bash
cp .env.example .env
```

2. Start the main stack.

```bash
docker compose up --build -d
```

3. Start the automotive testbed if you want the full demo environment.

```bash
bash scripts/setup/testbed/setup_testbed.sh
```

4. Run a mission.

```bash
python -m src.main \
  --mission-id demo-001 \
  --mission-goal "Perform scoped reconnaissance and exploit-path analysis" \
  --target-scope "automotive-testbed"
```

5. Export a report bundle for an existing mission.

```bash
python -m src.database.reporting.exporter --mission-id demo-001
```

## Where To Go Next

- [Docs Hub](docs/README.md)
- [Getting Started](docs/GETTING_STARTED.md)
- [Operations](docs/OPERATIONS.md)
- [Testing](docs/TESTING.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Development](docs/DEVELOPMENT.md)
- [Reference](docs/REFERENCE.md)
- [Contributing](CONTRIBUTING.md)

## Current Workflow Defaults

- The Compose stack provisions `postgres`, `knowledge_base`, `attackbox`, and `agents`.
- The knowledge base ingests `src/database/testbed_docs` through the `knowledge_base` service.
- Mission export bundles default to `exports/<mission_id>/` through `REPORT_EXPORT_DIR` unless overridden.
- Live tests and MCP-dependent flows assume the attackbox endpoint at `ATTACKBOX_MCP_URL`.
