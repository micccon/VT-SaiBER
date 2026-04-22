# VT-SaiBER

VT-SaiBER is a Dockerized multi-agent cyber security application for running modular reconnaissance, vulnerability research, exploitation, and post-exploitation workflows on a VM or a local machine.

The system is built around:
- `LangGraph` for orchestration
- `PostgreSQL + pgvector` for persistence and RAG
- `MCP servers` for Kali and Metasploit tool access
- a shared mission state passed between specialized agents

## What Starts Automatically

When you start the stack with Docker Compose, these pieces work together:
- `postgres`: mission data, findings, sessions, attack chain, and knowledge base storage
- `knowledge_base`: ingests and syncs `src/database/testbed_docs` into `knowledge_base`
- `kali-mcp`: exposes scanning and enumeration tools
- `msf-mcp`: exposes Metasploit RPC-backed tools
- `agents`: runs the VT-SaiBER application environment

Important behavior:
- Testbed documentation is automatically synced into the KB from `src/database/testbed_docs`
- Mission reports default to `exports/<mission_id>/`
- Report export can be triggered from the main orchestrator or from the exporter CLI

## Project Layout

```text
VT-SaiBER/
|- docker-compose.yml
|- .env.example
|- README.md
|- exports/                  # Generated mission reports
|- src/
|  |- main.py               # Orchestrator entry point
|  |- agents/               # Supervisor, Scout, Fuzzer, Librarian, Striker, Resident
|  |- database/
|  |  |- manager.py         # DB APIs and persistence helpers
|  |  |- persistence.py     # Runtime state -> DB sync hooks
|  |  |- reporting/         # Report export and attack-path graph generation
|  |  |- rag/               # Embedding, indexing, retrieval, orchestration
|  |  |- schema.sql
|  |  `- testbed_docs/      # Documentation corpus indexed into the KB
|  |- graph/                # LangGraph workflow assembly and routing
|  `- mcp/                  # Kali / Metasploit bridges and servers
`- tests/
```

## Quick Start

### 1. Configure environment

Create your local `.env` from the template:

```bash
cp .env.example .env
```

At minimum, set:
- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`
- `OPENROUTER_API_KEY`
- `KALI_MCP_URL`
- `MSF_MCP_URL`

Optional but useful:
- `REPORT_EXPORT_DIR=exports`
- `RAG_KB_TOP_K`, `RAG_KB_FETCH_K`
- `RAG_MIN_DOCS`, `RAG_MIN_SCORE`

### 2. Start the stack

```bash
docker compose up --build
```

On startup:
- PostgreSQL initializes schema and indexes
- the `knowledge_base` service waits for Postgres
- `src/database/testbed_docs` is indexed into the KB
- the agents environment becomes ready for mission execution

## Running a Mission

You can run the orchestrator from the repo environment:

```bash
python -m src.main \
  --mission-goal "Research and exploit the target" \
  --target-scope "192.168.56.101"
```

If you also want a report bundle after the mission:

```bash
python -m src.main \
  --mission-goal "Research and exploit the target" \
  --target-scope "192.168.56.101" \
  --export-dir exports
```

If `--export-dir` is omitted, VT-SaiBER uses `REPORT_EXPORT_DIR`, which defaults to `exports`.

## Reports and Exported Artifacts

To export a report bundle for an existing mission:

```bash
python -m src.database.reporting.exporter --mission-id <mission_id>
```

By default, artifacts are written to:

```text
exports/<mission_id>/
```

The export bundle includes:
- `summary.json`
- `snapshot.json`
- `report.md`
- `report.html`
- `targets.csv`
- `services.csv`
- `findings.csv`
- `sessions.csv`
- `agent_logs.csv`
- `attack_chain.csv`
- `attack_path.json`
- `attack_path.mmd`
- `attack_path.dot`
- `attack_path.svg` if Graphviz is available

## Knowledge Base Behavior

The RAG layer indexes files from:

```text
src/database/testbed_docs/
```

This includes text, markdown, and PDF files. The KB sync service is intended to make local/VM usage simple:
- users do not need to run a separate ingest script
- the documentation corpus is refreshed automatically through Docker Compose

Manual maintenance is still available when needed:

```bash
python -m src.database.rag.rag_engine sync
python -m src.database.rag.rag_engine rebuild
```

## Retrieval Tuning

RAG retrieval behavior is configurable from environment variables:
- `RAG_KB_TOP_K`
- `RAG_KB_FETCH_K`
- `RAG_FINDINGS_TOP_K`
- `RAG_FINDINGS_FETCH_K`
- `RAG_KB_SIMILARITY_THRESHOLD`
- `RAG_FINDINGS_SIMILARITY_THRESHOLD`
- `RAG_MIN_DOCS`
- `RAG_MIN_SCORE`
- `RAG_MAX_CHUNKS_PER_DOC`

These values affect Librarian confidence checks and KB/findings retrieval quality.

## Safety Notes

- All agent activity is expected to stay within the declared mission scope
- Exploit execution is guarded through the supervisor/striker flow
- Session state, findings, attack chain, and agent logs are persisted to PostgreSQL

## Current Practical Defaults

For local and VM usage, the current intended workflow is:
1. `docker compose up --build`
2. let the KB sync complete automatically
3. run missions through `src.main`
4. collect reports from `exports/<mission_id>/`

This keeps the user workflow simple without requiring manual ingest or manual report path selection.
