# Development

This page is the main contributor-oriented reference for repo layout, changing agents, and important configuration surfaces.

## Repo Map

Root:

- `README.md`
- `CONTRIBUTING.md`
- `docker-compose.yml`
- `.env.example`
- `cli.py`

Source:

- `src/main.py`
- `src/runtime/`
- `src/graph/`
- `src/agents/`
- `src/database/`
- `src/mcp/`
- `src/state/`

Scripts:

- `scripts/run_scenario.py`
- `scripts/setup/`
- `scripts/tests/`

Docs:

- `docs/README.md`
- `docs/GETTING_STARTED.md`
- `docs/OPERATIONS.md`
- `docs/TESTING.md`
- `docs/ARCHITECTURE.md`
- `docs/DEVELOPMENT.md`
- `docs/REFERENCE.md`
- `docs/ARCHIVE.md`

## Adding or Changing an Agent

Most agents live under `src/agents/<agent_name>/` and commonly split behavior into:

- `agent.py`
- `constants.py`
- `context.py`
- `mapper.py`
- `outcome.py`

When changing an agent:

- decide whether it belongs on the chat lane or execution lane
- confirm its state updates still fit `CyberState`
- confirm persistence and downstream consumers still understand its outputs
- update the closest matching suite under `scripts/tests/`

Places you usually touch:

- `src/agents/<agent_name>/...`
- `src/graph/builder.py`
- `src/graph/router.py`
- `src/runtime/...` when the change affects shared runner behavior

## Configuration Reference

Core LLM:

- `OPENROUTER_API_KEY`
- `OPENROUTER_MODEL`
- `OPENROUTER_BASE_URL`
- `OPENROUTER_EMBEDDING_API_KEY`

Supervisor/runtime:

- `SUPERVISOR_TIMEOUT_SECONDS`
- `SUPERVISOR_REASONING_ENABLED`
- `SUPERVISOR_MAX_REASONING_MESSAGES`
- `SAIBER_TRACE_ENABLED`
- `SAIBER_TRACE_INCLUDE_RAW`
- `SAIBER_TRACE_MAX_CHARS`

Database:

- `DB_HOST`
- `DB_PORT`
- `DB_NAME`
- `DB_USER`
- `DB_PASSWORD`

Reporting:

- `REPORT_EXPORT_DIR`

Attackbox and safety:

- `ATTACKBOX_MCP_URL`
- `MSF_PASSWORD`
- `MSF_SERVER`
- `MSF_PORT`
- `MSF_SSL`
- `STRIKER_REQUIRE_CONFIRMATION`

RAG and embeddings:

- `EMBEDDING_PROVIDER`
- `EMBEDDING_MODEL`
- `EMBEDDING_DIMENSIONS`
- `EMBEDDING_TIMEOUT_SECONDS`
- `RAG_KB_TOP_K`
- `RAG_KB_FETCH_K`
- `RAG_FINDINGS_TOP_K`
- `RAG_FINDINGS_FETCH_K`
- `RAG_KB_SIMILARITY_THRESHOLD`
- `RAG_FINDINGS_SIMILARITY_THRESHOLD`
- `RAG_MIN_DOCS`
- `RAG_MIN_SCORE`
- `RAG_MAX_CHUNKS_PER_DOC`

External research:

- `TAVILY_API_KEY`
- `TAVILY_MAX_RESULTS`
