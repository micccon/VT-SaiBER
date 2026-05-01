# Contributing to VT-SaiBER

This repo is organized for active iteration on orchestration, agent behavior, testing, and environment setup. The fastest way to stay productive is to use the current docs structure instead of relying on older handoff notes.

## Development Workflow

1. Create a branch for your work.
2. Keep changes scoped by subsystem when possible.
3. Prefer small, reviewable commits over broad mixed refactors.
4. Update docs when you change entrypoints, paths, behavior, or configuration.

## Repo Areas That Matter Most

- `src/runtime/`: shared execution/chat runtime, approvals, tracing
- `src/agents/`: specialist agent behavior and mapping logic
- `src/graph/`: orchestration flow and routing
- `src/database/`: persistence, reporting, and RAG
- `src/mcp/`: attackbox and Metasploit integration
- `scripts/setup/`: Docker and automotive testbed setup flows
- `scripts/tests/`: runtime, agent, infrastructure, and database tests

## Running Tests

Fast local slice:

```bash
python -m pytest scripts/tests/runtime scripts/tests/agents/unit scripts/tests/infrastructure/unit -q
```

Everything under the reorganized suite:

```bash
python -m pytest scripts/tests -q
```

Live tests are opt-in and expect real services, credentials, or containers:

```bash
python -m pytest scripts/tests/agents/live -m live -q
python -m pytest scripts/tests/infrastructure/live -m live -q
python -m pytest scripts/tests/database/live -m live -q
```

## Documentation Expectations

- Treat `README.md` as the product landing page.
- Treat `docs/README.md` as the canonical docs index.
- Keep active docs flat and easy to scan.
- Keep operator-facing instructions in `docs/OPERATIONS.md`.
- Keep contributor and architecture detail in `docs/DEVELOPMENT.md` and `docs/ARCHITECTURE.md`.
- Archive old or handoff-only material under `docs/archive/` instead of mixing it into active docs.

## Review Expectations

- Keep path references current: `scripts/setup/...`, `scripts/tests/...`, and `src/runtime/...`.
- Keep command examples runnable against the repo as it exists now.
- Keep environment variable references aligned with `.env.example` and `src/config.py`.

## Useful Entry Points

- `python cli.py`
- `python -m src.main`
- `python scripts/run_scenario.py --list`
- `python -m src.database.reporting.exporter --mission-id <id>`
