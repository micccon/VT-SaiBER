# Getting Started

This is the fastest path to a working VT-SaiBER environment and the main entrypoints you should know.

## Quick Start

1. Copy the environment template.

```bash
cp .env.example .env
```

2. Set the core values:

- `OPENROUTER_API_KEY`
- `OPENROUTER_MODEL`
- `DB_HOST`
- `DB_PORT`
- `DB_NAME`
- `DB_USER`
- `DB_PASSWORD`
- `ATTACKBOX_MCP_URL`

3. Start the main stack.

```bash
bash scripts/setup/docker/full_reset_startup.sh
```

4. Start the automotive testbed if you want the full demo environment.

```bash
bash scripts/setup/testbed/setup_testbed.sh
```

5. Run a mission.

```bash
python -m src.main \
  --mission-id demo-001 \
  --mission-goal "Perform scoped reconnaissance and exploit-path analysis" \
  --target-scope "automotive-testbed"
```

6. Export a mission bundle.

```bash
python -m src.database.reporting.exporter --mission-id demo-001
```

## Environment Notes

- `REPORT_EXPORT_DIR` defaults to `exports`
- the Compose stack starts `postgres`, `knowledge_base`, `attackbox`, and `agents`
- `knowledge_base` syncs `src/database/testbed_docs`
- automotive testbed scripts assume a Linux environment that can support `vcan`

## Main Entrypoints

- `python cli.py`: interactive setup, demos, status, and utility flow
- `python -m src.main`: direct orchestration entrypoint
- `python -m src.database.reporting.exporter`: export reports for an existing mission
- `python scripts/run_scenario.py --list`: curated demo and validation scenarios
