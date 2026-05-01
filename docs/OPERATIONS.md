# Operations

This page covers the practical day-to-day VT-SaiBER workflow: running missions, working with reports, using the attackbox and automotive testbed, and resolving common failures.

## Running Missions

The core mission inputs are:

- `mission_goal`
- `target_scope`
- `mission_id`

Basic run:

```bash
python -m src.main \
  --mission-id demo-001 \
  --mission-goal "Perform scoped reconnaissance and exploit-path analysis" \
  --target-scope "automotive-testbed"
```

Resume-related flags:

- `--resume`
- `--thread-id`
- `--checkpoint-id`

## Reports and Exports

Export a report bundle for an existing mission:

```bash
python -m src.database.reporting.exporter --mission-id demo-001
```

By default, exports land under:

```text
exports/<mission_id>/
```

Typical bundle contents:

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

## Attackbox and Testbed

Main runtime services:

- `postgres`
- `knowledge_base`
- `attackbox`
- `agents`

Main attackbox endpoint:

```text
ATTACKBOX_MCP_URL=http://attackbox:8080/mcp
```

Automotive testbed helpers:

- `scripts/setup/testbed/setup_testbed.sh`
- `scripts/setup/testbed/start_testbed.sh`
- `scripts/setup/testbed/validate_testbed.sh`
- `scripts/setup/testbed/reset_testbed.sh`

## Troubleshooting

Docker stack issues:

```bash
docker compose ps
docker compose logs --tail 100
bash scripts/setup/docker/full_reset_startup.sh
```

Attackbox reachability checks:

```bash
docker logs vt-saiber-attackbox --tail 100
docker exec vt-saiber-agents python3 -c "import socket; socket.create_connection(('attackbox', 8080), 3).close()"
```

Database checks:

```bash
docker logs vt-saiber-postgres --tail 100
docker exec vt-saiber-postgres psql -U "$DB_USER" -d "$DB_NAME" -c "\l"
```

Testbed checks:

```bash
bash scripts/setup/testbed/validate_testbed.sh
docker logs automotive-testbed --tail 100
```
