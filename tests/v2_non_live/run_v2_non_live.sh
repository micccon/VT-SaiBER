#!/bin/bash
# Run v2 non-live promotion tests inside the agents container.

set -euo pipefail

AGENTS_RUNNING=$(docker ps --filter "name=^vt-saiber-agents$" --filter "status=running" -q)

if [ -z "$AGENTS_RUNNING" ]; then
    echo "vt-saiber-agents is not running."
    echo "Start the stack with: docker compose up -d"
    exit 1
fi

docker exec -t vt-saiber-agents sh -lc \
    "cd /app && python3 -m pytest tests/v2_non_live -q"
