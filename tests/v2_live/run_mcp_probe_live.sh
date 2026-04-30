#!/bin/bash
# Run the direct attackbox MCP probe test inside the agents container.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/.env}"

if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
fi

if ! docker ps --filter "name=^vt-saiber-agents$" --filter "status=running" -q | grep -q .; then
    echo "vt-saiber-agents is not running. Start it with: docker compose up -d"
    exit 1
fi
if ! docker ps --filter "name=^vt-saiber-attackbox$" --filter "status=running" -q | grep -q .; then
    echo "vt-saiber-attackbox is not running. Start it with: docker compose up -d"
    exit 1
fi

docker exec -t \
    -e ATTACKBOX_MCP_URL="${ATTACKBOX_MCP_URL:-http://attackbox:8080/mcp}" \
    vt-saiber-agents sh -lc \
    "cd /app && python3 -m pytest tests/v2_live/test_mcp_direct_probe_live.py -q -s --log-cli-level=INFO"
