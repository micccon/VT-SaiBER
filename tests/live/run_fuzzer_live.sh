#!/bin/bash
# Run the live fuzzer test inside the agents container.

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
    -e SAIBER_TRACE_ENABLED="${SAIBER_TRACE_ENABLED:-true}" \
    -e SAIBER_TRACE_INCLUDE_RAW="${SAIBER_TRACE_INCLUDE_RAW:-false}" \
    -e SAIBER_TRACE_MAX_CHARS="${SAIBER_TRACE_MAX_CHARS:-2000}" \
    -e OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}" \
    -e OPENROUTER_BASE_URL="${OPENROUTER_BASE_URL:-https://openrouter.ai/api/v1}" \
    -e OPENROUTER_MODEL="${OPENROUTER_MODEL:-}" \
    -e ATTACKBOX_MCP_URL="${ATTACKBOX_MCP_URL:-http://attackbox:8080/mcp}" \
    -e MCP_ATTACKBOX_URL="${MCP_ATTACKBOX_URL:-${ATTACKBOX_MCP_URL:-http://attackbox:8080/mcp}}" \
    vt-saiber-agents sh -lc \
    "cd /app && python3 -m pytest tests/live/test_fuzzer_live.py -q --log-cli-level=INFO --log-cli-format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'"
