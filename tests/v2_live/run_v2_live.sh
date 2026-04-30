#!/bin/bash
# Run opt-in v2 live tests inside the agents container.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/.env}"

if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
else
    echo "Missing env file: $ENV_FILE"
    exit 1
fi

AGENTS_RUNNING=$(docker ps --filter "name=^vt-saiber-agents$" --filter "status=running" -q)

if [ -z "$AGENTS_RUNNING" ]; then
    echo "vt-saiber-agents is not running."
    echo "Start the stack with: docker compose up -d"
    exit 1
fi

if [ "${RUN_V2_LIVE_MCP_TESTS:-0}" = "1" ]; then
    ATTACKBOX_RUNNING=$(docker ps --filter "name=^vt-saiber-attackbox$" --filter "status=running" -q)
    if [ -z "$ATTACKBOX_RUNNING" ]; then
        echo "RUN_V2_LIVE_MCP_TESTS=1 requires vt-saiber-attackbox to be running."
        echo "Start the stack with: docker compose up -d"
        exit 1
    fi
fi

docker exec -t \
    -e RUN_V2_LIVE_TESTS="${RUN_V2_LIVE_TESTS:-1}" \
    -e RUN_V2_LIVE_MCP_TESTS="${RUN_V2_LIVE_MCP_TESTS:-0}" \
    -e V2_TRACE_ENABLED="${V2_TRACE_ENABLED:-true}" \
    -e V2_TRACE_INCLUDE_RAW="${V2_TRACE_INCLUDE_RAW:-false}" \
    -e V2_TRACE_MAX_CHARS="${V2_TRACE_MAX_CHARS:-2000}" \
    -e LOG_LEVEL="${LOG_LEVEL:-INFO}" \
    -e OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}" \
    -e OPENROUTER_BASE_URL="${OPENROUTER_BASE_URL:-https://openrouter.ai/api/v1}" \
    -e OPENROUTER_MODEL="${OPENROUTER_MODEL:-}" \
    -e SUPERVISOR_TIMEOUT_SECONDS="${SUPERVISOR_TIMEOUT_SECONDS:-90}" \
    -e SAIBER_GRAPH_VERSION="${SAIBER_GRAPH_VERSION:-v2}" \
    -e TARGET_HOST="${TARGET_HOST:-}" \
    -e TARGET_SCOPE="${TARGET_SCOPE:-}" \
    -e LIVE_TARGET_SCOPE="${LIVE_TARGET_SCOPE:-}" \
    -e LIVE_SCOUT_TARGET="${LIVE_SCOUT_TARGET:-}" \
    -e LIVE_FUZZER_BASE_URL="${LIVE_FUZZER_BASE_URL:-}" \
    -e LIVE_FUZZER_TARGET="${LIVE_FUZZER_TARGET:-}" \
    -e LIVE_FUZZER_PORT="${LIVE_FUZZER_PORT:-80}" \
    -e LIVE_FUZZER_SERVICE_VERSION="${LIVE_FUZZER_SERVICE_VERSION:-}" \
    -e LIVE_STRIKER_TARGET="${LIVE_STRIKER_TARGET:-}" \
    -e LIVE_STRIKER_BASE_URL="${LIVE_STRIKER_BASE_URL:-}" \
    -e LIVE_STRIKER_EXECUTE="${LIVE_STRIKER_EXECUTE:-false}" \
    -e LIVE_RESIDENT_SESSION_ID="${LIVE_RESIDENT_SESSION_ID:-}" \
    -e LIVE_RESIDENT_TARGET="${LIVE_RESIDENT_TARGET:-}" \
    -e ATTACKBOX_MCP_URL="${ATTACKBOX_MCP_URL:-http://attackbox:8080/mcp}" \
    -e MCP_ATTACKBOX_URL="${MCP_ATTACKBOX_URL:-http://attackbox:8000/mcp}" \
    -e DB_HOST="${DB_HOST:-postgres}" \
    -e DB_PORT="${DB_PORT:-5432}" \
    -e DB_NAME="${DB_NAME:-vtsaiber}" \
    -e DB_USER="${DB_USER:-vtsaiber}" \
    -e DB_PASSWORD="${DB_PASSWORD:-}" \
    vt-saiber-agents sh -lc \
    "cd /app && python3 -m pytest tests/v2_live -q --log-cli-level=INFO --log-cli-format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'"
