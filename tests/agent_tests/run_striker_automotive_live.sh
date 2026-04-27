#!/bin/bash
# Run the striker-only automotive live test inside the agents container.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"
ENV_FILE="${ENV_FILE:-$REPO_ROOT/.env}"
TARGET_HOST="${TARGET_HOST:-automotive-testbed}"
LIVE_STRIKER_EXECUTE="${LIVE_STRIKER_EXECUTE:-true}"
LIVE_STRIKER_PORTS="${LIVE_STRIKER_PORTS:-22,80,443,8000,8080,9555,9556,9999}"
LIVE_STRIKER_SCAN_TYPE="${LIVE_STRIKER_SCAN_TYPE:--sV}"
LIVE_STRIKER_EXTRA_ARGS="${LIVE_STRIKER_EXTRA_ARGS:--T4}"
LIVE_STRIKER_KB_TOP_K="${LIVE_STRIKER_KB_TOP_K:-5}"

detect_shared_network() {
    local preferred="vt-saiber-network"
    local candidate=""

    if docker network inspect "$preferred" >/dev/null 2>&1; then
        echo "$preferred"
        return 0
    fi

    candidate=$(docker network ls --format '{{.Name}}' | grep -E '(^|_)vt-saiber-network$' | head -n1 || true)
    if [ -n "$candidate" ]; then
        echo "$candidate"
        return 0
    fi

    candidate=$(docker network ls --format '{{.Name}}' | grep -E 'vt[-_]?saiber.*network' | head -n1 || true)
    if [ -n "$candidate" ]; then
        echo "$candidate"
        return 0
    fi

    return 1
}

if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
else
    echo "Missing env file: $ENV_FILE"
    exit 1
fi

if ! SHARED_NETWORK="$(detect_shared_network)"; then
    echo "Could not find a VT-SaiBER shared network."
    echo "Start the stack first: docker compose up -d"
    exit 1
fi

echo "======================================"
echo "STRIKER AUTOMOTIVE LIVE TEST"
echo "======================================"
echo "Target: $TARGET_HOST"
echo "Execute live exploit: $LIVE_STRIKER_EXECUTE"
echo ""

AGENTS_RUNNING=$(docker ps --filter "name=^vt-saiber-agents$" --filter "status=running" -q)
POSTGRES_RUNNING=$(docker ps --filter "name=^vt-saiber-postgres$" --filter "status=running" -q)
ATTACKBOX_RUNNING=$(docker ps --filter "name=^vt-saiber-attackbox$" --filter "status=running" -q)
TESTBED_RUNNING=$(docker ps --filter "name=^automotive-testbed$" --filter "status=running" -q)

if [ -z "$AGENTS_RUNNING" ] || [ -z "$POSTGRES_RUNNING" ] || [ -z "$ATTACKBOX_RUNNING" ]; then
    echo "Required VT-SaiBER containers are not all running."
    echo "Start them with: docker compose up -d"
    exit 1
fi

if [ -z "$TESTBED_RUNNING" ]; then
    echo "automotive-testbed is not running."
    echo "Start it with: bash scripts/testbed/start_testbed.sh"
    exit 1
fi

ON_NETWORK=$(docker inspect automotive-testbed \
    --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null \
    | grep -c -- "$SHARED_NETWORK" || true)

if [ "$ON_NETWORK" -eq 0 ]; then
    echo "Connecting automotive-testbed to $SHARED_NETWORK ..."
    docker network connect "$SHARED_NETWORK" automotive-testbed 2>/dev/null || true
fi

if ! docker exec vt-saiber-agents python -c "import socket; socket.gethostbyname('$TARGET_HOST')"; then
    TARGET_IP=$(docker network inspect "$SHARED_NETWORK" \
        --format '{{range $id,$c := .Containers}}{{if eq $c.Name "automotive-testbed"}}{{$c.IPv4Address}}{{end}}{{end}}' \
        2>/dev/null | cut -d/ -f1)
    if [ -z "$TARGET_IP" ]; then
        echo "Could not determine automotive-testbed IP on $SHARED_NETWORK"
        exit 1
    fi
    TARGET_HOST="$TARGET_IP"
fi

echo "Resolved target: $TARGET_HOST"
echo ""

docker exec -t \
    -e OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}" \
    -e OPENROUTER_BASE_URL="${OPENROUTER_BASE_URL:-https://openrouter.ai/api/v1}" \
    -e STRIKER_API_KEY="${STRIKER_API_KEY:-}" \
    -e STRIKER_MODEL="${STRIKER_MODEL:-}" \
    -e LLM_CLIENT="${LLM_CLIENT:-openrouter}" \
    -e LLM_MODEL="${LLM_MODEL:-nvidia/nemotron-3-super-120b-a12b:free}" \
    -e SUPERVISOR_MODEL="${SUPERVISOR_MODEL:-minimax/minimax-m2.5:free}" \
    -e SUPERVISOR_TIMEOUT_SECONDS="${SUPERVISOR_TIMEOUT_SECONDS:-90}" \
    -e STRIKER_REQUIRE_CONFIRMATION="${STRIKER_REQUIRE_CONFIRMATION:-true}" \
    -e DB_HOST="${DB_HOST:-postgres}" \
    -e DB_PORT="${DB_PORT:-5432}" \
    -e DB_NAME="${DB_NAME:-vtsaiber}" \
    -e DB_USER="${DB_USER:-vtsaiber}" \
    -e DB_PASSWORD="${DB_PASSWORD:-}" \
    -e ATTACKBOX_MCP_URL="${ATTACKBOX_MCP_URL:-http://attackbox:8080/mcp}" \
    -e TARGET_HOST="$TARGET_HOST" \
    -e LIVE_STRIKER_TARGET="$TARGET_HOST" \
    -e LIVE_STRIKER_PORTS="$LIVE_STRIKER_PORTS" \
    -e LIVE_STRIKER_SCAN_TYPE="$LIVE_STRIKER_SCAN_TYPE" \
    -e LIVE_STRIKER_EXTRA_ARGS="$LIVE_STRIKER_EXTRA_ARGS" \
    -e LIVE_STRIKER_EXECUTE="$LIVE_STRIKER_EXECUTE" \
    -e LIVE_STRIKER_KB_TOP_K="$LIVE_STRIKER_KB_TOP_K" \
    vt-saiber-agents \
    python3 -u /app/tests/agent_tests/test_striker_automotive_live.py
