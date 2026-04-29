#!/bin/bash
# Run the captured-evidence Striker live planning test inside the agents container.

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

echo "======================================"
echo "STRIKER CAPTURED-STATE LIVE TEST"
echo "======================================"
echo "Target source: pre-given evidence from output2.txt"
echo "Execution mode: planning only"
echo ""

AGENTS_RUNNING=$(docker ps --filter "name=^vt-saiber-agents$" --filter "status=running" -q)
ATTACKBOX_RUNNING=$(docker ps --filter "name=^vt-saiber-attackbox$" --filter "status=running" -q)

if [ -z "$AGENTS_RUNNING" ] || [ -z "$ATTACKBOX_RUNNING" ]; then
    echo "Required VT-SaiBER containers are not all running."
    echo "Start them with: docker compose up -d"
    exit 1
fi

docker exec -t \
    -e OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}" \
    -e OPENROUTER_EMBEDDING_API_KEY="${OPENROUTER_EMBEDDING_API_KEY:-}" \
    -e OPENROUTER_BASE_URL="${OPENROUTER_BASE_URL:-https://openrouter.ai/api/v1}" \
    -e OPENROUTER_MODEL="${OPENROUTER_MODEL:-}" \
    -e LLM_CLIENT="${LLM_CLIENT:-openrouter}" \
    -e LLM_MODEL="${LLM_MODEL:-nvidia/nemotron-3-super-120b-a12b:free}" \
    -e SUPERVISOR_MODEL="${SUPERVISOR_MODEL:-minimax/minimax-m2.5:free}" \
    -e SUPERVISOR_TIMEOUT_SECONDS="${SUPERVISOR_TIMEOUT_SECONDS:-90}" \
    -e STRIKER_REQUIRE_CONFIRMATION="${STRIKER_REQUIRE_CONFIRMATION:-true}" \
    -e ATTACKBOX_MCP_URL="${ATTACKBOX_MCP_URL:-http://attackbox:8080/mcp}" \
    vt-saiber-agents \
    python3 -u /app/tests/agent_tests/test_striker_automotive_captured_live.py
