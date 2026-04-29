#!/bin/bash
# Run the minimal-state Striker live planning test inside the agents container.

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
echo "STRIKER MINIMAL LIVE TEST"
echo "======================================"
echo "Target source: tiny prebuilt state"
MODE_LABEL="planning-only"
if [ "${LIVE_STRIKER_INTERACTIVE_APPROVAL:-false}" = "true" ]; then
    MODE_LABEL="interactive approval"
elif [ "${LIVE_STRIKER_EXECUTE:-false}" = "true" ]; then
    MODE_LABEL="auto-approve"
fi
echo "Execution mode: $MODE_LABEL"
echo ""

AGENTS_RUNNING=$(docker ps --filter "name=^vt-saiber-agents$" --filter "status=running" -q)
ATTACKBOX_RUNNING=$(docker ps --filter "name=^vt-saiber-attackbox$" --filter "status=running" -q)

if [ -z "$AGENTS_RUNNING" ] || [ -z "$ATTACKBOX_RUNNING" ]; then
    echo "Required VT-SaiBER containers are not all running."
    echo "Start them with: docker compose up -d"
    exit 1
fi

DOCKER_TTY_ARGS=(-t)
if [ "${LIVE_STRIKER_INTERACTIVE_APPROVAL:-false}" = "true" ]; then
    DOCKER_TTY_ARGS=(-it)
fi

docker exec "${DOCKER_TTY_ARGS[@]}" \
    -e OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}" \
    -e OPENROUTER_EMBEDDING_API_KEY="${OPENROUTER_EMBEDDING_API_KEY:-}" \
    -e OPENROUTER_BASE_URL="${OPENROUTER_BASE_URL:-https://openrouter.ai/api/v1}" \
    -e OPENROUTER_MODEL="${OPENROUTER_MODEL:-}" \
    -e LLM_CLIENT="${LLM_CLIENT:-openrouter}" \
    -e LLM_MODEL="${LLM_MODEL:-nvidia/nemotron-3-super-120b-a12b:free}" \
    -e SUPERVISOR_MODEL="${SUPERVISOR_MODEL:-minimax/minimax-m2.5:free}" \
    -e SUPERVISOR_TIMEOUT_SECONDS="${SUPERVISOR_TIMEOUT_SECONDS:-90}" \
    -e STRIKER_REQUIRE_CONFIRMATION="${STRIKER_REQUIRE_CONFIRMATION:-true}" \
    -e LIVE_STRIKER_EXECUTE="${LIVE_STRIKER_EXECUTE:-false}" \
    -e LIVE_STRIKER_INTERACTIVE_APPROVAL="${LIVE_STRIKER_INTERACTIVE_APPROVAL:-false}" \
    -e ATTACKBOX_MCP_URL="${ATTACKBOX_MCP_URL:-http://attackbox:8080/mcp}" \
    -e LIVE_STRIKER_TIMEOUT_SECONDS="${LIVE_STRIKER_TIMEOUT_SECONDS:-180}" \
    -e LIVE_STRIKER_MINIMAL_TARGET="${LIVE_STRIKER_MINIMAL_TARGET:-172.20.0.5}" \
    vt-saiber-agents \
    python3 -u /app/tests/agent_tests/test_striker_minimal_live.py
