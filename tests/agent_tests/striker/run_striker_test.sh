#!/bin/bash
# tests/agent_tests/striker/run_striker_test.sh
# Striker live integration test runner:
#   - real Kali MCP nmap scan
#   - real striker_node execution
#   - real Metasploit MCP tool calls
#
# Usage:
#   bash tests/agent_tests/striker/run_striker_test.sh --mode openrouter-nmap-trace
#   bash tests/agent_tests/striker/run_striker_test.sh --mode openrouter-nmap-trace --model "nvidia/nemotron-3-super-120b-a12b:free"
#
# Optional env overrides:
#   OPENROUTER_API_KEY
#   LLM_CLIENT
#   LLM_MODEL
#   STRIKER_REQUIRE_CONFIRMATION
#   STRIKER_MAX_INFO_CALLS
#   KALI_MCP_URL
#   MSF_MCP_URL

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$PROJECT_ROOT" ]]; then
  PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
fi
MODE="openrouter-nmap-trace"
MODEL_OVERRIDE=""

usage() {
  echo "Usage: $0 [--mode openrouter-nmap-trace] [--model MODEL]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="$2"
      shift 2
      ;;
    --model)
      MODEL_OVERRIDE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown arg: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ "$MODE" != "openrouter-nmap-trace" ]]; then
  echo "❌ Invalid mode '$MODE'. Expected: openrouter-nmap-trace"
  exit 1
fi

get_env_from_file() {
  local key="$1"
  local env_file="${PROJECT_ROOT}/.env"
  if [[ ! -f "$env_file" ]]; then
    echo ""
    return 0
  fi
  local raw
  raw="$(grep -E "^${key}=" "$env_file" | tail -n1 | cut -d= -f2- || true)"
  raw="${raw%\"}"
  raw="${raw#\"}"
  raw="${raw%\'}"
  raw="${raw#\'}"
  echo "$raw"
}

echo "======================================"
echo "🧪 STRIKER TEST RUNNER"
echo "   mode: $MODE"
echo "======================================"

echo ""
echo "🔍 Checking container status..."
AGENTS_RUNNING="$(docker ps --filter "name=vt-saiber-agents" --filter "status=running" -q)"
MSF_RUNNING="$(docker ps --filter "name=vt-saiber-msf-mcp" --filter "status=running" -q)"
KALI_RUNNING="$(docker ps --filter "name=vt-saiber-kali-mcp" --filter "status=running" -q)"

if [[ -z "$AGENTS_RUNNING" ]]; then
  echo "❌ vt-saiber-agents not running. Start with: docker compose up -d agents"
  exit 1
fi

if [[ -z "$MSF_RUNNING" ]]; then
  echo "❌ vt-saiber-msf-mcp not running. Start with: docker compose up -d msf-mcp"
  exit 1
fi

if [[ -z "$KALI_RUNNING" ]]; then
  echo "❌ vt-saiber-kali-mcp not running. Start with: docker compose up -d kali-mcp"
  exit 1
fi

echo "✅ Required containers are running"
TEST_FILE="test_striker_nmap_openrouter_trace.py"

DOCKER_EXEC_FLAGS="-t"
if [[ -t 0 ]]; then
  DOCKER_EXEC_FLAGS="-it"
fi

echo ""
echo "📋 Copying test script to container..."
REMOTE_TEST_DIR="/app/tests/agent_tests/striker"
docker exec vt-saiber-agents mkdir -p "${REMOTE_TEST_DIR}"
docker cp "${SCRIPT_DIR}/${TEST_FILE}" "vt-saiber-agents:${REMOTE_TEST_DIR}/${TEST_FILE}"

echo ""
echo "🚀 Running test..."
echo "   test: ${REMOTE_TEST_DIR}/${TEST_FILE}"
echo "======================================"
echo ""
OPENROUTER_API_KEY_VAL="${OPENROUTER_API_KEY:-$(get_env_from_file OPENROUTER_API_KEY)}"
LLM_CLIENT_VAL="${LLM_CLIENT:-$(get_env_from_file LLM_CLIENT)}"
LLM_MODEL_VAL="${LLM_MODEL:-$(get_env_from_file LLM_MODEL)}"
STRIKER_REQUIRE_CONFIRMATION_VAL="${STRIKER_REQUIRE_CONFIRMATION:-$(get_env_from_file STRIKER_REQUIRE_CONFIRMATION)}"
STRIKER_MAX_INFO_CALLS_VAL="${STRIKER_MAX_INFO_CALLS:-$(get_env_from_file STRIKER_MAX_INFO_CALLS)}"
KALI_MCP_URL_VAL="${KALI_MCP_URL:-$(get_env_from_file KALI_MCP_URL)}"
MSF_MCP_URL_VAL="${MSF_MCP_URL:-$(get_env_from_file MSF_MCP_URL)}"

if [[ -n "$MODEL_OVERRIDE" ]]; then
  LLM_MODEL_VAL="$MODEL_OVERRIDE"
fi

LLM_CLIENT_VAL="${LLM_CLIENT_VAL:-openrouter}"
LLM_MODEL_VAL="${LLM_MODEL_VAL:-nvidia/nemotron-3-super-120b-a12b:free}"
STRIKER_REQUIRE_CONFIRMATION_VAL="${STRIKER_REQUIRE_CONFIRMATION_VAL:-true}"
KALI_MCP_URL_VAL="${KALI_MCP_URL_VAL:-http://kali-mcp:5001}"
MSF_MCP_URL_VAL="${MSF_MCP_URL_VAL:-http://msf-mcp:8085}"

if [[ -z "$OPENROUTER_API_KEY_VAL" ]]; then
  echo "❌ OPENROUTER_API_KEY is not set (env or .env)."
  exit 1
fi

docker exec ${DOCKER_EXEC_FLAGS} \
  -e OPENROUTER_API_KEY="${OPENROUTER_API_KEY_VAL}" \
  -e LLM_CLIENT="${LLM_CLIENT_VAL}" \
  -e LLM_MODEL="${LLM_MODEL_VAL}" \
  -e STRIKER_REQUIRE_CONFIRMATION="${STRIKER_REQUIRE_CONFIRMATION_VAL}" \
  -e STRIKER_MAX_INFO_CALLS="${STRIKER_MAX_INFO_CALLS_VAL:-12}" \
  -e KALI_MCP_URL="${KALI_MCP_URL_VAL}" \
  -e MSF_MCP_URL="${MSF_MCP_URL_VAL}" \
  -e TARGET_HOST="${TARGET_HOST:-automotive-testbed}" \
  -e NMAP_SCAN_TYPE="${NMAP_SCAN_TYPE:--sS -sV -sC}" \
  -e NMAP_PORTS="${NMAP_PORTS:-}" \
  -e NMAP_ADDITIONAL_ARGS="${NMAP_ADDITIONAL_ARGS:--Pn -T4}" \
  vt-saiber-agents \
  python3 -u "${REMOTE_TEST_DIR}/${TEST_FILE}"
TEST_EXIT=$?

echo ""
if [[ $TEST_EXIT -eq 0 ]]; then
  echo "======================================"
  echo "✅ STRIKER TEST PASSED ($MODE)"
  echo "======================================"
else
  echo "======================================"
  echo "❌ STRIKER TEST FAILED ($MODE)"
  echo "======================================"
fi

exit $TEST_EXIT
