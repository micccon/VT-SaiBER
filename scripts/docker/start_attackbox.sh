#!/bin/bash

set -e

echo "=========================================="
echo "Starting VT-SaiBER Attackbox"
echo "=========================================="

echo ""
echo "[1/3] Starting msfrpcd..."
cd /usr/share/metasploit-framework || cd /usr/src/metasploit-framework
./msfrpcd -P "${MSF_PASSWORD:-mymsfrpcpassword}" -S -a 0.0.0.0 -p "${MSF_PORT:-55553}" &

echo ""
echo "[2/3] Waiting for msfrpcd to listen on port ${MSF_PORT:-55553}..."

RETRIES=120
READY=false

for i in $(seq 1 $RETRIES); do
    if nc -z localhost "${MSF_PORT:-55553}"; then
        echo "   msfrpcd is ready."
        READY=true
        break
    fi

    if [ $((i % 10)) -eq 0 ]; then
        echo "   ... still waiting ($i/$RETRIES)"
    fi
    sleep 1
done

if [ "$READY" = false ]; then
    echo "   ERROR: Timeout waiting for msfrpcd to start."
    exit 1
fi

echo ""
echo "[3/3] Starting unified attackbox MCP server..."
cd /app

exec python3 -m src.mcp.attackbox_server
