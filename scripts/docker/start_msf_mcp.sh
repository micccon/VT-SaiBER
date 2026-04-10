#!/bin/bash
# scripts/docker/start_msf_mcp.sh

set -e

echo "=========================================="
echo "Starting Metasploit MCP Server"
echo "=========================================="

echo ""
echo "[1/3] Starting msfrpcd..."

cd /usr/src/metasploit-framework
./msfrpcd -P ${MSF_PASSWORD:-mymsfrpcpassword} -S -a 0.0.0.0 -p 55553 &

echo ""
echo "[2/3] Waiting for msfrpcd to listen on port 55553..."

RETRIES=120
READY=false

for i in $(seq 1 $RETRIES); do
    if nc -z localhost 55553; then
        echo "Connection successful! msfrpcd is listening."
        READY=true
        break
    fi

    echo "   ... waiting ($i/$RETRIES)"
    sleep 1
done

if [ "$READY" = false ]; then
    echo "ERROR: Timeout waiting for msfrpcd to start."
    echo "TAILING METASPLOIT LOGS:"
    cat /root/.msf4/logs/framework.log || echo "No log file found."
    exit 1
fi

echo ""
echo "[3/3] Starting MCP HTTP server..."
cd /app/MetasploitMCP

python3 MetasploitMCP.py --transport http --host 0.0.0.0 --port 8085
