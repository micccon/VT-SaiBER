#!/bin/bash
# scripts/docker/start_kali_mcp.sh

set -e

echo "=========================================="
echo "Starting Kali MCP Infrastructure"
echo "=========================================="

cd /app/kali-mcp

echo ""
echo "[1/3] Starting Kali REST API server (kali_server.py)..."

python3 kali_server.py --ip 0.0.0.0 --port 5000 &
KALI_REST_PID=$!

echo "   Started kali_server.py with PID $KALI_REST_PID"

echo ""
echo "[2/3] Waiting for Kali REST API to listen on port 5000..."

RETRIES=60
READY=false

for i in $(seq 1 $RETRIES); do
    if curl -f http://localhost:5000/health > /dev/null 2>&1; then
        echo "   Kali REST API is ready and healthy"
        READY=true
        break
    fi

    if [ $((i % 10)) -eq 0 ]; then
        echo "   ... still waiting ($i/$RETRIES)"
    fi
    sleep 1
done

if [ "$READY" = false ]; then
    echo "   ERROR: Timeout waiting for Kali REST API to start."
    exit 1
fi

echo ""
echo "[3/3] Starting Kali MCP server (SSE on port 5001)..."

exec python3 mcp_server.py \
    --server http://127.0.0.1:5000 \
    --host 0.0.0.0 \
    --port 5001
