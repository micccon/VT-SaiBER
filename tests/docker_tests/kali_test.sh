#!/bin/bash
# scripts/docker_tests/test_kali.sh

echo "==================================================="
echo "🧪 TESTING KALI MCP SERVER"
echo "==================================================="

echo "[1/4] Starting Kali MCP..."
docker-compose up -d kali-mcp

echo "[2/4] Waiting for Kali MCP to be healthy..."
RETRIES=30
while [ $RETRIES -gt 0 ]; do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' vt-saiber-kali-mcp 2>/dev/null)
    if [ "$STATUS" == "healthy" ]; then
        echo "✅ Kali MCP is healthy!"
        break
    fi
    sleep 2
    ((RETRIES--))
done

if [ $RETRIES -eq 0 ]; then
    echo "❌ Timeout waiting for Kali MCP."
    docker logs vt-saiber-kali-mcp
    exit 1
fi

echo "[3/4] Testing API Server (port 5000)..."
INTERNAL_TEST=$(docker exec vt-saiber-kali-mcp curl -s http://localhost:5000/health)

if [[ "$INTERNAL_TEST" == *"healthy"* ]]; then
    echo "✅ API Server Health Check Passed: $INTERNAL_TEST"
else
    echo "❌ API Server Health Check Failed."
    docker logs vt-saiber-kali-mcp
    exit 1
fi

echo "[4/4] Verifying MCP Bridge is running..."
# Check if mcp_server.py process is running
MCP_PROCESS=$(docker exec vt-saiber-kali-mcp ps aux | grep "mcp_server.py" | grep -v grep)

if [ ! -z "$MCP_PROCESS" ]; then
    echo "✅ MCP Bridge process is running"
    echo "   $MCP_PROCESS"
else
    echo "❌ MCP Bridge process not found"
    docker logs vt-saiber-kali-mcp
    exit 1
fi

echo ""
echo "==================================================="
echo "✅ ALL KALI MCP TESTS PASSED"
echo "==================================================="