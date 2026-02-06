#!/bin/bash
# scripts/test_kali.sh

echo "==================================================="
echo "🧪 TESTING KALI MCP SERVER"
echo "==================================================="

echo "[1/3] Starting Kali MCP..."
docker-compose up -d kali-mcp

echo "[2/3] Waiting for Kali MCP to be healthy..."
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
    exit 1
fi

echo "[3/3] Testing API Endpoint..."
INTERNAL_TEST=$(docker exec vt-saiber-kali-mcp curl -s http://localhost:5000/health)

if [[ "$INTERNAL_TEST" == *"healthy"* ]]; then
    echo "✅ Health Check Passed: $INTERNAL_TEST"
else
    echo "❌ Health Check Failed."
    exit 1
fi