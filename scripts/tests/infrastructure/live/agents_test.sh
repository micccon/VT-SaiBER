#!/bin/bash
# scripts/tests/infrastructure/live/agents_test.sh

echo "==================================================="
echo "🧪 TESTING AGENTS CONTAINER"
echo "==================================================="

echo "[1/4] Starting agents container..."
docker-compose up -d agents

echo "[2/4] Waiting for agents container to be running..."
RETRIES=30
while [ $RETRIES -gt 0 ]; do
    STATUS=$(docker inspect --format='{{.State.Status}}' vt-saiber-agents 2>/dev/null)
    if [ "$STATUS" == "running" ]; then
        echo "✅ Agents container is running!"
        break
    fi
    sleep 2
    ((RETRIES--))
done

if [ $RETRIES -eq 0 ]; then
    echo "❌ Timeout waiting for vt-saiber-agents to start."
    docker logs vt-saiber-agents
    exit 1
fi

echo "[3/4] Verifying Python runtime and app source..."
if docker exec vt-saiber-agents sh -lc "python3 --version > /dev/null && test -d /app/src"; then
    echo "✅ Python and /app/src are available."
else
    echo "❌ Python runtime or /app/src check failed."
    exit 1
fi

echo "[4/4] Verifying MCP connectivity from agents..."
if docker exec vt-saiber-agents python3 -c "import socket; socket.create_connection(('attackbox',8080),3).close(); print('ok')" > /dev/null; then
    echo "✅ Agents can reach attackbox:8080."
else
    echo "❌ Agents cannot reach attackbox MCP."
    exit 1
fi

echo ""
echo "==================================================="
echo "✅ ALL AGENTS CONTAINER TESTS PASSED"
echo "==================================================="
