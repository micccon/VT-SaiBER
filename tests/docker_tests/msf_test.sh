#!/bin/bash
# scripts/test_msf.sh

echo "==================================================="
echo "🧪 TESTING METASPLOIT MCP SERVER"
echo "==================================================="

echo "[1/3] Starting Metasploit MCP..."
docker-compose up -d msf-mcp

echo "[2/3] Waiting for Metasploit MCP to be healthy..."
RETRIES=60
while [ $RETRIES -gt 0 ]; do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' vt-saiber-msf-mcp 2>/dev/null)
    if [ "$STATUS" == "healthy" ]; then
        echo "✅ Metasploit MCP is healthy!"
        break
    fi
    sleep 2
    ((RETRIES--))
done

if [ $RETRIES -eq 0 ]; then
    echo "❌ Timeout waiting for Metasploit MCP."
    docker logs vt-saiber-msf-mcp
    exit 1
fi

echo "[3/3] Testing API Endpoint..."

# We use -f (fail) so curl returns an error code if the page doesn't load (e.g. 404 or 500)
# We throw away the HTML output (> /dev/null) because we only care if it succeeds
if docker exec vt-saiber-msf-mcp curl -f -s http://localhost:8085/docs > /dev/null; then
    echo "✅ Health Check Passed: API Docs are accessible."
else
    echo "❌ Health Check Failed: Could not reach /docs endpoint."
    exit 1
fi