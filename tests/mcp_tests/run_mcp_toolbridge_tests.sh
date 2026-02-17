#!/bin/bash
# scripts/run_mcp_toolbridge_tests.sh
# Run MCP Bridge tests inside agents container

echo "======================================"
echo "🧪 MCP BRIDGE TESTS (SSE Architecture)"
echo "======================================"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Check if containers are running
echo "🔍 Checking container status..."
KALI_RUNNING=$(docker ps --filter "name=vt-saiber-kali-mcp" --filter "status=running" -q)
MSF_RUNNING=$(docker ps --filter "name=vt-saiber-msf-mcp" --filter "status=running" -q)
AGENTS_RUNNING=$(docker ps --filter "name=vt-saiber-agents" --filter "status=running" -q)

if [ -z "$KALI_RUNNING" ]; then
    echo "❌ Kali MCP container not running. Start with: docker-compose up -d kali-mcp"
    exit 1
fi

if [ -z "$MSF_RUNNING" ]; then
    echo "❌ MSF MCP container not running. Start with: docker-compose up -d msf-mcp"
    exit 1
fi

if [ -z "$AGENTS_RUNNING" ]; then
    echo "❌ Agents container not running. Start with: docker-compose up -d agents"
    exit 1
fi

echo "✅ All containers running"

# Copy test script into container
echo ""
echo "📋 Copying test script to container..."
docker cp "$SCRIPT_DIR/mcp_toolbridge_tests.py" vt-saiber-agents:/app/mcp_toolbridge_tests.py

if [ $? -ne 0 ]; then
    echo "❌ Failed to copy test script"
    exit 1
fi

# Run tests
echo ""
echo "🔍 Running tests..."
echo "======================================"
docker exec vt-saiber-agents python3 /app/mcp_toolbridge_tests.py

TEST_EXIT=$?

# Cleanup
echo ""
echo "🧹 Cleaning up..."
docker exec vt-saiber-agents rm -f /app/mcp_toolbridge_tests.py

# Exit with test result
if [ $TEST_EXIT -eq 0 ]; then
    echo ""
    echo "======================================"
    echo "✅ ALL TESTS PASSED"
    echo "======================================"
else
    echo ""
    echo "======================================"
    echo "❌ SOME TESTS FAILED"
    echo "======================================"
fi

exit $TEST_EXIT