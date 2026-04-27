#!/bin/bash
# tests/mcp_tests/run_mcp_toolbridge_tests.sh
# Run MCP bridge tests inside the agents container.

echo "======================================"
echo "MCP BRIDGE TESTS (Attackbox Architecture)"
echo "======================================"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Checking container status..."
ATTACKBOX_RUNNING=$(docker ps --filter "name=vt-saiber-attackbox" --filter "status=running" -q)
AGENTS_RUNNING=$(docker ps --filter "name=vt-saiber-agents" --filter "status=running" -q)

if [ -z "$ATTACKBOX_RUNNING" ]; then
    echo "Attackbox container not running. Start with: docker compose up -d attackbox"
    exit 1
fi

if [ -z "$AGENTS_RUNNING" ]; then
    echo "Agents container not running. Start with: docker compose up -d agents"
    exit 1
fi

echo "Attackbox and agents containers are running"
echo ""
echo "Copying test script to container..."
docker cp "$SCRIPT_DIR/mcp_toolbridge_tests.py" vt-saiber-agents:/app/mcp_toolbridge_tests.py

if [ $? -ne 0 ]; then
    echo "Failed to copy test script"
    exit 1
fi

echo ""
echo "Running tests..."
echo "======================================"
docker exec vt-saiber-agents python3 /app/mcp_toolbridge_tests.py
TEST_EXIT=$?

echo ""
echo "Cleaning up..."
docker exec vt-saiber-agents rm -f /app/mcp_toolbridge_tests.py

if [ $TEST_EXIT -eq 0 ]; then
    echo ""
    echo "======================================"
    echo "ALL TESTS PASSED"
    echo "======================================"
else
    echo ""
    echo "======================================"
    echo "SOME TESTS FAILED"
    echo "======================================"
fi

exit $TEST_EXIT
