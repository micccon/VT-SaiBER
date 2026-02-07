#!/bin/bash
# Test both MCP clients - Copy, Run, Cleanup

echo "======================================"
echo "🧪 VT-SaiBER MCP CLIENT TESTS"
echo "======================================"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Copy test scripts into container
echo "📋 Copying test scripts into agents container..."
docker cp "$SCRIPT_DIR/kali_mcp_test.py" vt-saiber-agents:/tmp/kali_mcp_test.py
docker cp "$SCRIPT_DIR/msf_mcp_test.py" vt-saiber-agents:/tmp/msf_mcp_test.py

# Run Kali tests
echo ""
echo "🔍 Testing Kali MCP Client..."
docker exec vt-saiber-agents python3 /tmp/kali_mcp_test.py
KALI_EXIT=$?

# Run MSF tests
echo ""
echo "🔍 Testing MSF MCP Client..."
docker exec vt-saiber-agents python3 /tmp/msf_mcp_test.py
MSF_EXIT=$?

# Cleanup
echo ""
echo "🧹 Cleaning up test files..."
docker exec vt-saiber-agents rm -f /tmp/kali_mcp_test.py /tmp/msf_mcp_test.py

# Summary
echo ""
echo "======================================"
if [ $KALI_EXIT -eq 0 ] && [ $MSF_EXIT -eq 0 ]; then
    echo "✅ ALL TESTS PASSED"
    exit 0
else
    echo "❌ SOME TESTS FAILED"
    echo "   Kali: $([ $KALI_EXIT -eq 0 ] && echo '✅' || echo '❌')"
    echo "   MSF:  $([ $MSF_EXIT -eq 0 ] && echo '✅' || echo '❌')"
    exit 1
fi