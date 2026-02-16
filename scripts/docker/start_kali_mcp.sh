#!/bin/bash
# docker/start_kali_mcp.sh

# Exit on error
set -e

echo "=========================================="
echo "Starting Kali MCP Server"
echo "=========================================="
echo "Binary: /usr/bin/kali-server-mcp"
echo "Host:   0.0.0.0 (Public)"
echo "Port:   5000"
echo "=========================================="

# -----------------------------------------------------------------------------
# Start the Server
# -----------------------------------------------------------------------------
# We discovered the binary is at /usr/bin/kali-server-mcp
# We bind to 0.0.0.0 so the Agents can reach it.
# We don't need 'nc' because we aren't waiting for a background process anymore.

exec /usr/bin/kali-server-mcp --port 5000 --ip 0.0.0.0 --debug