#!/bin/bash
# scripts/docker/start_msf_mcp.sh

# Exit on error
set -e

echo "=========================================="
echo "Starting Metasploit MCP Server"
echo "=========================================="

# -----------------------------------------------------------------------------
# 1. Start msfrpcd
# -----------------------------------------------------------------------------
echo ""
echo "[1/3] Starting msfrpcd..."

# Navigate to directory
cd /usr/src/metasploit-framework

# Start RPC daemon
# We do NOT capture PID because it changes (forks)
./msfrpcd -P ${MSF_PASSWORD:-mymsfrpcpassword} -S -a 0.0.0.0 -p 55553 &

# -----------------------------------------------------------------------------
# 2. Wait for Port 55553 (Robust Check)
# -----------------------------------------------------------------------------
echo ""
echo "[2/3] Waiting for msfrpcd to listen on port 55553..."

# Try to connect to the port every second for 60 seconds
RETRIES=120
READY=false

for i in $(seq 1 $RETRIES); do
    if nc -z localhost 55553; then
        echo "✅ Connection successful! msfrpcd is listening."
        READY=true
        break
    fi
    
    echo "   ... waiting ($i/$RETRIES)"
    sleep 1
done

if [ "$READY" = false ]; then
    echo "❌ ERROR: Timeout waiting for msfrpcd to start."
    echo "📋 TAILING METASPLOIT LOGS:"
    cat /root/.msf4/logs/framework.log || echo "No log file found."
    exit 1
fi

# -----------------------------------------------------------------------------
# 3. Start MCP Server
# -----------------------------------------------------------------------------
echo ""
echo "[3/3] Starting MCP HTTP server..."
cd /app/MetasploitMCP

# Ensure it listens on 0.0.0.0
python3 MetasploitMCP.py --transport http --host 0.0.0.0 --port 8085