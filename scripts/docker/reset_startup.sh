#!/bin/bash
# scripts/validate_testbed.sh

echo "==================================================="
echo "🚀 VT-SaiBER FULL SYSTEM REBUILD & VALIDATION"
echo "==================================================="

# 1. Aggressive Cleanup
echo "[1/4] Performing aggressive cleanup..."
echo "   👉 Removing orphans..."
docker-compose down --remove-orphans 2>/dev/null

echo "   👉 Pruning build cache..."
docker builder prune -f > /dev/null

# 2. Start Environment with Build
echo "[2/4] Building and starting full stack..."

# Capture the exit code. If build fails, STOP HERE.
if ! docker-compose up --build -d; then
    echo "❌ ERROR: Docker Build failed! Check the output above."
    exit 1
fi

# 3. Wait for ALL containers to be healthy
echo "[3/4] Waiting for all services to be healthy..."
services=("vt-saiber-postgres" "vt-saiber-kali-mcp" "vt-saiber-msf-mcp")

for container in "${services[@]}"; do
    echo "   ⏳ Checking $container..."
    RETRIES=150
    while [ $RETRIES -gt 0 ]; do
        # Check Health Status
        HEALTH_STATUS=$(docker inspect --format='{{.State.Health.Status}}' $container 2>/dev/null)
        # Check if it crashed (Exited)
        RUNNING_STATUS=$(docker inspect --format='{{.State.Status}}' $container 2>/dev/null)

        if [ "$HEALTH_STATUS" == "healthy" ]; then
            echo "      ✅ $container is healthy."
            break
        fi

        # FAST FAIL: If container is dead, stop waiting and show logs immediately
        if [ "$RUNNING_STATUS" == "exited" ] || [ "$RUNNING_STATUS" == "dead" ]; then
            echo "      ❌ $container CRASHED unexpectedly (Status: $RUNNING_STATUS)."
            echo "      📋 SHOWING LOGS FOR $container:"
            echo "---------------------------------------------------"
            docker logs $container --tail 50
            echo "---------------------------------------------------"
            exit 1
        fi

        sleep 2
        ((RETRIES--))
    done
    
    if [ $RETRIES -eq 0 ]; then
        echo "      ❌ Timeout waiting for $container (Status: $HEALTH_STATUS)."
        echo "      📋 SHOWING LOGS:"
        docker logs $container --tail 20
        exit 1
    fi
done

# 4. Connectivity Tests (From Agents Container)
echo "[4/4] Testing Inter-Container Connectivity..."

# Helper function to run test and show error on failure
run_test() {
    description=$1
    command=$2
    
    echo "   👉 $description..."
    # Capture output (stderr and stdout)
    OUTPUT=$(eval "$command" 2>&1)
    EXIT_CODE=$?

    if [ $EXIT_CODE -eq 0 ]; then
        echo "      ✅ Success"
    else
        echo "      ❌ FAILED."
        echo "      🔍 ERROR DETAILS:"
        echo "$OUTPUT" | sed 's/^/         /' # Indent output
        return 1
    fi
}

FAIL=0

# Test Agents -> Kali
# Removing -s so we see errors, but capturing them in variable
run_test "Testing Agents -> Kali MCP" \
    "docker exec vt-saiber-agents curl -v --fail http://kali-mcp:5000/health" || FAIL=1

# Test Agents -> Metasploit
run_test "Testing Agents -> Metasploit MCP" \
    "docker exec vt-saiber-agents curl -v --fail http://msf-mcp:8085/docs" || FAIL=1

# Test Agents -> Postgres (Using Python Socket)
run_test "Testing Agents -> PostgreSQL (Port Check)" \
    "docker exec vt-saiber-agents python3 -c \"import socket; socket.create_connection(('vt-saiber-postgres', 5432))\"" || FAIL=1

if [ "$FAIL" -ne 0 ]; then
    echo "==================================================="
    echo "❌ SYSTEM VALIDATION FAILED"
    echo "==================================================="
    exit 1
else
    echo "==================================================="
    echo "🎉 ALL SYSTEMS GO - READY FOR DEVELOPMENT"
    echo "==================================================="
    exit 0
fi