#!/bin/bash
#
# validate_setup.sh - Verify the automotive pentesting testbed is properly configured
#
# This script checks:
# - vcan0 interface is UP
# - All required services are running
# - API endpoints respond correctly
#

set -uo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Print functions
pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASSED=$((PASSED + 1))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAILED=$((FAILED + 1))
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    WARNINGS=$((WARNINGS + 1))
}

info() {
    echo -e "[ -- ] $1"
}

echo "========================================"
echo " Automotive Pentesting Testbed Validator"
echo "========================================"
echo ""

# ----------------------------------------
# Check 1: vcan0 interface
# ----------------------------------------
info "Checking vcan0 interface..."
if ip link show vcan0 &>/dev/null; then
    STATE=$(ip link show vcan0 | grep -o 'state [A-Z]*' | awk '{print $2}')
    if [ "$STATE" = "UP" ] || [ "$STATE" = "UNKNOWN" ]; then
        pass "vcan0 interface is UP"
    else
        fail "vcan0 interface exists but is DOWN (state: $STATE)"
    fi
else
    fail "vcan0 interface does not exist"
fi

# ----------------------------------------
# Check 2: Supervisord running
# ----------------------------------------
info "Checking supervisord..."
if pgrep -x supervisord &>/dev/null; then
    pass "supervisord is running"
else
    fail "supervisord is not running"
fi

# ----------------------------------------
# Check 3: Required services via supervisorctl
# ----------------------------------------
REQUIRED_SERVICES="sshd validation-api infotainment gateway"
OPTIONAL_SERVICES="icsim icsim-controls obd"

info "Checking required services..."
for service in $REQUIRED_SERVICES; do
    if supervisorctl status "$service" 2>/dev/null | grep -q "RUNNING"; then
        pass "$service is RUNNING"
    else
        fail "$service is not running"
    fi
done

info "Checking optional services..."
for service in $OPTIONAL_SERVICES; do
    STATUS=$(supervisorctl status "$service" 2>/dev/null | awk '{print $2}')
    if [ "$STATUS" = "RUNNING" ]; then
        pass "$service is RUNNING"
    elif [ "$service" = "obd" ]; then
        warn "$service is not running (optional - may crash during buffer overflow testing)"
    else
        warn "$service is not running (optional - requires DISPLAY)"
    fi
done

# ----------------------------------------
# Check 4: SSH port listening
# ----------------------------------------
info "Checking SSH port (22)..."
if ss -tlnp 2>/dev/null | grep -q ':22 '; then
    pass "SSH is listening on port 22"
else
    fail "SSH is not listening on port 22"
fi

# ----------------------------------------
# Check 5: Validation API responding
# ----------------------------------------
info "Checking Validation API (port 9999)..."
if curl -sf http://localhost:9999/ >/dev/null 2>&1; then
    RESPONSE=$(curl -sf http://localhost:9999/ 2>/dev/null)
    if echo "$RESPONSE" | grep -q '"status"'; then
        pass "Validation API is responding on port 9999"
    else
        fail "Validation API returned unexpected response"
    fi
else
    fail "Validation API is not responding on port 9999"
fi

# Check /status endpoint
info "Checking Validation API /status endpoint..."
if curl -sf http://localhost:9999/status >/dev/null 2>&1; then
    RESPONSE=$(curl -sf http://localhost:9999/status 2>/dev/null)
    if echo "$RESPONSE" | grep -q '"timestamp"' && echo "$RESPONSE" | grep -q '"services"'; then
        pass "Validation API /status endpoint is working"
    else
        fail "Validation API /status returned unexpected format"
    fi
else
    fail "Validation API /status endpoint not responding"
fi

# ----------------------------------------
# Check 6: Infotainment app responding
# ----------------------------------------
info "Checking Infotainment app (port 8000)..."
if curl -sf http://localhost:8000/ >/dev/null 2>&1; then
    pass "Infotainment app is responding on port 8000"
else
    fail "Infotainment app is not responding on port 8000"
fi

# Check /login endpoint
info "Checking Infotainment /login endpoint..."
if curl -sf http://localhost:8000/login >/dev/null 2>&1; then
    RESPONSE=$(curl -sf http://localhost:8000/login 2>/dev/null)
    if echo "$RESPONSE" | grep -qi "login\|username\|password"; then
        pass "Infotainment /login endpoint is working"
    else
        fail "Infotainment /login returned unexpected response"
    fi
else
    fail "Infotainment /login endpoint not responding"
fi

# ----------------------------------------
# Check 7: Gateway service responding
# ----------------------------------------
info "Checking Gateway service (port 8080)..."
if curl -sf http://localhost:8080/ >/dev/null 2>&1; then
    RESPONSE=$(curl -sf http://localhost:8080/ 2>/dev/null)
    if echo "$RESPONSE" | grep -q '"status"'; then
        pass "Gateway service is responding on port 8080"
    else
        fail "Gateway service returned unexpected response"
    fi
else
    fail "Gateway service is not responding on port 8080"
fi

# ----------------------------------------
# Check 8: OBD service accepting connections (optional)
# ----------------------------------------
info "Checking OBD service (port 9555)..."
if ss -tlnp 2>/dev/null | grep -q ':9555 '; then
    pass "OBD service is listening on port 9555"
else
    warn "OBD service is not listening on port 9555 (optional - may crash during exploitation)"
fi

# ----------------------------------------
# Check 9: Log directory exists and is writable
# ----------------------------------------
info "Checking log directory..."
LOG_DIR="/var/log/automotive-pentest"
if [ -d "$LOG_DIR" ]; then
    if [ -w "$LOG_DIR" ]; then
        pass "Log directory exists and is writable"
    else
        fail "Log directory exists but is not writable"
    fi
else
    fail "Log directory does not exist: $LOG_DIR"
fi

# ----------------------------------------
# Summary
# ----------------------------------------
echo ""
echo "========================================"
echo " Validation Summary"
echo "========================================"
echo -e " ${GREEN}Passed:${NC}   $PASSED"
echo -e " ${RED}Failed:${NC}   $FAILED"
echo -e " ${YELLOW}Warnings:${NC} $WARNINGS"
echo "========================================"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}SUCCESS: All required checks passed!${NC}"
    if [ $WARNINGS -gt 0 ]; then
        echo -e "${YELLOW}Note: Some optional services have warnings (see above).${NC}"
    fi
    exit 0
else
    echo -e "${RED}FAILURE: $FAILED check(s) failed. Please review the errors above.${NC}"
    exit 1
fi
