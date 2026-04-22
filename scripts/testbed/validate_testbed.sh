#!/usr/bin/env bash
# =============================================================================
# validate_testbed.sh
# Validates that the automotive testbed is running correctly and is reachable
# from within the VT-SaiBER Docker network.
#
# Usage:
#   bash scripts/testbed/validate_testbed.sh
#
# Exit codes:
#   0 - all core checks passed
#   1 - one or more checks failed
# =============================================================================

set -uo pipefail

cd "$(dirname "$0")"

CONTAINER_NAME="automotive-testbed"
SHARED_NETWORK="vt-saiber-network"
VALIDATION_URL="http://localhost:9999"
PASS=0
FAIL=1
overall=0

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*" >&2; overall=1; }
header() { echo ""; echo "--- $* ---"; }

# -----------------------------------------------------------------------------
# Check 1: Container running
# -----------------------------------------------------------------------------
header "Container status"
if docker ps --filter "name=^${CONTAINER_NAME}$" --filter "status=running" --format "{{.Names}}" \
    | grep -q "^${CONTAINER_NAME}$"; then
    pass "$CONTAINER_NAME is running."
else
    fail "$CONTAINER_NAME is NOT running. Run: bash scripts/testbed/setup_testbed.sh"
    # No point continuing if container is down
    echo ""
    echo "Overall: FAIL (container not running)"
    exit 1
fi

# -----------------------------------------------------------------------------
# Check 2: Container on shared network
# -----------------------------------------------------------------------------
header "Network membership"
if docker network inspect "$SHARED_NETWORK" \
    --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null \
    | grep -q "$CONTAINER_NAME"; then
    pass "$CONTAINER_NAME is on $SHARED_NETWORK."
else
    fail "$CONTAINER_NAME is NOT on $SHARED_NETWORK."
    fail "Fix: docker network connect $SHARED_NETWORK $CONTAINER_NAME"
fi

# -----------------------------------------------------------------------------
# Check 3: Validation API responding
# -----------------------------------------------------------------------------
header "Validation API (port 9999)"
if curl -sf "${VALIDATION_URL}/status" > /dev/null 2>&1; then
    pass "Validation API is responding."
else
    fail "Validation API is NOT responding on ${VALIDATION_URL}/status"
fi

# -----------------------------------------------------------------------------
# Check 4: Run the testbed's own internal validation script
# -----------------------------------------------------------------------------
header "Internal testbed validation (validate_setup.sh)"
echo "  Running inside container..."
if docker exec "$CONTAINER_NAME" /opt/automotive-testbed/validate_setup.sh 2>&1 \
    | sed 's/^/  | /'; then
    pass "Internal validation script completed."
else
    fail "Internal validation script reported failures."
fi

# -----------------------------------------------------------------------------
# Check 5: Vulnerability status (V1-V12)
# -----------------------------------------------------------------------------
header "Vulnerability status (V1-V12)"
STATUS_JSON=$(curl -sf "${VALIDATION_URL}/status" 2>/dev/null || echo "{}")

if [ "$STATUS_JSON" = "{}" ]; then
    fail "Could not retrieve status JSON from Validation API."
else
    pass "Status JSON retrieved."
    echo ""
    echo "  Vulnerability exploit status:"
    echo "$STATUS_JSON" | python3 -c "
import sys, json
data = json.load(sys.stdin)
vulns = data.get('exploits') or data.get('vulnerabilities') or {}
if isinstance(vulns, dict) and vulns:
    for k in sorted(vulns.keys()):
        v = bool(vulns[k])
        status = 'exploited' if v else 'not exploited'
        icon = '[x]' if v else '[ ]'
        print(f'    {icon} {k}: {status}')
else:
    print('    [WARN] No exploit status map found in /status payload')
    if isinstance(data, dict):
        print(json.dumps(data, indent=4))
" 2>/dev/null || echo "$STATUS_JSON" | python3 -m json.tool | sed 's/^/  /'
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
echo "============================================================"
if [ "$overall" -eq 0 ]; then
    echo "  Overall: PASS - testbed is healthy and reachable"
else
    echo "  Overall: FAIL - one or more checks failed (see above)"
fi
echo ""
echo "  Useful commands:"
echo "    View logs:    docker logs $CONTAINER_NAME"
echo "    Shell access: docker exec -it $CONTAINER_NAME bash"
echo "    Full status:  curl http://localhost:9999/status | python3 -m json.tool"
echo "    Reset:        bash scripts/testbed/reset_testbed.sh"
echo "============================================================"

exit "$overall"
