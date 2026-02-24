#!/usr/bin/env bash
# =============================================================================
# setup_testbed.sh
# Starts the automotive pentesting testbed and connects it to vt-saiber-network
# so that kali-mcp and msf-mcp containers can reach it by hostname.
#
# Usage:
#   bash scripts/testbed/setup_testbed.sh
#
# Prerequisites:
#   - Main VT-SaiBER stack must be running (creates vt-saiber-network):
#       docker-compose up -d   (from project root)
#   - Native Linux or Linux VM (for vcan CAN bus support)
# =============================================================================

set -euo pipefail

# Anchor to this script's directory so the -f path is always correct
cd "$(dirname "$0")"

COMPOSE_FILE="../../third_party/automotive_testbed/docker-compose.yml"
CONTAINER_NAME="automotive-testbed"
SHARED_NETWORK="vt-saiber-network"
VALIDATION_URL="http://localhost:9999/status"
MAX_RETRIES=60
RETRY_SLEEP=2

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*" >&2; }
error()   { echo "[ERROR] $*" >&2; }

# -----------------------------------------------------------------------------
# Step 1: Load vcan kernel module
# -----------------------------------------------------------------------------
info "Loading vcan kernel module..."
if sudo modprobe vcan 2>/dev/null; then
    success "vcan module loaded."
else
    warn "modprobe vcan failed. CAN bus challenges (V3, V4, V10) will not work."
    warn "Continuing — web/SSH/OBD/UDS challenges are still available."
fi

if lsmod | grep -q "^vcan"; then
    success "vcan confirmed active."
else
    warn "vcan not detected in lsmod output."
fi

# -----------------------------------------------------------------------------
# Step 2: Build and start the testbed container
# -----------------------------------------------------------------------------
info "Starting automotive testbed (this may take a few minutes on first build)..."
#docker-compose -f "$COMPOSE_FILE" up -d --build

# Alternative with build output:
docker compose -f "$COMPOSE_FILE" up -d --build
# -----------------------------------------------------------------------------
# Step 3: Wait for Validation API to become healthy
# -----------------------------------------------------------------------------
info "Waiting for Validation API on $VALIDATION_URL ..."
attempt=0
until curl -sf "$VALIDATION_URL" > /dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge "$MAX_RETRIES" ]; then
        error "Timed out waiting for testbed to become healthy after $((MAX_RETRIES * RETRY_SLEEP))s."
        error "Check logs: docker logs $CONTAINER_NAME"
        exit 1
    fi
    printf "."
    sleep "$RETRY_SLEEP"
done
echo ""
success "Validation API is responding."

# -----------------------------------------------------------------------------
# Step 4: Connect testbed to the shared VT-SaiBER network
# -----------------------------------------------------------------------------
info "Connecting $CONTAINER_NAME to $SHARED_NETWORK ..."
if docker network connect "$SHARED_NETWORK" "$CONTAINER_NAME" 2>/dev/null; then
    success "$CONTAINER_NAME joined $SHARED_NETWORK."
else
    # Already connected is fine
    success "$CONTAINER_NAME already on $SHARED_NETWORK (no action needed)."
fi

# -----------------------------------------------------------------------------
# Step 5: Print status summary
# -----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  Automotive Testbed Ready"
echo "============================================================"
echo "  Container : $CONTAINER_NAME"
echo "  Network   : $SHARED_NETWORK (+ host port mappings)"
echo ""
echo "  Host ports:"
echo "    SSH          -> localhost:2222"
echo "    Infotainment -> localhost:8000"
echo "    Gateway      -> localhost:8080"
echo "    OBD-II       -> localhost:9555"
echo "    UDS Gateway  -> localhost:9556"
echo "    Validation   -> localhost:9999"
echo ""
echo "  Reachable by other containers at:"
echo "    $CONTAINER_NAME:8000  (Infotainment)"
echo "    $CONTAINER_NAME:9999  (Validation API)"
echo "    ... etc."
echo ""
echo "  Quick status:"
curl -s "$VALIDATION_URL" | python3 -m json.tool 2>/dev/null || curl -s "$VALIDATION_URL"
echo ""
echo "  Run validate:  bash scripts/testbed/validate_testbed.sh"
echo "  Run reset:     bash scripts/testbed/reset_testbed.sh"
echo "============================================================"
