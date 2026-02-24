#!/usr/bin/env bash
# =============================================================================
# start_testbed.sh
# Starts an already-built automotive testbed without rebuilding the image.
# Use setup_testbed.sh for first-time setup or after Dockerfile changes.
#
# Usage:
#   bash scripts/testbed/start_testbed.sh
#
# Prerequisites:
#   - setup_testbed.sh has been run at least once (image already built)
#   - Main VT-SaiBER stack must be running (creates vt-saiber-network):
#       docker-compose up -d   (from project root)
# =============================================================================

set -euo pipefail

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
# Step 2: Start the existing testbed container (no rebuild)
# -----------------------------------------------------------------------------
info "Starting automotive testbed (using existing image, no rebuild)..."
docker compose -f "$COMPOSE_FILE" up -d

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
        error "If the image is missing, run setup_testbed.sh instead."
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
    success "$CONTAINER_NAME already on $SHARED_NETWORK (no action needed)."
fi

# -----------------------------------------------------------------------------
# Step 5: Run internal testbed validation
# -----------------------------------------------------------------------------
info "Running internal testbed validation (validate_setup.sh)..."
if docker exec "$CONTAINER_NAME" /opt/automotive-testbed/validate_setup.sh 2>&1 | sed 's/^/  | /'; then
    success "Internal validation passed."
else
    error "Internal validation failed. Check logs: docker logs $CONTAINER_NAME"
    exit 1
fi

# -----------------------------------------------------------------------------
# Step 6: Print status summary
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
echo "  Full setup:    bash scripts/testbed/setup_testbed.sh  (rebuilds image)"
echo "============================================================"
