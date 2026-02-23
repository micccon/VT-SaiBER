#!/usr/bin/env bash
# =============================================================================
# reset_testbed.sh
# Stops and removes the automotive testbed container.
# The main VT-SaiBER stack (postgres, kali-mcp, msf-mcp, agents) is unaffected.
#
# Usage:
#   bash scripts/testbed/reset_testbed.sh          # stop container only
#   bash scripts/testbed/reset_testbed.sh --clean  # stop + remove built image
#                                                   # (forces full rebuild next time)
# =============================================================================

set -uo pipefail

cd "$(dirname "$0")"

COMPOSE_FILE="../../automotive_testbed/docker-compose.yml"
CONTAINER_NAME="automotive-testbed"
SHARED_NETWORK="vt-saiber-network"
CLEAN=false

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --clean) CLEAN=true ;;
        *) echo "[WARN] Unknown argument: $arg" >&2 ;;
    esac
done

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }

# -----------------------------------------------------------------------------
# Step 1: Disconnect from shared network
# -----------------------------------------------------------------------------
info "Disconnecting $CONTAINER_NAME from $SHARED_NETWORK ..."
docker network disconnect "$SHARED_NETWORK" "$CONTAINER_NAME" 2>/dev/null \
    && success "Disconnected from $SHARED_NETWORK." \
    || success "Already disconnected (no action needed)."

# -----------------------------------------------------------------------------
# Step 2: Stop and remove container (and optionally the image)
# -----------------------------------------------------------------------------
if [ "$CLEAN" = true ]; then
    info "Stopping testbed and removing image (--clean mode)..."
    docker-compose -f "$COMPOSE_FILE" down --rmi local
    success "Testbed stopped and image removed. Next setup will do a full rebuild."
else
    info "Stopping testbed container..."
    docker-compose -f "$COMPOSE_FILE" down
    success "Testbed stopped. (Image cached — next setup will be faster.)"
    info "To also remove the image: bash scripts/testbed/reset_testbed.sh --clean"
fi

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo ""
echo "============================================================"
echo "  Automotive testbed has been stopped."
echo "  Main VT-SaiBER stack is unaffected."
echo ""
echo "  To restart: bash scripts/testbed/setup_testbed.sh"
echo "============================================================"
