#!/bin/bash
# scripts/docker/reset.sh - Reset system state without rebuilding images

# This script is for quickly resetting the system to a clean state during development or tesing.
# Use when you change docker related scripts (.sh), but not the underlying Dockerfiles.

echo "==================================================="
echo "🔄 VT-SaiBER SYSTEM RESET (Containers & Data)"
echo "==================================================="

# 1. Kill and Clear Data
echo "[1/3] Stopping containers and wiping volumes..."
# --volumes removes named volumes like postgres_data and msf_data
# --remove-orphans cleans up any leftover containers from previous configs
docker-compose down --volumes --remove-orphans

# 2. Re-initialize
echo "[2/3] Re-creating containers..."
# We use --force-recreate to ensure we aren't reusing old container layers
# We do NOT use --build here to keep it fast
docker-compose up -d --force-recreate

# 3. Quick Health Check
echo "[3/3] Waiting for services to stabilize..."
sleep 5

echo "==================================================="
echo "📊 Current System Status:"
docker-compose ps

echo ""
echo "✅ Reset Complete! Database is fresh and containers are new."
echo "==================================================="