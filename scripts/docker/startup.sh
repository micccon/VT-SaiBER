#!/bin/bash
# scripts/docker/startup.sh - Start all containers without rebuilding

# this is the default startup script used in the Dockerfile for the main "agents" container
# It assumes that all images are already built and just starts the containers.
# Use this for normal startups. For a full reset and rebuild, use scripts/docker/full_reset_startup.sh

echo "🚀 Starting VT-SaiBER containers..."
docker compose up -d

echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 5

docker compose ps

echo ""
echo "✅ Done! View logs with: docker compose logs -f"