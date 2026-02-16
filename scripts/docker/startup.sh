#!/bin/bash
# scripts/start.sh - Start all containers without rebuilding

echo "🚀 Starting VT-SaiBER containers..."
docker-compose up -d

echo ""
echo "⏳ Waiting for services to be healthy..."
sleep 5

docker-compose ps

echo ""
echo "✅ Done! View logs with: docker-compose logs -f"
