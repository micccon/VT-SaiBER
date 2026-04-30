#!/bin/bash
# scripts/tests/infrastructure/live/postgres_test.sh

echo "==================================================="
echo "🧪 TESTING POSTGRESQL DATABASE"
echo "==================================================="

echo "[1/3] Starting PostgreSQL..."
docker-compose up -d postgres

echo "[2/3] Waiting for database to be healthy..."
RETRIES=30
while [ $RETRIES -gt 0 ]; do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' vt-saiber-postgres 2>/dev/null)
    if [ "$STATUS" == "healthy" ]; then
        echo "✅ Database is healthy!"
        break
    fi
    sleep 2
    ((RETRIES--))
done

if [ $RETRIES -eq 0 ]; then
    echo "❌ Timeout waiting for PostgreSQL."
    exit 1
fi

echo "[3/3] Verifying connection..."
if docker exec vt-saiber-postgres psql -U vtsaiber -d vtsaiber -c "\l" > /dev/null; then
    echo "✅ SUCCESS: Connected to database 'vtsaiber'."
else
    echo "❌ FAILURE: Could not connect to database."
    exit 1
fi
