#!/bin/bash
# Repair database collation-version mismatches for the VT-SaiBER Postgres container.
#
# This is an explicit maintenance action. It rebuilds indexes in the target
# database and refreshes the recorded collation version so recurring warnings
# disappear after a host/libc upgrade.

set -euo pipefail

DB_CONTAINER="${DB_CONTAINER:-vt-saiber-postgres}"
DB_NAME="${DB_NAME:-vtsaiber}"
DB_USER="${DB_USER:-vtsaiber}"
AUTO_CONFIRM="${1:-}"

run_psql() {
    local sql="$1"
    docker exec -i "$DB_CONTAINER" psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -P pager=off -c "$sql"
}

if ! docker ps --filter "name=^${DB_CONTAINER}$" --filter "status=running" -q | grep -q .; then
    echo "Postgres container '$DB_CONTAINER' is not running."
    echo "Start the stack first with: docker compose up -d"
    exit 1
fi

echo "==================================================="
echo "VT-SaiBER POSTGRES COLLATION REPAIR"
echo "==================================================="
echo "Container: $DB_CONTAINER"
echo "Database:  $DB_NAME"
echo "User:      $DB_USER"
echo ""
echo "Current database collation version status:"
run_psql "SELECT datname, datcollversion AS recorded_version, pg_database_collation_actual_version(oid) AS actual_version FROM pg_database WHERE datname = current_database();"
echo ""
echo "Affected collations and dependent objects (if any):"
run_psql "SELECT pg_describe_object(refclassid, refobjid, refobjsubid) AS collation, pg_describe_object(classid, objid, objsubid) AS dependent_object FROM pg_depend d JOIN pg_collation c ON refclassid = 'pg_collation'::regclass AND refobjid = c.oid WHERE c.collversion <> pg_collation_actual_version(c.oid) ORDER BY 1, 2;"
echo ""
echo "This operation will:"
echo "  1. REINDEX DATABASE $DB_NAME"
echo "  2. ALTER DATABASE $DB_NAME REFRESH COLLATION VERSION"
echo ""
echo "REINDEX can take locks while it runs. Use this only when you are okay with maintenance activity on the dev database."
echo ""

if [ "$AUTO_CONFIRM" != "--yes" ]; then
    read -r -p "Type 'repair' to continue: " confirmation
    if [ "$confirmation" != "repair" ]; then
        echo "Aborted."
        exit 1
    fi
fi

echo ""
echo "[1/2] Reindexing database..."
run_psql "REINDEX DATABASE \"$DB_NAME\";"

echo "[2/2] Refreshing recorded collation version..."
run_psql "ALTER DATABASE \"$DB_NAME\" REFRESH COLLATION VERSION;"

echo ""
echo "Post-repair database collation version status:"
run_psql "SELECT datname, datcollversion AS recorded_version, pg_database_collation_actual_version(oid) AS actual_version FROM pg_database WHERE datname = current_database();"
echo ""
echo "Repair complete."
