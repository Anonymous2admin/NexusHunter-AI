#!/usr/bin/env bash
set -euo pipefail

# NexusHunter-AI Database Migration Runner
DB_URL="${DATABASE_URL:-postgres://nexushunter:huntersecret123@localhost:5432/nexushunter_db?sslmode=disable}"
MIGRATIONS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../backend/migrations" && pwd)"

echo "==> Running NexusHunter-AI PostgreSQL Migrations..."
echo "--> Migrations Directory: ${MIGRATIONS_DIR}"

if command -v psql >/dev/null 2>&1; then
    for file in "${MIGRATIONS_DIR}"/*.up.sql; do
        if [ -f "$file" ]; then
            echo "--> Applying migration: $(basename "$file")"
            psql "${DB_URL}" -f "$file"
        fi
    done
    echo "==> Migrations applied successfully."
else
    echo "Notice: 'psql' not found in PATH. Ensure PostgreSQL container is running or install postgresql-client."
fi
