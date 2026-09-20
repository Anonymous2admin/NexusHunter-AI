#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Starting NexusHunter-AI Development Stack..."

# 1. Start Docker Services if Docker is available
if command -v docker >/dev/null 2>&1; then
    echo "--> Launching PostgreSQL & Redis via Docker Compose..."
    docker compose up -d
fi

# 2. Start Go Backend in background
echo "--> Launching Go API Server on port 8080..."
cd "${ROOT_DIR}/backend"
HTTP_PORT=8080 go run ./cmd/server/main.go &
BACKEND_PID=$!

trap "kill $BACKEND_PID" EXIT

# 3. Start Frontend Dev Server
echo "--> Launching Frontend Dashboard on port 3000..."
cd "${ROOT_DIR}"
npm run dev
