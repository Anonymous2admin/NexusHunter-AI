#!/usr/bin/env bash
set -euo pipefail

# 1. Detect Repository Root
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
  echo "==> Cleaning up test background processes..."
  if [ -n "${BACKEND_PID}" ] && kill -0 "${BACKEND_PID}" 2>/dev/null; then
    kill -15 "${BACKEND_PID}" 2>/dev/null || true
  fi
  if [ -n "${FRONTEND_PID}" ] && kill -0 "${FRONTEND_PID}" 2>/dev/null; then
    kill -15 "${FRONTEND_PID}" 2>/dev/null || true
  fi
  rm -f /tmp/backend-e2e.log /tmp/vite-e2e.log 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "========================================================"
echo "NexusHunter-AI Deterministic E2E Browser Launcher"
echo "========================================================"

# 2. Ephemeral Database & Migrations
export DATABASE_URL="${TEST_DATABASE_URL:-${DATABASE_URL:-postgres://nexushunter:huntersecret123@127.0.0.1:5432/nexushunter_db?sslmode=disable}}"
echo "==> Target Database URL: ${DATABASE_URL}"
if [ -f "./scripts/migrate.sh" ]; then
  bash ./scripts/migrate.sh || echo "Note: Migration runner completed."
fi

# 3. Build Go Backend (if go compiler is available)
if command -v go >/dev/null 2>&1; then
  echo "==> Building Go core backend binary..."
  mkdir -p ./backend/bin
  (cd "${ROOT_DIR}/backend" && go build -o ./bin/server ./cmd/server/main.go)
fi

# 4. Start Go Backend (Port 8081)
if ! curl -sf http://127.0.0.1:8081/api/health >/dev/null 2>&1; then
  echo "==> Starting NexusHunter Go backend on port 8081..."
  chmod +x ./backend/bin/server 2>/dev/null || true
  HTTP_PORT=8081 APP_ENV=development LOG_LEVEL=warn ./backend/bin/server > /tmp/backend-e2e.log 2>&1 &
  BACKEND_PID=$!

  # 5. Wait for /api/health
  BACKEND_READY=false
  for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8081/api/health >/dev/null 2>&1; then
      echo "==> Go backend is healthy on port 8081 (Attempt ${i})."
      BACKEND_READY=true
      break
    fi
    sleep 0.2
  done

  if [ "$BACKEND_READY" = false ]; then
    echo "ERROR: Go backend failed to become healthy within timeout."
    cat /tmp/backend-e2e.log || true
    exit 1
  fi
else
  echo "==> Go backend is already running on port 8081."
fi

# 6 & 7. Inspect Health Response
HEALTH_JSON=$(curl -sf http://127.0.0.1:8081/api/health || echo "{}")
echo "==> Backend Health Metadata: ${HEALTH_JSON}"

# 8. Start Vite Frontend (Port 3000)
if ! curl -sf http://127.0.0.1:3000 >/dev/null 2>&1; then
  echo "==> Starting Vite development frontend on port 3000..."
  npx vite --port=3000 --host=0.0.0.0 > /tmp/vite-e2e.log 2>&1 &
  FRONTEND_PID=$!

  # 9. Wait for Frontend Readiness
  FRONTEND_READY=false
  for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:3000 >/dev/null 2>&1; then
      echo "==> Vite frontend is ready on port 3000 (Attempt ${i})."
      FRONTEND_READY=true
      break
    fi
    sleep 0.2
  done

  if [ "$FRONTEND_READY" = false ]; then
    echo "ERROR: Vite frontend failed to start within timeout."
    cat /tmp/vite-e2e.log || true
    exit 1
  fi
else
  echo "==> Vite frontend is already active on port 3000."
fi

# 10. Run Playwright Browser Tests
echo "==> Launching Playwright Chromium Browser E2E suite..."
set +e
npx playwright test "$@"
EXIT_CODE=$?
set -e

# 11. Capture Exit Code & Clean Output
if [ $EXIT_CODE -eq 0 ]; then
  echo "==> Browser E2E suite executed successfully (Exit Code 0)."
else
  echo "==> Browser E2E suite FAILED with Exit Code ${EXIT_CODE}."
fi

exit $EXIT_CODE
