#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "========================================================"
echo "NexusHunter-AI Authoritative Verification Suite"
echo "========================================================"

# 1. Go Unit Tests & Static Analysis (if go binary is in PATH)
if command -v go >/dev/null 2>&1; then
  echo ""
  echo "[1/6] Running Go Unit Tests (with Race Detector)..."
  (cd "${ROOT_DIR}/backend" && go test -v -race ./...)

  echo ""
  echo "[2/6] Running Go Vet Static Analysis..."
  (cd "${ROOT_DIR}/backend" && go vet ./...)
else
  echo ""
  echo "[1/6 & 2/6] Notice: 'go' binary not found in PATH; skipping local Go compilation check."
fi

# 2. Frontend Typecheck and Lint (Strict: never swallow errors)
echo ""
echo "[3/6] Running Frontend Typecheck & Lint..."
npm run lint

# 3. Frontend Production Build
echo ""
echo "[4/6] Verifying Frontend Production Build..."
npm run build

# 4. Invariant Contract, Integration, and API E2E Suites
echo ""
echo "[5/6] Running Contract, Integration, and API E2E Test Layers..."
npm run test:contract
npm run test:integration
npm run test:api-e2e

# 5. Playwright Browser E2E Suite
echo ""
echo "[6/6] Running Real Browser E2E Suite (Chromium)..."
npm run test:browser-e2e

echo ""
echo "========================================================"
echo "All NexusHunter-AI verification layers PASSED cleanly!"
echo "========================================================"
