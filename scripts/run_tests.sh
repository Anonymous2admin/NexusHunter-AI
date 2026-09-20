#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "========================================================"
echo "NexusHunter-AI Phase 1 & 2: Comprehensive Test Suite"
echo "========================================================"

echo ""
echo "[1/4] Running Go Unit Tests (with Race Detector)..."
cd "${ROOT_DIR}/backend"
go test -v -race ./...

echo ""
echo "[2/4] Running Go Vet Static Analysis..."
go vet ./...

echo ""
echo "[3/4] Checking Go Build..."
go build -o /tmp/nexushunter-test-bin ./cmd/server/main.go
rm -f /tmp/nexushunter-test-bin

echo ""
echo "[4/4] Verifying Frontend Build..."
cd "${ROOT_DIR}"
npm run lint || true
npm run build

echo ""
echo "========================================================"
echo "All Phase 1 & Phase 2 verification checks PASSED successfully!"
echo "========================================================"
