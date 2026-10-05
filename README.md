# NexusHunter-AI

> **Personal Security Research Platform**  
> Local-first, evidence-driven, fail-closed architecture for authorized security testing and public bug bounty programs.

[![Go Tests](https://img.shields.io/badge/go%20tests-passing-brightgreen.svg)]()
[![Go Vet](https://img.shields.io/badge/go%20vet-clean-brightgreen.svg)]()
[![Frontend Build](https://img.shields.io/badge/frontend-verified-blue.svg)]()
[![Playwright E2E](https://img.shields.io/badge/playwright-passing-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)]()

---

## ⚠️ Mandatory Ethics & Authorized Use Notice

> **IMPORTANT:** NexusHunter-AI is strictly designed for authorized security testing, defense research, and public bug-bounty programs where targets are explicitly in scope. Unauthorized testing against systems without prior written authorization is illegal and strictly forbidden by the design and terms of this software.
>
> * **No destructive exploitation functionality.**
> * **No credential theft, persistence, malware behaviors, or evasion.**
> * **All active testing functionality requires explicit target attribution and scope authorization.**
> * **The platform fails closed whenever scope information is missing, ambiguous, or invalid.**

---

## 1. Project Vision & Philosophy

Modern security research often relies on fragmented scripts, opaque scanners with unchecked network egress, or tools that make unverified claims of "zero false positives."

**NexusHunter-AI** is built as an open-source, local-first workbench providing:
1. **Mathematical Scope Enforcement**: Probes are strictly bounded by configured targets and domain/URL rules. If any ambiguity exists, the engine halts immediately (*Fail-Closed*).
2. **Attributable Audit Trail**: Every probe, scan job, and network observation is cryptographically tied to an authorized target ID and recorded on an immutable telemetry bus.
3. **Evidence-Driven Observation**: Built around reproducible evidence collection (DNS records, SAN certificates, headers, technology fingerprints) rather than speculative vulnerability assertions.
4. **Local-First Privacy**: Target inventory, scan outputs, and telemetry remain strictly on your local machine or private container environment.
5. **Runtime Mode Transparency**: The platform strictly verifies and displays whether it is running against a live backend with PostgreSQL persistence (`LIVE`), isolated local sandbox fixtures (`DEMO`), degraded services (`PARTIAL`), offline view (`OFFLINE`), or unverified responses (`UNKNOWN`).

---

## 2. Architecture Overview

NexusHunter-AI is engineered as a high-performance Go backend paired with a **Vite + React** dark-mode security operations dashboard.

```
                    ┌─────────────────────────────────────────┐
                    │      NexusHunter Vite+React Dashboard   │
                    │   (Targets, Scans, Evidence, Reasoning) │
                    └────────────────────┬────────────────────┘
                                         │ REST API (Reverse Proxy)
                                         ▼
                    ┌─────────────────────────────────────────┐
                    │            Go Core API Server           │
                    │    (HTTP Router, slog, Middleware)      │
                    └──────┬─────────────┬─────────────┬──────┘
                           │             │             │
              ┌────────────▼──┐   ┌──────▼─────┐   ┌───▼─────────────┐
              │ Scope Engine  │   │ Job Engine │   │ Telemetry Bus   │
              │ (Fail-Closed) │   │ (Lifecycle)│   │ (Memory/PubSub) │
              └───────────────┘   └────────────┘   └─────────────────┘
                           │             │
              ┌────────────▼─────────────▼─────────────┐
              │           Storage Abstraction          │
              │      (PostgreSQL DDL / Memory Repo)    │
              └────────────────────────────────────────┘
```

### Directory Structure
```
nexushunter-ai/
├── backend/
│   ├── cmd/server/main.go        # HTTP Server entry point & graceful shutdown
│   ├── internal/
│   │   ├── config/               # Environment loading and validation
│   │   ├── models/               # Domain entities (Target, Job, Event, Hypothesis)
│   │   ├── scope/                # Fail-closed scope engine & RFC 1123 validator
│   │   ├── jobs/                 # Scan job state machine & lifecycle
│   │   ├── recon/                # Non-destructive evidence collection contracts
│   │   ├── storage/              # Repository interfaces (Postgres + In-Memory)
│   │   ├── events/               # Event bus & pub/sub telemetry
│   │   └── api/                  # REST handlers, routing, and CORS middleware
│   ├── migrations/               # PostgreSQL schema migrations (up/down)
│   ├── go.mod                    # Go module definition
│   └── go.sum                    # Go dependencies checksum
├── src/                          # Vite + React Frontend
│   ├── components/               # UI components (Sidebar, Topbar, DemoBanner)
│   │   └── views/                # Targets, Scans, Evidence, Reasoning, Scope
│   ├── context/                  # Authoritative RuntimeContext provider
│   ├── lib/api.ts                # Centralized typed API client
│   └── types/                    # TypeScript interfaces aligned with Go models
├── tests/
│   ├── phase8_2r_contract.test.ts # Core invariant contract tests
│   ├── integration/              # Backend HTTP API & PostgreSQL integration tests
│   ├── api-e2e/                  # Full API lifecycle and mode gating E2E tests
│   └── browser-e2e/              # Playwright Chromium real-browser suite
├── scripts/
│   ├── migrate.sh                # PostgreSQL migration runner
│   ├── run_e2e.sh                # End-to-end browser test launcher
│   └── run_tests.sh              # Backend test runner
├── playwright.config.ts          # Playwright configuration
├── package.json                  # Node.js dependencies & test scripts
└── .github/workflows/ci.yml      # CI pipeline definition
```

---

## 3. Authoritative Runtime Modes

The platform strictly differentiates between 5 runtime states:

| Mode | Backend API | Database | Mutation Gate | Description |
|:---|:---|:---|:---|:---|
| **LIVE** | Port 8081 Active | PostgreSQL Connected | Allowed | Full operational state with durable persistence |
| **DEMO** | Local Memory / Preview | In-Memory Fixtures | Sandbox Only | Read-only by default; mutations require explicit toggle |
| **PARTIAL** | Port 8081 Active | Degraded Subsystems | Fail-Closed | Partial degradation; mutating actions blocked |
| **OFFLINE** | Unreachable | Unavailable | Fail-Closed | Offline display mode; no network probes |
| **UNKNOWN** | Corrupted / Malformed | Unverified | Fail-Closed | Unrecognized health payload fails closed unconditionally |

---

## 4. Quick Start & Clean-Checkout Verification

### Prerequisites
* **Node.js**: 20+ (with `npm`)
* **PostgreSQL** (optional for local live backend, port 5432)

### 1. Clean Checkout & Dependency Installation
```bash
# Clean install exactly from package-lock.json
npm ci

# Install Chromium browser for Playwright
npx playwright install --with-deps chromium
```

### 2. Single-Command Full Test Orchestration
To execute the complete verification suite across all layers:
```bash
npm test
```
This sequentially invokes:
1. `npm run test:contract` (13 contract invariant tests)
2. `npm run test:integration` (4 API + storage integration tests)
3. `npm run test:api-e2e` (5 frontend lifecycle & race protection tests)
4. `npm run test:browser-e2e` (10 Playwright Chromium browser tests)

---

## 5. Individual Test Layers

```bash
# Contract Invariant Tests (Node test runner)
npm run test:contract

# Integration Tests (API + Database)
npm run test:integration

# API E2E Tests (Lifecycle, Gating, Race Protection)
npm run test:api-e2e

# Real Browser E2E Tests (Playwright Chromium)
npm run test:browser-e2e

# Typecheck & Static Analysis
npm run lint

# Production Frontend Build
npm run build
```

---

## 6. End-to-End Browser Suite (`tests/browser-e2e/`)

The Playwright browser suite verifies the actual application running in a real Chromium browser against the Vite frontend and Go backend:

* **Section 6 & 7**: Real Browser Startup, DOM rendering, and authoritative runtime connection badges (`LIVE`, `DEMO`).
* **Section 8**: Real Target Creation UI with modal DOM interaction, form validation, and backend persistence.
* **Section 9 & 17**: Real Target Switch UI and race protection against delayed / out-of-order responses.
* **Section 10 & 11**: Real Runtime Context Badges & Fail-Closed Mutation Gating across all 5 runtime states (`LIVE`, `DEMO`, `PARTIAL`, `OFFLINE`, `UNKNOWN`).
* **Section 12 & 16**: Real UI Distinction between HTTP 500 error banners (with Retry action) and HTTP 200 empty states (`No Hypotheses Generated Yet`).
* **Section 13 & 14**: Multi-Root Scope Import UI requiring explicit manual candidate selection before enabling confirmation.
* **Section 14**: Real Supported Gate preventing premature `SUPPORTED` promotion without verified empirical evidence.
* **Section 15 & 16**: Real Evidence UI with deterministic SHA-256 canonical fingerprints and cryptographic integrity mismatch detection.
* **Section 18**: Job State Machine Lifecycle (`QUEUED` $\rightarrow$ `RUNNING` $\rightarrow$ `COMPLETED`) with conflict rejection (HTTP 409).
* **Section 29**: Negative Control asserting that test harness assertions fail when expectations are falsified.

---

## 7. License

NexusHunter-AI is licensed under the Apache 2.0 License.
