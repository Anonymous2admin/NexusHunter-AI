# NexusHunter-AI

> **Personal Security Research Platform**  
> Local-first, evidence-driven, fail-closed architecture for authorized security testing and public bug bounty programs.

[![Go Tests](https://img.shields.io/badge/go%20tests-passing-brightgreen.svg)]()
[![Go Vet](https://img.shields.io/badge/go%20vet-clean-brightgreen.svg)]()
[![Frontend Build](https://img.shields.io/badge/frontend-verified-blue.svg)]()
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

---

## 2. Architecture Overview

NexusHunter-AI is engineered as a high-performance Go backend paired with a Next.js / React dark-mode security operations dashboard.

```
                    ┌─────────────────────────────────────────┐
                    │        NexusHunter Web Dashboard        │
                    │   (Targets, Scans, Scope Inspector)     │
                    └────────────────────┬────────────────────┘
                                         │ REST API
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
│   │   ├── models/               # Domain entities (Target, Job, Event)
│   │   ├── scope/                # Fail-closed scope engine & RFC 1123 validator
│   │   ├── jobs/                 # Scan job state machine & lifecycle
│   │   ├── recon/                # Non-destructive evidence collection contracts
│   │   ├── storage/              # Repository interfaces (Postgres + In-Memory)
│   │   ├── events/               # Event bus & pub/sub telemetry
│   │   └── api/                  # REST handlers, routing, and CORS middleware
│   ├── migrations/               # PostgreSQL schema migrations (up/down)
│   ├── go.mod                    # Go 1.22 module definition
│   └── go.sum                    # Go dependencies checksum
├── frontend/
│   ├── components/               # Reusable UI components (Sidebar, MetricCard, etc.)
│   │   └── views/                # Dashboard, Targets, Scans, and Scope Inspector
│   ├── lib/api.ts                # Centralized typed API client
│   └── types/                    # TypeScript interfaces aligned with Go models
├── configs/                      # Example configuration templates
├── docs/                         # Architecture, Scope, and API documentation
├── scripts/                      # Migration, test, and dev launcher scripts
└── docker-compose.yml            # PostgreSQL 16 and Redis 7 services
```

---

## 3. Scope Engine & Fail-Closed Rules

The `internal/scope` package implements a strict validation engine ensuring no scan or probe can execute without verified authorization.

### Rules Matrix
* **Target Attribution**: A job or probe cannot run without an existing target whose status is `ACTIVE`.
* **Explicit Inclusions**: Specifying `example.com` permits `example.com` ONLY. Wildcards like `*.example.com` must be explicitly defined.
* **Broad Wildcard Rejection**: Generic wildcards (`*`, `*.com`, `*.org`) are rejected during target creation.
* **Exclusion Precedence**: Excluded subdomains (e.g. `admin.example.com`, `*.internal.example.com`) take immediate precedence over wildcards.
* **Path Enforcements**: If allowed URL patterns (e.g. `/api/*`) are configured, any URL outside those paths is blocked.
* **Host Syntax Validity**: All hostnames are checked against RFC 1123. Malformed hostnames (e.g. `..host`, strings with quotes/spaces) trigger immediate rejection.

---

## 4. Local Installation & Quick Start

### Prerequisites
* **Go**: 1.22 or higher
* **Node.js**: 18+ and npm
* **Docker & Docker Compose** (optional for local PostgreSQL/Redis)

### 1. Clone & Setup Environment
```bash
git clone https://github.com/nexushunter-ai/nexushunter-ai.git
cd nexushunter-ai
cp .env.example .env
```

### 2. Launch Supporting Services (Docker)
```bash
docker compose up -d
```
This spins up:
* **PostgreSQL 16** on `localhost:5432`
* **Redis 7** on `localhost:6379`
* Applies database migrations from `backend/migrations/` automatically.

### 3. Run Database Migrations Manually
```bash
./scripts/migrate.sh
```

### 4. Run the Go API Server
```bash
cd backend
go run cmd/server/main.go
```
The server listens on `http://localhost:8080` and outputs structured JSON logs.

### 5. Run the Frontend Dashboard
```bash
npm install
npm run dev
```
Open `http://localhost:3000` to interact with the Security Operations Dashboard.

---

## 5. Testing & Static Analysis

NexusHunter-AI includes an automated test runner script covering all backend packages and frontend builds:

```bash
# Run the complete test suite
./scripts/run_tests.sh
```

Or execute individual test commands:

```bash
# Backend unit tests with race detector
cd backend
go test -v -race ./...

# Static analysis with Go vet
go vet ./...

# Frontend compilation check
npm run lint
npm run build
```

---

## 6. API Reference Summary

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Service health status |
| `GET` | `/api/version` | Service version and environment |
| `GET` | `/api/targets` | List authorized target programs |
| `POST` | `/api/targets` | Register a new target with strict scope rules |
| `GET` | `/api/targets/:id` | Get target details and scope rules |
| `DELETE` | `/api/targets/:id` | Remove a target program |
| `POST` | `/api/scope/verify` | Real-time fail-closed scope evaluation |
| `GET` | `/api/jobs` | List scan jobs (optional `?target_id=`) |
| `POST` | `/api/jobs` | Enqueue a scoped reconnaissance scan |
| `GET` | `/api/events` | Audit log telemetry stream |

For complete schemas and examples, see [`docs/API.md`](docs/API.md).

---

## 7. Contributing Guidelines

We welcome contributions focused on safety, scope verification, and evidence-gathering fidelity.

1. **Safety First**: Pull requests adding unauthorized exploitation payloads, credential harvesters, or stealth evasion will be rejected.
2. **Scope Discipline**: Any code interacting with network targets must invoke `scope.Validator.IsInScope()` and fail closed on error.
3. **Test Coverage**: All new models, storage methods, and validator logic must include unit tests.
4. **Code Quality**: Code must pass `go vet ./...` and `npm run build` cleanly before submission.

---

## 8. License

NexusHunter-AI is licensed under the Apache 2.0 License.
