# NexusHunter-AI Architecture Specification

## 1. System Mission & Philosophy
NexusHunter-AI is a local-first, personal security research platform designed exclusively for authorized bug bounty programs and security assessments. 

### Core Tenets
1. **Strict Target Authorization**: Active actions require an attributable target ID with verified, fail-closed boundaries.
2. **Fail Closed**: If scope data is missing, ambiguous, malformed, or conflicting, the system denies execution immediately.
3. **Evidence Over Assumptions**: Focus on reproducible observation and proof-of-concept evidence rather than probabilistic guesses or unverified false-positive claims.
4. **Safety by Design**: Exploitation payloads, credential dumping, persistence, malware behavior, evasion techniques, and destructive operations are architecturally prohibited.

---

## 2. Monorepo Organization
```
nexushunter-ai/
├── backend/
│   ├── cmd/server/       # HTTP Server entry point & graceful shutdown
│   ├── internal/
│   │   ├── config/       # Environment loading & validation
│   │   ├── models/       # Domain structs (Target, Job, Event)
│   │   ├── scope/        # Fail-closed scope authorization engine & unit tests
│   │   ├── jobs/         # Scan job state machine & lifecycle management
│   │   ├── recon/        # Evidence collection abstraction & scanner interface
│   │   ├── storage/      # Storage repository interfaces (Postgres + In-Memory)
│   │   ├── events/       # Internal event bus & pub/sub telemetry
│   │   └── api/          # HTTP REST handlers, router, & middleware
│   ├── migrations/       # PostgreSQL DDL migrations (up/down)
│   ├── go.mod            # Go module definition
│   └── go.sum            # Module checksums
├── frontend/             # Next.js / React Dark Security Dashboard
│   ├── components/       # Reusable components (Sidebar, Topbar, MetricCard, DataTable, etc.)
│   ├── lib/              # Centralized typed API client (api.ts)
│   └── types/            # TypeScript interfaces aligned with Go models
├── configs/              # Environment templates and example YAML
├── docs/                 # Architecture, Scope, and API documentation
├── scripts/              # Migration and testing automation scripts
├── docker-compose.yml    # Local PostgreSQL and Redis services
└── README.md             # Comprehensive platform documentation
```

---

## 3. Data Flow & Security Boundary Enforcement
Every incoming probe or scan invocation traverses the strict authorization pipeline:
```
[User Request / Scan Trigger]
             │
             ▼
[Target Resolution & Attribution] ──(Missing/Inactive)──► [DENIED (403/422)]
             │
             ▼
[Scope Evaluator: IsInScope()]
  ├── 1. Check Exclusion Rules (Highest Precedence) ────► [EXCLUDED (Denied)]
  ├── 2. Exact Domain / Explicit Wildcard Check ────────► [OUT OF SCOPE (Denied)]
  ├── 3. URL Path Restrictons Check ────────────────────► [PATH RESTRICTED (Denied)]
  └── 4. RFC Hostname / Scheme Integrity ───────────────► [MALFORMED (Denied)]
             │
        (Authorized)
             ▼
[Evidence Collector / Job Engine]
             │
             ▼
[Event Bus Audit Log & State Persistence]
```
