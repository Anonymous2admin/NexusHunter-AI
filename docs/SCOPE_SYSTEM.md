# NexusHunter-AI Scope Authorization Model

## Overview
The Scope Validation Engine (`internal/scope`) guarantees that security research probes are confined strictly within authorized bug bounty boundaries.

## Rules & Invariants
1. **Target Existence & Active Status**: A probe cannot execute without an existing target whose status is `ACTIVE`.
2. **Exclusion Precedence**: Excluded hostnames, patterns, or paths take precedence over any inclusion rule.
3. **No Implicit Wildcard Expansion**: Specifying `example.com` authorizes `example.com` ONLY. Subdomains like `api.example.com` are strictly rejected unless `*.example.com` is explicitly configured.
4. **Broad Wildcard Rejection**: Generic wildcards (such as `*`, `*.com`, `*.org`) are rejected during target registration.
5. **Path Restrictions**: When allowed URL patterns are specified (e.g. `/api/*`, `/v1/*`), requests to omitted endpoints (e.g. `/admin`, `/internal`) are immediately blocked.
6. **Protocol Restrictions**: Only valid `http` and `https` schemes are recognized. `file://`, `gopher://`, `ftp://`, or custom schemes trigger immediate rejection.

## Verification Matrix
| Target Configuration | Input Host / URL | Result | Rationale |
| :--- | :--- | :--- | :--- |
| `example.com` | `example.com` | **ALLOWED** | Exact root match |
| `example.com` | `api.example.com` | **DENIED** | No wildcard specified; implicit expansion forbidden |
| `*.example.com` | `api.example.com` | **ALLOWED** | Explicit wildcard subdomain match |
| `*.example.com` | `evil-example.com` | **DENIED** | Domain boundary violation |
| `*.example.com` (Excl: `admin.example.com`) | `admin.example.com` | **DENIED** | Explicit exclusion match |
| Allowed paths: `[/api/*]` | `https://example.com/blog` | **DENIED** | Path not covered by allowed URL patterns |
| `example.com` | `<script>alert(1)</script>` | **DENIED** | Malformed hostname fails RFC 1123 validation |
