# NexusHunter-AI API Reference

## Base URL
```
http://localhost:8080
```

## System Endpoints

### 1. Health Check
`GET /api/health`
**Response (200 OK):**
```json
{
  "status": "ok",
  "service": "nexushunter-api",
  "time": "2026-09-16T18:00:00Z"
}
```

### 2. Version Check
`GET /api/version`
**Response (200 OK):**
```json
{
  "status": "ok",
  "service": "nexushunter-api",
  "version": "0.1.0-alpha",
  "environment": "development"
}
```

---

## Target Management Endpoints

### 3. Register Target
`POST /api/targets`
**Request Body:**
```json
{
  "name": "Acme Bug Bounty",
  "root_domain": "acme.com",
  "allowed_domains": ["acme.com", "*.acme.com"],
  "allowed_url_patterns": ["/api/*", "/v1/*"],
  "excluded_patterns": ["admin.acme.com", "*.internal.acme.com"]
}
```
**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "id": "tgt-9a4f21",
    "name": "Acme Bug Bounty",
    "root_domain": "acme.com",
    "allowed_domains": ["acme.com", "*.acme.com"],
    "allowed_url_patterns": ["/api/*", "/v1/*"],
    "excluded_patterns": ["admin.acme.com", "*.internal.acme.com"],
    "status": "ACTIVE",
    "created_at": "2026-09-16T18:00:00Z",
    "updated_at": "2026-09-16T18:00:00Z"
  }
}
```

### 4. List Targets
`GET /api/targets`

### 5. Get Target by ID
`GET /api/targets/:id`

### 6. Delete Target
`DELETE /api/targets/:id`

---

## Scope Evaluation Endpoint

### 7. Verify Scope
`POST /api/scope/verify`
**Request Body:**
```json
{
  "target_id": "tgt-9a4f21",
  "hostname": "api.acme.com",
  "url": "https://api.acme.com/api/v1/health"
}
```
**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "in_scope": true,
    "reason": "authorized",
    "matched_rule": "*.acme.com && /api/*"
  }
}
```

---

## Scan Job Endpoints

### 8. Enqueue Scan Job
`POST /api/jobs`
**Request Body:**
```json
{
  "target_id": "tgt-9a4f21",
  "type": "PASSIVE_DNS_ENUMERATION",
  "metadata": {
    "depth": 2
  }
}
```

### 9. List Scan Jobs
`GET /api/jobs?target_id=tgt-9a4f21`

### 10. Query Audit & Telemetry Events
`GET /api/events`
