-- NexusHunter-AI Phase 2: Reconnaissance Engine Database Schema (PostgreSQL)

-- 1. Discovered Assets Table
CREATE TABLE IF NOT EXISTS assets (
    id VARCHAR(64) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    asset_type VARCHAR(64) NOT NULL DEFAULT 'SUBDOMAIN',
    status VARCHAR(32) NOT NULL DEFAULT 'DISCOVERED',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_assets_target_hostname UNIQUE(target_id, hostname)
);

CREATE INDEX IF NOT EXISTS idx_assets_target_id ON assets(target_id);
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen DESC);

-- 2. DNS Records Table
CREATE TABLE IF NOT EXISTS dns_records (
    id VARCHAR(64) PRIMARY KEY,
    asset_id VARCHAR(64) NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    record_type VARCHAR(16) NOT NULL,
    value TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_dns_records_asset_type_val UNIQUE(asset_id, record_type, value)
);

CREATE INDEX IF NOT EXISTS idx_dns_records_asset_id ON dns_records(asset_id);
CREATE INDEX IF NOT EXISTS idx_dns_records_type ON dns_records(record_type);

-- 3. HTTP Services Table
CREATE TABLE IF NOT EXISTS http_services (
    id VARCHAR(64) PRIMARY KEY,
    asset_id VARCHAR(64) NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    status_code INT NOT NULL,
    content_type VARCHAR(255),
    response_time INT NOT NULL DEFAULT 0,
    final_url TEXT,
    server_header VARCHAR(255),
    tls_version VARCHAR(64),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_http_services_asset_url UNIQUE(asset_id, url)
);

CREATE INDEX IF NOT EXISTS idx_http_services_asset_id ON http_services(asset_id);
CREATE INDEX IF NOT EXISTS idx_http_services_status ON http_services(status_code);

-- 4. Discovered URLs Table (Crawled / Discovered Endpoints)
CREATE TABLE IF NOT EXISTS urls (
    id VARCHAR(64) PRIMARY KEY,
    asset_id VARCHAR(64) NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    source VARCHAR(64) NOT NULL DEFAULT 'CRAWLER',
    depth INT NOT NULL DEFAULT 0,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_urls_asset_url UNIQUE(asset_id, url)
);

CREATE INDEX IF NOT EXISTS idx_urls_asset_id ON urls(asset_id);
CREATE INDEX IF NOT EXISTS idx_urls_depth ON urls(depth);

-- 5. Reconnaissance Execution Runs Table
CREATE TABLE IF NOT EXISTS recon_runs (
    id VARCHAR(64) PRIMARY KEY,
    job_id VARCHAR(64) NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    status VARCHAR(32) NOT NULL DEFAULT 'RUNNING',
    hosts_discovered INT NOT NULL DEFAULT 0,
    hosts_resolved INT NOT NULL DEFAULT 0,
    http_probed INT NOT NULL DEFAULT 0,
    urls_discovered INT NOT NULL DEFAULT 0,
    urls_crawled INT NOT NULL DEFAULT 0,
    errors INT NOT NULL DEFAULT 0,
    skipped_out_of_scope INT NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_recon_runs_job_id ON recon_runs(job_id);
CREATE INDEX IF NOT EXISTS idx_recon_runs_target_id ON recon_runs(target_id);
CREATE INDEX IF NOT EXISTS idx_recon_runs_started_at ON recon_runs(started_at DESC);
