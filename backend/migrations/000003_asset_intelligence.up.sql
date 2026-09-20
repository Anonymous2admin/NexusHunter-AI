-- NexusHunter-AI Phase 3: Asset Intelligence & Technology Fingerprinting Schema (PostgreSQL)

-- 1. Technology Observations Table
CREATE TABLE IF NOT EXISTS technology_observations (
    id VARCHAR(64) PRIMARY KEY,
    asset_id VARCHAR(64) NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    service_id VARCHAR(64) REFERENCES http_services(id) ON DELETE SET NULL,
    technology_name VARCHAR(128) NOT NULL,
    category VARCHAR(64) NOT NULL,
    version VARCHAR(64),
    confidence VARCHAR(16) NOT NULL DEFAULT 'LOW',
    detection_source VARCHAR(64) NOT NULL,
    evidence TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_tech_obs_asset_tech_ver UNIQUE(asset_id, technology_name, version)
);

CREATE INDEX IF NOT EXISTS idx_tech_obs_target_id ON technology_observations(target_id);
CREATE INDEX IF NOT EXISTS idx_tech_obs_asset_id ON technology_observations(asset_id);
CREATE INDEX IF NOT EXISTS idx_tech_obs_category ON technology_observations(category);
CREATE INDEX IF NOT EXISTS idx_tech_obs_confidence ON technology_observations(confidence);
CREATE INDEX IF NOT EXISTS idx_tech_obs_name ON technology_observations(technology_name);

-- 2. Service Observations Table (Enhanced Service Identity & Metadata)
CREATE TABLE IF NOT EXISTS service_observations (
    id VARCHAR(64) PRIMARY KEY,
    asset_id VARCHAR(64) NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    service_identity VARCHAR(255) NOT NULL,
    scheme VARCHAR(16) NOT NULL,
    port INT NOT NULL,
    status_code INT NOT NULL,
    page_title TEXT,
    web_server VARCHAR(255),
    content_type VARCHAR(255),
    content_length BIGINT NOT NULL DEFAULT 0,
    response_time_ms INT NOT NULL DEFAULT 0,
    tls_version VARCHAR(64),
    headers_snapshot JSONB,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_service_obs_asset_ident UNIQUE(asset_id, service_identity)
);

CREATE INDEX IF NOT EXISTS idx_service_obs_target_id ON service_observations(target_id);
CREATE INDEX IF NOT EXISTS idx_service_obs_asset_id ON service_observations(asset_id);
CREATE INDEX IF NOT EXISTS idx_service_obs_port ON service_observations(port);
CREATE INDEX IF NOT EXISTS idx_service_obs_scheme ON service_observations(scheme);
CREATE INDEX IF NOT EXISTS idx_service_obs_status ON service_observations(status_code);

-- 3. Security Observations Table (Passive HTTP Security Properties)
CREATE TABLE IF NOT EXISTS security_observations (
    id VARCHAR(64) PRIMARY KEY,
    asset_id VARCHAR(64) NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    service_id VARCHAR(64) REFERENCES http_services(id) ON DELETE SET NULL,
    property_name VARCHAR(128) NOT NULL,
    is_present BOOLEAN NOT NULL DEFAULT false,
    details TEXT,
    raw_value TEXT,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_sec_obs_asset_prop UNIQUE(asset_id, property_name)
);

CREATE INDEX IF NOT EXISTS idx_sec_obs_target_id ON security_observations(target_id);
CREATE INDEX IF NOT EXISTS idx_sec_obs_asset_id ON security_observations(asset_id);
CREATE INDEX IF NOT EXISTS idx_sec_obs_prop ON security_observations(property_name);

-- 4. Asset Tags Table (Manual & Automatic Inferred Tags)
CREATE TABLE IF NOT EXISTS asset_tags (
    id VARCHAR(64) PRIMARY KEY,
    asset_id VARCHAR(64) NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    tag VARCHAR(64) NOT NULL,
    is_inferred BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(64) NOT NULL DEFAULT 'system',
    CONSTRAINT uq_asset_tags_asset_tag UNIQUE(asset_id, tag)
);

CREATE INDEX IF NOT EXISTS idx_asset_tags_target_id ON asset_tags(target_id);
CREATE INDEX IF NOT EXISTS idx_asset_tags_asset_id ON asset_tags(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_tags_tag ON asset_tags(tag);

-- 5. Asset Changes Table (Scan-to-Scan Comparison & History)
CREATE TABLE IF NOT EXISTS asset_changes (
    id VARCHAR(64) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    change_type VARCHAR(32) NOT NULL,
    entity_type VARCHAR(32) NOT NULL,
    entity_id VARCHAR(64) NOT NULL,
    previous_state JSONB,
    current_state JSONB,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asset_changes_target_id ON asset_changes(target_id);
CREATE INDEX IF NOT EXISTS idx_asset_changes_asset_id ON asset_changes(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_changes_type ON asset_changes(change_type);
CREATE INDEX IF NOT EXISTS idx_asset_changes_detected_at ON asset_changes(detected_at DESC);

-- 6. Page Assets Table (Static JS, CSS, SourceMaps, API Endpoints)
CREATE TABLE IF NOT EXISTS page_assets (
    id VARCHAR(64) PRIMARY KEY,
    asset_id VARCHAR(64) NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    asset_type VARCHAR(32) NOT NULL,
    source_page TEXT NOT NULL,
    is_in_scope BOOLEAN NOT NULL DEFAULT true,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_page_assets_asset_url UNIQUE(asset_id, url)
);

CREATE INDEX IF NOT EXISTS idx_page_assets_asset_id ON page_assets(asset_id);
CREATE INDEX IF NOT EXISTS idx_page_assets_target_id ON page_assets(target_id);
CREATE INDEX IF NOT EXISTS idx_page_assets_type ON page_assets(asset_type);
