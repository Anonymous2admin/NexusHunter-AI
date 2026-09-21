-- NexusHunter-AI: Phase 8 Scope, JS Intel, Cloud References, WAF & AI Hunting Planner Schema

-- 1. Scope Import Reviews
CREATE TABLE IF NOT EXISTS scope_imports (
    id VARCHAR(128) PRIMARY KEY,
    file_name VARCHAR(256) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING_CONFIRMATION',
    selected_root_domain VARCHAR(256) NOT NULL,
    target_id VARCHAR(64) REFERENCES targets(id) ON DELETE SET NULL,
    rules_discovered INT NOT NULL DEFAULT 0,
    include_hosts_count INT NOT NULL DEFAULT 0,
    exclude_hosts_count INT NOT NULL DEFAULT 0,
    regex_rules_count INT NOT NULL DEFAULT 0,
    path_rules_count INT NOT NULL DEFAULT 0,
    warnings_count INT NOT NULL DEFAULT 0,
    ambiguous_count INT NOT NULL DEFAULT 0,
    root_domains JSONB NOT NULL DEFAULT '[]',
    normalizations JSONB NOT NULL DEFAULT '[]',
    canonical_scope JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scope_imports_status ON scope_imports(status);
CREATE INDEX IF NOT EXISTS idx_scope_imports_target ON scope_imports(target_id);

-- 2. JavaScript Assets
CREATE TABLE IF NOT EXISTS js_assets (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    url TEXT NOT NULL,
    parent_url TEXT NOT NULL,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scope_in_scope BOOLEAN NOT NULL DEFAULT true,
    scope_reason VARCHAR(256),
    content_sha256 VARCHAR(64),
    byte_size BIGINT NOT NULL DEFAULT 0,
    is_third_party BOOLEAN NOT NULL DEFAULT false,
    fetch_status VARCHAR(32) NOT NULL DEFAULT 'DISCOVERED',
    line_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_js_assets_target ON js_assets(target_id);
CREATE INDEX IF NOT EXISTS idx_js_assets_asset ON js_assets(asset_id);
CREATE INDEX IF NOT EXISTS idx_js_assets_url ON js_assets(url);

-- 3. JavaScript Structural References
CREATE TABLE IF NOT EXISTS js_references (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    js_asset_id VARCHAR(128) NOT NULL REFERENCES js_assets(id) ON DELETE CASCADE,
    source_url TEXT NOT NULL,
    category VARCHAR(64) NOT NULL,
    extracted_value TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    line_number INT,
    byte_offset BIGINT,
    source_fragment TEXT,
    scope_status VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    confidence VARCHAR(32) NOT NULL DEFAULT 'HIGH',
    evidence_id VARCHAR(128) REFERENCES evidence_records(id) ON DELETE SET NULL,
    provenance_sha VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_js_refs_target ON js_references(target_id);
CREATE INDEX IF NOT EXISTS idx_js_refs_asset ON js_references(asset_id);
CREATE INDEX IF NOT EXISTS idx_js_refs_category ON js_references(category);
CREATE INDEX IF NOT EXISTS idx_js_refs_js_asset ON js_references(js_asset_id);

-- 4. JavaScript Secret Indicators (Strictly Redacted)
CREATE TABLE IF NOT EXISTS js_secret_indicators (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    js_asset_id VARCHAR(128) NOT NULL REFERENCES js_assets(id) ON DELETE CASCADE,
    secret_type VARCHAR(64) NOT NULL,
    location VARCHAR(128) NOT NULL,
    masked_preview VARCHAR(128) NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    confidence VARCHAR(32) NOT NULL DEFAULT 'HIGH',
    source_js_asset TEXT NOT NULL,
    evidence_id VARCHAR(128) REFERENCES evidence_records(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_js_secrets_target ON js_secret_indicators(target_id);
CREATE INDEX IF NOT EXISTS idx_js_secrets_type ON js_secret_indicators(secret_type);

-- 5. Cloud References
CREATE TABLE IF NOT EXISTS cloud_references (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    provider VARCHAR(64) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    raw_reference TEXT NOT NULL,
    normalized_target TEXT NOT NULL,
    source_origin VARCHAR(64) NOT NULL,
    source_location TEXT NOT NULL,
    scope_status VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    validation_status VARCHAR(32) NOT NULL DEFAULT 'UNCHECKED',
    status_code INT,
    public_accessible BOOLEAN NOT NULL DEFAULT false,
    evidence_id VARCHAR(128) REFERENCES evidence_records(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cloud_refs_target ON cloud_references(target_id);
CREATE INDEX IF NOT EXISTS idx_cloud_refs_provider ON cloud_references(provider);

-- 6. WAF Observations
CREATE TABLE IF NOT EXISTS waf_observations (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    provider VARCHAR(64) NOT NULL,
    confidence VARCHAR(32) NOT NULL DEFAULT 'LOW',
    evidence_ids JSONB NOT NULL DEFAULT '[]',
    matched_indicators JSONB NOT NULL DEFAULT '[]',
    observed_headers JSONB NOT NULL DEFAULT '[]',
    throttling_state VARCHAR(32) NOT NULL DEFAULT 'NORMAL',
    current_rate_limit_rps DOUBLE PRECISION NOT NULL DEFAULT 10.0,
    retry_after_seconds INT,
    circuit_breaker_open BOOLEAN NOT NULL DEFAULT false,
    throttle_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_waf_target ON waf_observations(target_id);
CREATE INDEX IF NOT EXISTS idx_waf_asset ON waf_observations(asset_id);

-- 7. Investigation Plans
CREATE TABLE IF NOT EXISTS investigation_plans (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    hypothesis_id VARCHAR(128) REFERENCES hypotheses(id) ON DELETE SET NULL,
    title VARCHAR(256) NOT NULL,
    reason TEXT NOT NULL,
    hypothesis TEXT NOT NULL,
    why_interesting JSONB NOT NULL DEFAULT '{}',
    required_evidence JSONB NOT NULL DEFAULT '[]',
    evidence_required_count INT NOT NULL DEFAULT 0,
    evidence_satisfied_count INT NOT NULL DEFAULT 0,
    safe_validation TEXT NOT NULL,
    expected_observation TEXT NOT NULL,
    alternative_explanation TEXT NOT NULL,
    stop_condition TEXT NOT NULL,
    scope_requirements JSONB NOT NULL DEFAULT '[]',
    risk VARCHAR(32) NOT NULL DEFAULT 'LOW',
    confidence VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
    epistemic_status VARCHAR(32) NOT NULL DEFAULT 'HYPOTHESIZED',
    status VARCHAR(32) NOT NULL DEFAULT 'PLANNED',
    source_evidence_ids JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_inv_plans_target ON investigation_plans(target_id);
CREATE INDEX IF NOT EXISTS idx_inv_plans_status ON investigation_plans(status);

-- 8. Investigation Plan Steps
CREATE TABLE IF NOT EXISTS investigation_plan_steps (
    id BIGSERIAL PRIMARY KEY,
    plan_id VARCHAR(128) NOT NULL REFERENCES investigation_plans(id) ON DELETE CASCADE,
    step_number INT NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    description TEXT NOT NULL,
    target_url TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    approved_by_human BOOLEAN NOT NULL DEFAULT false,
    approved_at TIMESTAMPTZ,
    result_evidence_id VARCHAR(128) REFERENCES evidence_records(id) ON DELETE SET NULL,
    result_observation TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_plan_steps_plan ON investigation_plan_steps(plan_id);
