-- NexusHunter-AI: Phase 6 Evidence Intelligence & Security Reasoning Schema (PostgreSQL)

-- 1. First-Class Evidence Records
CREATE TABLE IF NOT EXISTS evidence_records (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    observation_id VARCHAR(128),
    candidate_id VARCHAR(64) REFERENCES finding_candidates(id) ON DELETE SET NULL,
    source VARCHAR(64) NOT NULL,
    evidence_type VARCHAR(64) NOT NULL,
    summary TEXT NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status_code INT NOT NULL DEFAULT 0,
    request_data JSONB NOT NULL DEFAULT '{}',
    response_data JSONB NOT NULL DEFAULT '{}',
    relevant_headers JSONB NOT NULL DEFAULT '{}',
    redirect_chain JSONB NOT NULL DEFAULT '[]',
    dns_context JSONB NOT NULL DEFAULT '{}',
    tls_metadata JSONB NOT NULL DEFAULT '{}',
    validation_context JSONB NOT NULL DEFAULT '{}',
    scope_decision JSONB NOT NULL DEFAULT '{}',
    redaction_status JSONB NOT NULL DEFAULT '{}',
    canonical_representation TEXT NOT NULL DEFAULT '',
    sha256 VARCHAR(64) NOT NULL,
    provenance JSONB NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_target_id ON evidence_records(target_id);
CREATE INDEX IF NOT EXISTS idx_evidence_asset_id ON evidence_records(asset_id);
CREATE INDEX IF NOT EXISTS idx_evidence_type ON evidence_records(evidence_type);
CREATE INDEX IF NOT EXISTS idx_evidence_sha256 ON evidence_records(sha256);
CREATE INDEX IF NOT EXISTS idx_evidence_captured_at ON evidence_records(captured_at DESC);

-- 2. Evidence Diffs (Level 1, Level 2, Level 3 differences)
CREATE TABLE IF NOT EXISTS evidence_diffs (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    evidence_a_id VARCHAR(128) NOT NULL REFERENCES evidence_records(id) ON DELETE CASCADE,
    evidence_b_id VARCHAR(128) NOT NULL REFERENCES evidence_records(id) ON DELETE CASCADE,
    raw_diff JSONB NOT NULL DEFAULT '{}',
    semantic_diff JSONB NOT NULL DEFAULT '{}',
    security_diff JSONB NOT NULL DEFAULT '{}',
    is_noise_filtered BOOLEAN NOT NULL DEFAULT true,
    is_security_relevant BOOLEAN NOT NULL DEFAULT false,
    computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_diffs_target_id ON evidence_diffs(target_id);
CREATE INDEX IF NOT EXISTS idx_diffs_asset_id ON evidence_diffs(asset_id);
CREATE INDEX IF NOT EXISTS idx_diffs_ev_a ON evidence_diffs(evidence_a_id);
CREATE INDEX IF NOT EXISTS idx_diffs_ev_b ON evidence_diffs(evidence_b_id);

-- 3. Security Expectations (Expected Model)
CREATE TABLE IF NOT EXISTS security_expectations (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    endpoint TEXT NOT NULL DEFAULT '',
    control_name VARCHAR(128) NOT NULL,
    source VARCHAR(64) NOT NULL,
    expected_state VARCHAR(32) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    rule_details JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_expectations_target_id ON security_expectations(target_id);
CREATE INDEX IF NOT EXISTS idx_expectations_asset_id ON security_expectations(asset_id);
CREATE INDEX IF NOT EXISTS idx_expectations_control ON security_expectations(control_name);

-- 4. Security Contradictions (Contradiction Foundation)
CREATE TABLE IF NOT EXISTS security_contradictions (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    endpoint TEXT NOT NULL DEFAULT '',
    contradiction_type VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'UNVERIFIED',
    severity VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    expectation_id VARCHAR(128) REFERENCES security_expectations(id) ON DELETE SET NULL,
    observed_state VARCHAR(32) NOT NULL,
    evidence_refs JSONB NOT NULL DEFAULT '[]',
    explanation TEXT NOT NULL DEFAULT '',
    suggested_followup JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_contradictions_target_id ON security_contradictions(target_id);
CREATE INDEX IF NOT EXISTS idx_contradictions_asset_id ON security_contradictions(asset_id);
CREATE INDEX IF NOT EXISTS idx_contradictions_type ON security_contradictions(contradiction_type);
CREATE INDEX IF NOT EXISTS idx_contradictions_status ON security_contradictions(status);

-- 5. Security Outliers (Outlier Foundation)
CREATE TABLE IF NOT EXISTS security_outliers (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    endpoint TEXT NOT NULL DEFAULT '',
    comparison_group VARCHAR(128) NOT NULL,
    observed_value TEXT NOT NULL DEFAULT '',
    baseline_value TEXT NOT NULL DEFAULT '',
    deviation_type VARCHAR(64) NOT NULL,
    evidence_refs JSONB NOT NULL DEFAULT '[]',
    confidence NUMERIC(4,3) NOT NULL DEFAULT 0.85,
    details JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_outliers_target_id ON security_outliers(target_id);
CREATE INDEX IF NOT EXISTS idx_outliers_asset_id ON security_outliers(asset_id);

-- 6. Evidence Timeline Events
CREATE TABLE IF NOT EXISTS evidence_timeline_events (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    event_type VARCHAR(64) NOT NULL,
    summary TEXT NOT NULL,
    epistemic_status VARCHAR(32) NOT NULL DEFAULT 'OBSERVED',
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    provenance JSONB NOT NULL DEFAULT '{}',
    reference_id VARCHAR(128) NOT NULL DEFAULT '',
    details JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_timeline_target_id ON evidence_timeline_events(target_id);
CREATE INDEX IF NOT EXISTS idx_timeline_asset_id ON evidence_timeline_events(asset_id);
CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON evidence_timeline_events(timestamp DESC);
