-- NexusHunter-AI: Phase 7 Security Reasoning, Hypothesis & Investigation Intelligence Engine Schema (PostgreSQL)

-- 1. Reasoning Signals (Deterministic observations, NOT vulnerabilities)
CREATE TABLE IF NOT EXISTS reasoning_signals (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    endpoint VARCHAR(512),
    signal_type VARCHAR(64) NOT NULL,
    category VARCHAR(64) NOT NULL,
    title VARCHAR(256) NOT NULL,
    description TEXT NOT NULL,
    epistemic_status VARCHAR(32) NOT NULL DEFAULT 'OBSERVED',
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
    severity_of_attention VARCHAR(32) NOT NULL DEFAULT 'INFO',
    source_observations JSONB NOT NULL DEFAULT '[]',
    source_evidence JSONB NOT NULL DEFAULT '[]',
    detector VARCHAR(128) NOT NULL,
    detector_version VARCHAR(32) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_signals_target_id ON reasoning_signals(target_id);
CREATE INDEX IF NOT EXISTS idx_signals_asset_id ON reasoning_signals(asset_id);
CREATE INDEX IF NOT EXISTS idx_signals_type ON reasoning_signals(signal_type);
CREATE INDEX IF NOT EXISTS idx_signals_status ON reasoning_signals(status);
CREATE INDEX IF NOT EXISTS idx_signals_created_at ON reasoning_signals(created_at DESC);

-- 2. Hypothesis Groups (Mutually competing explanations)
CREATE TABLE IF NOT EXISTS hypothesis_groups (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    subject VARCHAR(256) NOT NULL,
    signals JSONB NOT NULL DEFAULT '[]',
    hypothesis_ids JSONB NOT NULL DEFAULT '[]',
    active_investigation VARCHAR(128),
    has_competing_theories BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hypo_groups_target_id ON hypothesis_groups(target_id);
CREATE INDEX IF NOT EXISTS idx_hypo_groups_asset_id ON hypothesis_groups(asset_id);

-- 3. Hypotheses (Formal, testable theories)
CREATE TABLE IF NOT EXISTS hypotheses (
    id VARCHAR(128) PRIMARY KEY,
    group_id VARCHAR(128) NOT NULL REFERENCES hypothesis_groups(id) ON DELETE CASCADE,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    endpoint VARCHAR(512),
    title VARCHAR(256) NOT NULL,
    description TEXT NOT NULL,
    category VARCHAR(64) NOT NULL,
    epistemic_status VARCHAR(32) NOT NULL DEFAULT 'HYPOTHESIZED',
    status VARCHAR(32) NOT NULL DEFAULT 'HYPOTHESIZED',
    reasoning_method VARCHAR(128) NOT NULL,
    supporting_signals JSONB NOT NULL DEFAULT '[]',
    supporting_evidence JSONB NOT NULL DEFAULT '[]',
    contradicting_evidence JSONB NOT NULL DEFAULT '[]',
    alternative_hypotheses JSONB NOT NULL DEFAULT '[]',
    recommended_investigations JSONB NOT NULL DEFAULT '[]',
    evidence_strength INT NOT NULL DEFAULT 0,
    investigation_priority INT NOT NULL DEFAULT 0,
    priority_breakdown JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_hypo_target_id ON hypotheses(target_id);
CREATE INDEX IF NOT EXISTS idx_hypo_group_id ON hypotheses(group_id);
CREATE INDEX IF NOT EXISTS idx_hypo_asset_id ON hypotheses(asset_id);
CREATE INDEX IF NOT EXISTS idx_hypo_status ON hypotheses(status);
CREATE INDEX IF NOT EXISTS idx_hypo_priority ON hypotheses(investigation_priority DESC);

-- 4. Falsification Conditions ("What would prove this hypothesis wrong?")
CREATE TABLE IF NOT EXISTS falsification_conditions (
    id VARCHAR(128) PRIMARY KEY,
    hypothesis_id VARCHAR(128) NOT NULL REFERENCES hypotheses(id) ON DELETE CASCADE,
    condition_description TEXT NOT NULL,
    required_evidence TEXT NOT NULL,
    validation_method VARCHAR(128) NOT NULL,
    result VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    evidence_refs JSONB NOT NULL DEFAULT '[]',
    evaluated_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_falsification_hypo_id ON falsification_conditions(hypothesis_id);

-- 5. Evidence Requirements ("What do we NOT know?")
CREATE TABLE IF NOT EXISTS evidence_requirements (
    id VARCHAR(128) PRIMARY KEY,
    hypothesis_id VARCHAR(128) NOT NULL REFERENCES hypotheses(id) ON DELETE CASCADE,
    description TEXT NOT NULL,
    importance VARCHAR(32) NOT NULL DEFAULT 'HIGH',
    evidence_type VARCHAR(64) NOT NULL,
    collection_method VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'MISSING',
    satisfied_by_ref VARCHAR(128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_req_hypo_id ON evidence_requirements(hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_evidence_req_status ON evidence_requirements(status);

-- 6. Investigations (Bounded, safe, non-destructive validation plans)
CREATE TABLE IF NOT EXISTS investigations (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    hypothesis_id VARCHAR(128) NOT NULL REFERENCES hypotheses(id) ON DELETE CASCADE,
    group_id VARCHAR(128) REFERENCES hypothesis_groups(id) ON DELETE SET NULL,
    title VARCHAR(256) NOT NULL,
    objective TEXT NOT NULL,
    priority VARCHAR(32) NOT NULL DEFAULT 'MEDIUM',
    priority_score INT NOT NULL DEFAULT 50,
    priority_factors JSONB NOT NULL DEFAULT '{}',
    status VARCHAR(32) NOT NULL DEFAULT 'PLANNED',
    steps JSONB NOT NULL DEFAULT '[]',
    result_summary TEXT,
    generated_evidence JSONB NOT NULL DEFAULT '[]',
    updated_hypothesis VARCHAR(128),
    created_by VARCHAR(64) NOT NULL DEFAULT 'SYSTEM',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_investigations_target_id ON investigations(target_id);
CREATE INDEX IF NOT EXISTS idx_investigations_hypo_id ON investigations(hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status);

-- 7. Trust Boundaries (Observed or inferred security perimeter transitions)
CREATE TABLE IF NOT EXISTS trust_boundaries (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    boundary_name VARCHAR(128) NOT NULL,
    from_tier VARCHAR(64) NOT NULL,
    to_tier VARCHAR(64) NOT NULL,
    epistemic_status VARCHAR(32) NOT NULL DEFAULT 'INFERRED',
    evidence_refs JSONB NOT NULL DEFAULT '[]',
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trust_boundaries_target_id ON trust_boundaries(target_id);
CREATE INDEX IF NOT EXISTS idx_trust_boundaries_asset_id ON trust_boundaries(asset_id);

-- 8. Auth Contexts (Authorized researcher identities, NO autonomous credential attacks)
CREATE TABLE IF NOT EXISTS auth_contexts (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    authorization_basis TEXT NOT NULL,
    scope_constraint VARCHAR(256) NOT NULL,
    headers JSONB NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_contexts_target_id ON auth_contexts(target_id);

-- 9. Permission Matrix Entries (Context x Resource verified decisions)
CREATE TABLE IF NOT EXISTS permission_matrix_entries (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    endpoint VARCHAR(512) NOT NULL,
    context_id VARCHAR(128) NOT NULL REFERENCES auth_contexts(id) ON DELETE CASCADE,
    context_name VARCHAR(128) NOT NULL,
    state VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    status_code INT NOT NULL DEFAULT 0,
    evidence_refs JSONB NOT NULL DEFAULT '[]',
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_perm_matrix_target ON permission_matrix_entries(target_id);
CREATE INDEX IF NOT EXISTS idx_perm_matrix_endpoint ON permission_matrix_entries(endpoint);
CREATE INDEX IF NOT EXISTS idx_perm_matrix_context ON permission_matrix_entries(context_id);

-- 10. Security Control Records (Posture verification)
CREATE TABLE IF NOT EXISTS security_control_records (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    endpoint VARCHAR(512),
    control_name VARCHAR(128) NOT NULL,
    expected_state VARCHAR(32) NOT NULL,
    observed_state VARCHAR(32) NOT NULL,
    is_contradicted BOOLEAN NOT NULL DEFAULT false,
    evidence_refs JSONB NOT NULL DEFAULT '[]',
    confidence NUMERIC(4,3) NOT NULL DEFAULT 1.0,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sec_controls_target_id ON security_control_records(target_id);
CREATE INDEX IF NOT EXISTS idx_sec_controls_asset_id ON security_control_records(asset_id);

-- 11. Reasoning Runs (Execution telemetry & audit log)
CREATE TABLE IF NOT EXISTS reasoning_runs (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    engine VARCHAR(128) NOT NULL,
    engine_version VARCHAR(32) NOT NULL,
    input_count INT NOT NULL DEFAULT 0,
    signals_count INT NOT NULL DEFAULT 0,
    hypotheses_count INT NOT NULL DEFAULT 0,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'SUCCESS',
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reasoning_runs_target_id ON reasoning_runs(target_id);
CREATE INDEX IF NOT EXISTS idx_reasoning_runs_created_at ON reasoning_runs(created_at DESC);
