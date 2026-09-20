-- NexusHunter-AI Phase 4: AI-Assisted Security Analysis Engine Schema (PostgreSQL)

-- 1. Analysis Runs Table
CREATE TABLE IF NOT EXISTS analysis_runs (
    id VARCHAR(64) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE CASCADE,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    provider VARCHAR(64) NOT NULL DEFAULT 'mock',
    model VARCHAR(128) NOT NULL DEFAULT '',
    signals_count INT NOT NULL DEFAULT 0,
    candidates_count INT NOT NULL DEFAULT 0,
    summary TEXT,
    confidence_notes TEXT,
    error TEXT,
    execution_time_ms INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_target_id ON analysis_runs(target_id);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_asset_id ON analysis_runs(asset_id);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_status ON analysis_runs(status);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_created_at ON analysis_runs(created_at DESC);

-- 2. Security Signals Table (Deterministic Pre-LLM Signals)
CREATE TABLE IF NOT EXISTS security_signals (
    id VARCHAR(64) PRIMARY KEY,
    analysis_run_id VARCHAR(64) REFERENCES analysis_runs(id) ON DELETE CASCADE,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE CASCADE,
    signal_type VARCHAR(128) NOT NULL,
    severity_hint VARCHAR(32) NOT NULL DEFAULT 'LOW',
    evidence TEXT NOT NULL,
    source VARCHAR(64) NOT NULL DEFAULT 'deterministic_detector',
    url TEXT,
    details JSONB,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_signals_target_id ON security_signals(target_id);
CREATE INDEX IF NOT EXISTS idx_security_signals_asset_id ON security_signals(asset_id);
CREATE INDEX IF NOT EXISTS idx_security_signals_run_id ON security_signals(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_security_signals_type ON security_signals(signal_type);
CREATE INDEX IF NOT EXISTS idx_security_signals_severity ON security_signals(severity_hint);

-- 3. Finding Candidates Table (Strictly Candidates, Never Auto-Confirmed)
CREATE TABLE IF NOT EXISTS finding_candidates (
    id VARCHAR(64) PRIMARY KEY,
    analysis_run_id VARCHAR(64) REFERENCES analysis_runs(id) ON DELETE CASCADE,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE CASCADE,
    category VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    state VARCHAR(32) NOT NULL DEFAULT 'CANDIDATE',
    confidence_score NUMERIC(4,3) NOT NULL DEFAULT 0.500,
    reasoning TEXT NOT NULL DEFAULT '',
    missing_evidence TEXT NOT NULL DEFAULT '',
    validation_steps JSONB NOT NULL DEFAULT '[]',
    evidence_references JSONB NOT NULL DEFAULT '[]',
    recommended_verification TEXT NOT NULL DEFAULT '',
    is_mock BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_candidates_target_id ON finding_candidates(target_id);
CREATE INDEX IF NOT EXISTS idx_candidates_asset_id ON finding_candidates(asset_id);
CREATE INDEX IF NOT EXISTS idx_candidates_run_id ON finding_candidates(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_candidates_category ON finding_candidates(category);
CREATE INDEX IF NOT EXISTS idx_candidates_state ON finding_candidates(state);
CREATE INDEX IF NOT EXISTS idx_candidates_confidence ON finding_candidates(confidence_score DESC);
CREATE INDEX IF NOT EXISTS idx_candidates_created_at ON finding_candidates(created_at DESC);

-- 4. Candidate Evidence Association Table
CREATE TABLE IF NOT EXISTS candidate_evidence (
    id VARCHAR(64) PRIMARY KEY,
    candidate_id VARCHAR(64) NOT NULL REFERENCES finding_candidates(id) ON DELETE CASCADE,
    evidence_type VARCHAR(64) NOT NULL,
    reference_id VARCHAR(255) NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    sha256 VARCHAR(64) NOT NULL DEFAULT '',
    details JSONB,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_candidate_evidence_cand_id ON candidate_evidence(candidate_id);
CREATE INDEX IF NOT EXISTS idx_candidate_evidence_type ON candidate_evidence(evidence_type);
CREATE INDEX IF NOT EXISTS idx_candidate_evidence_sha256 ON candidate_evidence(sha256);
