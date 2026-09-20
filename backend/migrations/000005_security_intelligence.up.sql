-- NexusHunter-AI: Differentiated Security Intelligence Schema (PostgreSQL)

-- 1. Graph Nodes
CREATE TABLE IF NOT EXISTS graph_nodes (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    type VARCHAR(64) NOT NULL,
    label VARCHAR(255) NOT NULL,
    properties JSONB NOT NULL DEFAULT '{}',
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_graph_nodes_target_id ON graph_nodes(target_id);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_asset_id ON graph_nodes(asset_id);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON graph_nodes(type);

-- 2. Graph Edges
CREATE TABLE IF NOT EXISTS graph_edges (
    id VARCHAR(128) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    source_node_id VARCHAR(128) NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    target_node_id VARCHAR(128) NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    relationship VARCHAR(64) NOT NULL,
    weight NUMERIC(5,2) NOT NULL DEFAULT 1.0,
    properties JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_graph_edges_target_id ON graph_edges(target_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(target_node_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_rel ON graph_edges(relationship);

-- 3. Temporal Change Records ("What Changed")
CREATE TABLE IF NOT EXISTS temporal_change_records (
    id VARCHAR(64) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE SET NULL,
    change_type VARCHAR(64) NOT NULL,
    summary TEXT NOT NULL,
    previous_value TEXT NOT NULL DEFAULT '',
    current_value TEXT NOT NULL DEFAULT '',
    source VARCHAR(64) NOT NULL DEFAULT 'temporal_diff_engine',
    confidence NUMERIC(4,3) NOT NULL DEFAULT 0.95,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_temporal_changes_target_id ON temporal_change_records(target_id);
CREATE INDEX IF NOT EXISTS idx_temporal_changes_asset_id ON temporal_change_records(asset_id);
CREATE INDEX IF NOT EXISTS idx_temporal_changes_type ON temporal_change_records(change_type);
CREATE INDEX IF NOT EXISTS idx_temporal_changes_detected_at ON temporal_change_records(detected_at DESC);

-- 4. State Invariant Signals
CREATE TABLE IF NOT EXISTS invariant_signals (
    id VARCHAR(64) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL,
    state_from VARCHAR(64) NOT NULL,
    state_to VARCHAR(64) NOT NULL,
    observed_condition TEXT NOT NULL,
    invariant_violation TEXT NOT NULL,
    confidence NUMERIC(4,3) NOT NULL DEFAULT 0.85,
    evidence TEXT NOT NULL DEFAULT '',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invariants_target_id ON invariant_signals(target_id);
CREATE INDEX IF NOT EXISTS idx_invariants_asset_id ON invariant_signals(asset_id);

-- 5. Differential Behavior Records
CREATE TABLE IF NOT EXISTS behavior_differences (
    id VARCHAR(64) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    asset_id VARCHAR(64) REFERENCES assets(id) ON DELETE CASCADE,
    probe_a_url TEXT NOT NULL,
    probe_b_url TEXT NOT NULL,
    context_a VARCHAR(128) NOT NULL,
    context_b VARCHAR(128) NOT NULL,
    status_diff BOOLEAN NOT NULL DEFAULT false,
    length_diff INT NOT NULL DEFAULT 0,
    header_diff JSONB NOT NULL DEFAULT '[]',
    body_diff_fingerprint VARCHAR(64) NOT NULL DEFAULT '',
    state_change_observed BOOLEAN NOT NULL DEFAULT false,
    timing_delta_ms INT NOT NULL DEFAULT 0,
    is_meaningful BOOLEAN NOT NULL DEFAULT false,
    normalized_details JSONB NOT NULL DEFAULT '{}',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_behavior_diffs_target_id ON behavior_differences(target_id);
CREATE INDEX IF NOT EXISTS idx_behavior_diffs_asset_id ON behavior_differences(asset_id);
CREATE INDEX IF NOT EXISTS idx_behavior_diffs_meaningful ON behavior_differences(is_meaningful);

-- 6. Correlated Investigation Clusters
CREATE TABLE IF NOT EXISTS investigation_clusters (
    id VARCHAR(64) PRIMARY KEY,
    target_id VARCHAR(64) NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    category VARCHAR(64) NOT NULL,
    priority_score INT NOT NULL DEFAULT 50,
    priority_explanation TEXT NOT NULL DEFAULT '',
    priority_factors JSONB NOT NULL DEFAULT '[]',
    related_assets JSONB NOT NULL DEFAULT '[]',
    related_endpoints JSONB NOT NULL DEFAULT '[]',
    confidence NUMERIC(4,3) NOT NULL DEFAULT 0.75,
    reason TEXT NOT NULL DEFAULT '',
    recommended_validation JSONB NOT NULL DEFAULT '[]',
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_clusters_target_id ON investigation_clusters(target_id);
CREATE INDEX IF NOT EXISTS idx_clusters_priority ON investigation_clusters(priority_score DESC);
CREATE INDEX IF NOT EXISTS idx_clusters_status ON investigation_clusters(status);

-- 7. Controlled Validation Results
CREATE TABLE IF NOT EXISTS controlled_validation_results (
    id VARCHAR(64) PRIMARY KEY,
    candidate_id VARCHAR(64) REFERENCES finding_candidates(id) ON DELETE CASCADE,
    cluster_id VARCHAR(64) REFERENCES investigation_clusters(id) ON DELETE CASCADE,
    success BOOLEAN NOT NULL DEFAULT false,
    state VARCHAR(32) NOT NULL,
    observations JSONB NOT NULL DEFAULT '[]',
    output_fact TEXT NOT NULL DEFAULT '',
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_val_results_cand_id ON controlled_validation_results(candidate_id);
CREATE INDEX IF NOT EXISTS idx_val_results_cluster_id ON controlled_validation_results(cluster_id);
