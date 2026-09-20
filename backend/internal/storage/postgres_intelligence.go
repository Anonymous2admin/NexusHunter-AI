package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// SaveGraphNode inserts or updates a node in the asset relationship graph.
func (p *PostgresStorage) SaveGraphNode(ctx context.Context, node *models.GraphNode) error {
	propsJSON, err := json.Marshal(node.Properties)
	if err != nil {
		propsJSON = []byte("{}")
	}

	query := `
		INSERT INTO graph_nodes (id, target_id, asset_id, type, label, properties, first_seen, last_seen)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO UPDATE SET
			label = EXCLUDED.label,
			properties = EXCLUDED.properties,
			last_seen = EXCLUDED.last_seen
	`
	_, err = p.db.ExecContext(ctx, query,
		node.ID,
		node.TargetID,
		node.AssetID,
		string(node.Type),
		node.Label,
		propsJSON,
		node.FirstSeen,
		node.LastSeen,
	)
	return err
}

// SaveGraphEdge inserts a directed relationship into the graph.
func (p *PostgresStorage) SaveGraphEdge(ctx context.Context, edge *models.GraphEdge) error {
	propsJSON, err := json.Marshal(edge.Properties)
	if err != nil {
		propsJSON = []byte("{}")
	}

	query := `
		INSERT INTO graph_edges (id, target_id, source_node_id, target_node_id, relationship, weight, properties, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO NOTHING
	`
	_, err = p.db.ExecContext(ctx, query,
		edge.ID,
		edge.TargetID,
		edge.SourceNodeID,
		edge.TargetNodeID,
		string(edge.Relationship),
		edge.Weight,
		propsJSON,
		edge.CreatedAt,
	)
	return err
}

// GetTargetGraph retrieves the complete graph data for a target.
func (p *PostgresStorage) GetTargetGraph(ctx context.Context, targetID string) (*models.GraphData, error) {
	// Fetch nodes
	nodeQuery := `
		SELECT id, target_id, COALESCE(asset_id, ''), type, label, properties, first_seen, last_seen
		FROM graph_nodes
		WHERE target_id = $1
		ORDER BY first_seen ASC
	`
	rows, err := p.db.QueryContext(ctx, nodeQuery, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []*models.GraphNode
	metrics := make(map[string]int)

	for rows.Next() {
		var n models.GraphNode
		var typeStr string
		var propsRaw []byte

		if err := rows.Scan(&n.ID, &n.TargetID, &n.AssetID, &typeStr, &n.Label, &propsRaw, &n.FirstSeen, &n.LastSeen); err != nil {
			return nil, err
		}
		n.Type = models.GraphNodeType(typeStr)
		if len(propsRaw) > 0 {
			_ = json.Unmarshal(propsRaw, &n.Properties)
		}
		metrics[typeStr]++
		nodes = append(nodes, &n)
	}

	// Fetch edges
	edgeQuery := `
		SELECT id, target_id, source_node_id, target_node_id, relationship, weight, properties, created_at
		FROM graph_edges
		WHERE target_id = $1
		ORDER BY created_at ASC
	`
	eRows, err := p.db.QueryContext(ctx, edgeQuery, targetID)
	if err != nil {
		return nil, err
	}
	defer eRows.Close()

	var edges []*models.GraphEdge
	for eRows.Next() {
		var e models.GraphEdge
		var relStr string
		var propsRaw []byte

		if err := eRows.Scan(&e.ID, &e.TargetID, &e.SourceNodeID, &e.TargetNodeID, &relStr, &e.Weight, &propsRaw, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Relationship = models.GraphEdgeType(relStr)
		if len(propsRaw) > 0 {
			_ = json.Unmarshal(propsRaw, &e.Properties)
		}
		edges = append(edges, &e)
	}

	return &models.GraphData{
		TargetID:   targetID,
		Nodes:      nodes,
		Edges:      edges,
		TotalNodes: len(nodes),
		TotalEdges: len(edges),
		Metrics:    metrics,
	}, nil
}

// RecordTemporalChange records a temporal diff event.
func (p *PostgresStorage) RecordTemporalChange(ctx context.Context, record *models.TemporalChangeRecord) error {
	detailsJSON, err := json.Marshal(record.Details)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	query := `
		INSERT INTO temporal_change_records (id, target_id, asset_id, change_type, summary, previous_value, current_value, source, confidence, first_seen, last_seen, detected_at, details)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	_, err = p.db.ExecContext(ctx, query,
		record.ID,
		record.TargetID,
		record.AssetID,
		string(record.ChangeType),
		record.Summary,
		record.PreviousValue,
		record.CurrentValue,
		record.Source,
		record.Confidence,
		record.FirstSeen,
		record.LastSeen,
		record.DetectedAt,
		detailsJSON,
	)
	return err
}

// ListTemporalChanges lists chronological changes for a target.
func (p *PostgresStorage) ListTemporalChanges(ctx context.Context, targetID string, limit int) ([]*models.TemporalChangeRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), change_type, summary, previous_value, current_value, source, confidence, first_seen, last_seen, detected_at, details
		FROM temporal_change_records
		WHERE target_id = $1
		ORDER BY detected_at DESC
		LIMIT $2
	`
	rows, err := p.db.QueryContext(ctx, query, targetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []*models.TemporalChangeRecord
	for rows.Next() {
		var r models.TemporalChangeRecord
		var typeStr string
		var detailsRaw []byte

		if err := rows.Scan(&r.ID, &r.TargetID, &r.AssetID, &typeStr, &r.Summary, &r.PreviousValue, &r.CurrentValue, &r.Source, &r.Confidence, &r.FirstSeen, &r.LastSeen, &r.DetectedAt, &detailsRaw); err != nil {
			return nil, err
		}
		r.ChangeType = models.TemporalChangeType(typeStr)
		if len(detailsRaw) > 0 {
			_ = json.Unmarshal(detailsRaw, &r.Details)
		}
		records = append(records, &r)
	}
	return records, nil
}

// RecordInvariantSignal records a state-machine invariant violation.
func (p *PostgresStorage) RecordInvariantSignal(ctx context.Context, sig *models.InvariantSignal) error {
	query := `
		INSERT INTO invariant_signals (id, target_id, asset_id, endpoint, state_from, state_to, observed_condition, invariant_violation, confidence, evidence, detected_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := p.db.ExecContext(ctx, query,
		sig.ID,
		sig.TargetID,
		sig.AssetID,
		sig.Endpoint,
		string(sig.StateFrom),
		string(sig.StateTo),
		sig.ObservedCondition,
		sig.InvariantViolation,
		sig.Confidence,
		sig.Evidence,
		sig.DetectedAt,
	)
	return err
}

// ListInvariantSignals lists invariant violations for a target.
func (p *PostgresStorage) ListInvariantSignals(ctx context.Context, targetID string) ([]*models.InvariantSignal, error) {
	query := `
		SELECT id, target_id, asset_id, endpoint, state_from, state_to, observed_condition, invariant_violation, confidence, evidence, detected_at
		FROM invariant_signals
		WHERE target_id = $1
		ORDER BY detected_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sigs []*models.InvariantSignal
	for rows.Next() {
		var s models.InvariantSignal
		var stateFrom, stateTo string
		if err := rows.Scan(&s.ID, &s.TargetID, &s.AssetID, &s.Endpoint, &stateFrom, &stateTo, &s.ObservedCondition, &s.InvariantViolation, &s.Confidence, &s.Evidence, &s.DetectedAt); err != nil {
			return nil, err
		}
		s.StateFrom = models.SecurityState(stateFrom)
		s.StateTo = models.SecurityState(stateTo)
		sigs = append(sigs, &s)
	}
	return sigs, nil
}

// RecordBehaviorDifference inserts a normalized comparative observation.
func (p *PostgresStorage) RecordBehaviorDifference(ctx context.Context, diff *models.BehaviorDifference) error {
	headersJSON, _ := json.Marshal(diff.HeaderDiff)
	detailsJSON, _ := json.Marshal(diff.NormalizedDetails)

	query := `
		INSERT INTO behavior_differences (id, target_id, asset_id, probe_a_url, probe_b_url, context_a, context_b, status_diff, length_diff, header_diff, body_diff_fingerprint, state_change_observed, timing_delta_ms, is_meaningful, normalized_details, detected_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`
	_, err := p.db.ExecContext(ctx, query,
		diff.ID,
		diff.TargetID,
		diff.AssetID,
		diff.ProbeAURL,
		diff.ProbeBURL,
		diff.ContextA,
		diff.ContextB,
		diff.StatusDiff,
		diff.LengthDiff,
		headersJSON,
		diff.BodyDiffFingerprint,
		diff.StateChangeObserved,
		diff.TimingDeltaMS,
		diff.IsMeaningful,
		detailsJSON,
		diff.DetectedAt,
	)
	return err
}

// ListBehaviorDifferences lists differential behavior records for a target.
func (p *PostgresStorage) ListBehaviorDifferences(ctx context.Context, targetID string) ([]*models.BehaviorDifference, error) {
	query := `
		SELECT id, target_id, asset_id, probe_a_url, probe_b_url, context_a, context_b, status_diff, length_diff, header_diff, body_diff_fingerprint, state_change_observed, timing_delta_ms, is_meaningful, normalized_details, detected_at
		FROM behavior_differences
		WHERE target_id = $1
		ORDER BY detected_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var diffs []*models.BehaviorDifference
	for rows.Next() {
		var d models.BehaviorDifference
		var headersRaw, detailsRaw []byte
		if err := rows.Scan(&d.ID, &d.TargetID, &d.AssetID, &d.ProbeAURL, &d.ProbeBURL, &d.ContextA, &d.ContextB, &d.StatusDiff, &d.LengthDiff, &headersRaw, &d.BodyDiffFingerprint, &d.StateChangeObserved, &d.TimingDeltaMS, &d.IsMeaningful, &detailsRaw, &d.DetectedAt); err != nil {
			return nil, err
		}
		if len(headersRaw) > 0 {
			_ = json.Unmarshal(headersRaw, &d.HeaderDiff)
		}
		if len(detailsRaw) > 0 {
			_ = json.Unmarshal(detailsRaw, &d.NormalizedDetails)
		}
		diffs = append(diffs, &d)
	}
	return diffs, nil
}

// SaveInvestigationCluster creates or updates an investigation cluster.
func (p *PostgresStorage) SaveInvestigationCluster(ctx context.Context, cluster *models.InvestigationCluster) error {
	factorsJSON, _ := json.Marshal(cluster.PriorityFactors)
	assetsJSON, _ := json.Marshal(cluster.RelatedAssets)
	endpointsJSON, _ := json.Marshal(cluster.RelatedEndpoints)
	validationJSON, _ := json.Marshal(cluster.RecommendedValidation)

	query := `
		INSERT INTO investigation_clusters (id, target_id, title, category, priority_score, priority_explanation, priority_factors, related_assets, related_endpoints, confidence, reason, recommended_validation, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		ON CONFLICT (id) DO UPDATE SET
			title = EXCLUDED.title,
			priority_score = EXCLUDED.priority_score,
			priority_explanation = EXCLUDED.priority_explanation,
			priority_factors = EXCLUDED.priority_factors,
			related_assets = EXCLUDED.related_assets,
			related_endpoints = EXCLUDED.related_endpoints,
			confidence = EXCLUDED.confidence,
			reason = EXCLUDED.reason,
			recommended_validation = EXCLUDED.recommended_validation,
			status = EXCLUDED.status,
			updated_at = EXCLUDED.updated_at
	`
	_, err := p.db.ExecContext(ctx, query,
		cluster.ID,
		cluster.TargetID,
		cluster.Title,
		cluster.Category,
		cluster.PriorityScore,
		cluster.PriorityExplanation,
		factorsJSON,
		assetsJSON,
		endpointsJSON,
		cluster.Confidence,
		cluster.Reason,
		validationJSON,
		string(cluster.Status),
		cluster.CreatedAt,
		cluster.UpdatedAt,
	)
	return err
}

// GetInvestigationCluster retrieves a single cluster by ID.
func (p *PostgresStorage) GetInvestigationCluster(ctx context.Context, id string) (*models.InvestigationCluster, error) {
	query := `
		SELECT id, target_id, title, category, priority_score, priority_explanation, priority_factors, related_assets, related_endpoints, confidence, reason, recommended_validation, status, created_at, updated_at
		FROM investigation_clusters
		WHERE id = $1
	`
	row := p.db.QueryRowContext(ctx, query, id)

	var c models.InvestigationCluster
	var statusStr string
	var factorsRaw, assetsRaw, endpointsRaw, valRaw []byte

	err := row.Scan(&c.ID, &c.TargetID, &c.Title, &c.Category, &c.PriorityScore, &c.PriorityExplanation, &factorsRaw, &assetsRaw, &endpointsRaw, &c.Confidence, &c.Reason, &valRaw, &statusStr, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	c.Status = models.ClusterStatus(statusStr)
	_ = json.Unmarshal(factorsRaw, &c.PriorityFactors)
	_ = json.Unmarshal(assetsRaw, &c.RelatedAssets)
	_ = json.Unmarshal(endpointsRaw, &c.RelatedEndpoints)
	_ = json.Unmarshal(valRaw, &c.RecommendedValidation)
	return &c, nil
}

// ListInvestigationClusters retrieves all clusters for a target ordered by priority score.
func (p *PostgresStorage) ListInvestigationClusters(ctx context.Context, targetID string) ([]*models.InvestigationCluster, error) {
	query := `
		SELECT id, target_id, title, category, priority_score, priority_explanation, priority_factors, related_assets, related_endpoints, confidence, reason, recommended_validation, status, created_at, updated_at
		FROM investigation_clusters
		WHERE target_id = $1
		ORDER BY priority_score DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clusters []*models.InvestigationCluster
	for rows.Next() {
		var c models.InvestigationCluster
		var statusStr string
		var factorsRaw, assetsRaw, endpointsRaw, valRaw []byte

		if err := rows.Scan(&c.ID, &c.TargetID, &c.Title, &c.Category, &c.PriorityScore, &c.PriorityExplanation, &factorsRaw, &assetsRaw, &endpointsRaw, &c.Confidence, &c.Reason, &valRaw, &statusStr, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.Status = models.ClusterStatus(statusStr)
		_ = json.Unmarshal(factorsRaw, &c.PriorityFactors)
		_ = json.Unmarshal(assetsRaw, &c.RelatedAssets)
		_ = json.Unmarshal(endpointsRaw, &c.RelatedEndpoints)
		_ = json.Unmarshal(valRaw, &c.RecommendedValidation)
		clusters = append(clusters, &c)
	}
	return clusters, nil
}

// UpdateClusterStatus updates status of a cluster.
func (p *PostgresStorage) UpdateClusterStatus(ctx context.Context, id string, status models.ClusterStatus) error {
	query := `
		UPDATE investigation_clusters
		SET status = $1, updated_at = $2
		WHERE id = $3
	`
	res, err := p.db.ExecContext(ctx, query, string(status), time.Now().UTC(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// GetResearchMemory aggregates target statistics.
func (p *PostgresStorage) GetResearchMemory(ctx context.Context, targetID string) (*models.ResearchMemory, error) {
	mem := &models.ResearchMemory{
		TargetID:   targetID,
		LastScanAt: time.Now().UTC(),
	}

	_ = p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM assets WHERE target_id = $1", targetID).Scan(&mem.KnownAssetsCount)
	_ = p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM crawled_urls WHERE target_id = $1", targetID).Scan(&mem.KnownEndpointsCount)
	_ = p.db.QueryRowContext(ctx, "SELECT COUNT(DISTINCT technology) FROM technology_observations WHERE target_id = $1", targetID).Scan(&mem.KnownTechnologiesCount)
	_ = p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM temporal_change_records WHERE target_id = $1", targetID).Scan(&mem.TotalHistoricalChanges)
	_ = p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM investigation_clusters WHERE target_id = $1 AND status IN ('ACTIVE', 'INVESTIGATING')", targetID).Scan(&mem.ActiveInvestigationsCount)
	_ = p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM finding_candidates WHERE target_id = $1 AND state IN ('REPORTED', 'RESOLVED')", targetID).Scan(&mem.ValidatedFindingsCount)
	_ = p.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM finding_candidates WHERE target_id = $1 AND state = 'DISMISSED'", targetID).Scan(&mem.RejectedCandidatesCount)

	recentChanges, _ := p.ListTemporalChanges(ctx, targetID, 10)
	mem.RecentWhatChanged = recentChanges

	clusters, _ := p.ListInvestigationClusters(ctx, targetID)
	mem.DeservesReinvestigation = clusters

	return mem, nil
}

// RecordValidationResult records non-destructive safe verification results.
func (p *PostgresStorage) RecordValidationResult(ctx context.Context, result *models.ControlledValidationResult) error {
	obsJSON, _ := json.Marshal(result.Observations)

	query := `
		INSERT INTO controlled_validation_results (id, candidate_id, cluster_id, success, state, observations, output_fact, executed_at)
		VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), $4, $5, $6, $7, $8)
	`
	_, err := p.db.ExecContext(ctx, query,
		result.ID,
		result.CandidateID,
		result.ClusterID,
		result.Success,
		string(result.State),
		obsJSON,
		result.OutputFact,
		result.ExecutedAt,
	)
	return err
}
