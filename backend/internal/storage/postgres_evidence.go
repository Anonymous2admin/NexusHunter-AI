package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// SaveEvidence persists a first-class evidence record.
func (p *PostgresStorage) SaveEvidence(ctx context.Context, ev *models.Evidence) error {
	reqJSON, _ := json.Marshal(ev.Request)
	respJSON, _ := json.Marshal(ev.Response)
	headersJSON, _ := json.Marshal(ev.RelevantHeaders)
	redirectJSON, _ := json.Marshal(ev.RedirectChain)
	dnsJSON, _ := json.Marshal(ev.DNSContext)
	tlsJSON, _ := json.Marshal(ev.TLSMetadata)
	valJSON, _ := json.Marshal(ev.ValidationContext)
	scopeJSON, _ := json.Marshal(ev.ScopeDecision)
	redactionJSON, _ := json.Marshal(ev.RedactionStatus)
	provJSON, _ := json.Marshal(ev.Provenance)
	metaJSON, _ := json.Marshal(ev.Metadata)

	query := `
		INSERT INTO evidence_records (
			id, target_id, asset_id, observation_id, candidate_id, source, evidence_type, summary,
			captured_at, status_code, request_data, response_data, relevant_headers, redirect_chain,
			dns_context, tls_metadata, validation_context, scope_decision, redaction_status,
			canonical_representation, sha256, provenance, metadata, created_at
		) VALUES (
			$1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''), $6, $7, $8,
			$9, $10, $11, $12, $13, $14,
			$15, $16, $17, $18, $19,
			$20, $21, $22, $23, NOW()
		) ON CONFLICT (id) DO UPDATE SET
			summary = EXCLUDED.summary,
			status_code = EXCLUDED.status_code,
			response_data = EXCLUDED.response_data,
			relevant_headers = EXCLUDED.relevant_headers,
			redirect_chain = EXCLUDED.redirect_chain,
			dns_context = EXCLUDED.dns_context,
			tls_metadata = EXCLUDED.tls_metadata,
			validation_context = EXCLUDED.validation_context,
			redaction_status = EXCLUDED.redaction_status,
			canonical_representation = EXCLUDED.canonical_representation,
			sha256 = EXCLUDED.sha256,
			provenance = EXCLUDED.provenance,
			metadata = EXCLUDED.metadata
	`

	_, err := p.db.ExecContext(ctx, query,
		ev.ID,
		ev.TargetID,
		ev.AssetID,
		ev.ObservationID,
		ev.CandidateID,
		string(ev.Source),
		string(ev.EvidenceType),
		ev.Summary,
		ev.CapturedAt,
		ev.StatusCode,
		reqJSON,
		respJSON,
		headersJSON,
		redirectJSON,
		dnsJSON,
		tlsJSON,
		valJSON,
		scopeJSON,
		redactionJSON,
		ev.CanonicalRepresentation,
		ev.SHA256,
		provJSON,
		metaJSON,
	)
	return err
}

func (p *PostgresStorage) GetEvidence(ctx context.Context, id string) (*models.Evidence, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), COALESCE(observation_id, ''), COALESCE(candidate_id, ''),
		       source, evidence_type, summary, captured_at, status_code, request_data, response_data,
		       relevant_headers, redirect_chain, dns_context, tls_metadata, validation_context,
		       scope_decision, redaction_status, canonical_representation, sha256, provenance, metadata
		FROM evidence_records
		WHERE id = $1
	`
	row := p.db.QueryRowContext(ctx, query, id)
	return p.scanEvidence(row)
}

func (p *PostgresStorage) ListEvidenceByTarget(ctx context.Context, targetID string) ([]*models.Evidence, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), COALESCE(observation_id, ''), COALESCE(candidate_id, ''),
		       source, evidence_type, summary, captured_at, status_code, request_data, response_data,
		       relevant_headers, redirect_chain, dns_context, tls_metadata, validation_context,
		       scope_decision, redaction_status, canonical_representation, sha256, provenance, metadata
		FROM evidence_records
		WHERE target_id = $1
		ORDER BY captured_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.Evidence
	for rows.Next() {
		ev, err := p.scanEvidence(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, ev)
	}
	return list, rows.Err()
}

func (p *PostgresStorage) ListEvidenceByAsset(ctx context.Context, assetID string) ([]*models.Evidence, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), COALESCE(observation_id, ''), COALESCE(candidate_id, ''),
		       source, evidence_type, summary, captured_at, status_code, request_data, response_data,
		       relevant_headers, redirect_chain, dns_context, tls_metadata, validation_context,
		       scope_decision, redaction_status, canonical_representation, sha256, provenance, metadata
		FROM evidence_records
		WHERE asset_id = $1
		ORDER BY captured_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.Evidence
	for rows.Next() {
		ev, err := p.scanEvidence(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, ev)
	}
	return list, rows.Err()
}

func (p *PostgresStorage) ListEvidenceByObservation(ctx context.Context, obsID string) ([]*models.Evidence, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), COALESCE(observation_id, ''), COALESCE(candidate_id, ''),
		       source, evidence_type, summary, captured_at, status_code, request_data, response_data,
		       relevant_headers, redirect_chain, dns_context, tls_metadata, validation_context,
		       scope_decision, redaction_status, canonical_representation, sha256, provenance, metadata
		FROM evidence_records
		WHERE observation_id = $1
		ORDER BY captured_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query, obsID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.Evidence
	for rows.Next() {
		ev, err := p.scanEvidence(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, ev)
	}
	return list, rows.Err()
}

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func (p *PostgresStorage) scanEvidence(s rowScanner) (*models.Evidence, error) {
	ev := &models.Evidence{}
	var (
		sourceStr, typeStr string
		reqRaw, respRaw, headersRaw, redirRaw, dnsRaw, tlsRaw, valRaw []byte
		scopeRaw, redRaw, provRaw, metaRaw                             []byte
	)

	err := s.Scan(
		&ev.ID, &ev.TargetID, &ev.AssetID, &ev.ObservationID, &ev.CandidateID,
		&sourceStr, &typeStr, &ev.Summary, &ev.CapturedAt, &ev.StatusCode,
		&reqRaw, &respRaw, &headersRaw, &redirRaw, &dnsRaw, &tlsRaw, &valRaw,
		&scopeRaw, &redRaw, &ev.CanonicalRepresentation, &ev.SHA256, &provRaw, &metaRaw,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}

	ev.Source = models.EvidenceSource(sourceStr)
	ev.EvidenceType = models.EvidenceType(typeStr)

	_ = json.Unmarshal(reqRaw, &ev.Request)
	_ = json.Unmarshal(respRaw, &ev.Response)
	_ = json.Unmarshal(headersRaw, &ev.RelevantHeaders)
	_ = json.Unmarshal(redirRaw, &ev.RedirectChain)
	_ = json.Unmarshal(dnsRaw, &ev.DNSContext)
	_ = json.Unmarshal(tlsRaw, &ev.TLSMetadata)
	_ = json.Unmarshal(valRaw, &ev.ValidationContext)
	_ = json.Unmarshal(scopeRaw, &ev.ScopeDecision)
	_ = json.Unmarshal(redRaw, &ev.RedactionStatus)
	_ = json.Unmarshal(provRaw, &ev.Provenance)
	_ = json.Unmarshal(metaRaw, &ev.Metadata)

	return ev, nil
}

// SaveEvidenceDiff persists 3-level comparative analysis.
func (p *PostgresStorage) SaveEvidenceDiff(ctx context.Context, diff *models.EvidenceDiff) error {
	rawJSON, _ := json.Marshal(diff.RawDiff)
	semJSON, _ := json.Marshal(diff.SemanticDiff)
	secJSON, _ := json.Marshal(diff.SecurityDiff)

	query := `
		INSERT INTO evidence_diffs (
			id, target_id, asset_id, evidence_a_id, evidence_b_id,
			raw_diff, semantic_diff, security_diff, is_noise_filtered, is_security_relevant, computed_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5,
			$6, $7, $8, $9, $10, $11
		) ON CONFLICT (id) DO NOTHING
	`
	_, err := p.db.ExecContext(ctx, query,
		diff.ID, diff.TargetID, diff.AssetID, diff.EvidenceAID, diff.EvidenceBID,
		rawJSON, semJSON, secJSON, diff.IsNoiseFiltered, diff.IsSecurityRelevant, diff.ComputedAt,
	)
	return err
}

func (p *PostgresStorage) GetEvidenceDiff(ctx context.Context, id string) (*models.EvidenceDiff, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), evidence_a_id, evidence_b_id,
		       raw_diff, semantic_diff, security_diff, is_noise_filtered, is_security_relevant, computed_at
		FROM evidence_diffs
		WHERE id = $1
	`
	row := p.db.QueryRowContext(ctx, query, id)
	diff := &models.EvidenceDiff{}
	var rawJSON, semJSON, secJSON []byte

	err := row.Scan(
		&diff.ID, &diff.TargetID, &diff.AssetID, &diff.EvidenceAID, &diff.EvidenceBID,
		&rawJSON, &semJSON, &secJSON, &diff.IsNoiseFiltered, &diff.IsSecurityRelevant, &diff.ComputedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}

	_ = json.Unmarshal(rawJSON, &diff.RawDiff)
	_ = json.Unmarshal(semJSON, &diff.SemanticDiff)
	_ = json.Unmarshal(secJSON, &diff.SecurityDiff)

	return diff, nil
}

func (p *PostgresStorage) ListEvidenceDiffs(ctx context.Context, targetID string) ([]*models.EvidenceDiff, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), evidence_a_id, evidence_b_id,
		       raw_diff, semantic_diff, security_diff, is_noise_filtered, is_security_relevant, computed_at
		FROM evidence_diffs
		WHERE target_id = $1
		ORDER BY computed_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.EvidenceDiff
	for rows.Next() {
		diff := &models.EvidenceDiff{}
		var rawJSON, semJSON, secJSON []byte
		if err := rows.Scan(
			&diff.ID, &diff.TargetID, &diff.AssetID, &diff.EvidenceAID, &diff.EvidenceBID,
			&rawJSON, &semJSON, &secJSON, &diff.IsNoiseFiltered, &diff.IsSecurityRelevant, &diff.ComputedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(rawJSON, &diff.RawDiff)
		_ = json.Unmarshal(semJSON, &diff.SemanticDiff)
		_ = json.Unmarshal(secJSON, &diff.SecurityDiff)
		list = append(list, diff)
	}
	return list, rows.Err()
}

// SaveSecurityExpectation inserts an expected security model record.
func (p *PostgresStorage) SaveSecurityExpectation(ctx context.Context, exp *models.SecurityExpectation) error {
	rulesJSON, _ := json.Marshal(exp.RuleDetails)
	query := `
		INSERT INTO security_expectations (
			id, target_id, asset_id, endpoint, control_name, source, expected_state, description, rule_details, created_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5, $6, $7, $8, $9, $10
		) ON CONFLICT (id) DO NOTHING
	`
	if exp.CreatedAt.IsZero() {
		exp.CreatedAt = time.Now().UTC()
	}
	_, err := p.db.ExecContext(ctx, query,
		exp.ID, exp.TargetID, exp.AssetID, exp.Endpoint, exp.ControlName,
		string(exp.Source), string(exp.ExpectedState), exp.Description, rulesJSON, exp.CreatedAt,
	)
	return err
}

func (p *PostgresStorage) ListSecurityExpectations(ctx context.Context, targetID, assetID string) ([]*models.SecurityExpectation, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), endpoint, control_name, source, expected_state, description, rule_details, created_at
		FROM security_expectations
		WHERE target_id = $1 AND ($2 = '' OR asset_id = $2)
		ORDER BY created_at ASC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.SecurityExpectation
	for rows.Next() {
		exp := &models.SecurityExpectation{}
		var sourceStr, stateStr string
		var rulesJSON []byte

		if err := rows.Scan(
			&exp.ID, &exp.TargetID, &exp.AssetID, &exp.Endpoint, &exp.ControlName,
			&sourceStr, &stateStr, &exp.Description, &rulesJSON, &exp.CreatedAt,
		); err != nil {
			return nil, err
		}
		exp.Source = models.ExpectedModelSource(sourceStr)
		exp.ExpectedState = models.EpistemicObservationState(stateStr)
		_ = json.Unmarshal(rulesJSON, &exp.RuleDetails)
		list = append(list, exp)
	}
	return list, rows.Err()
}

// SaveSecurityContradiction persists identified contradictions between Expected and Observed states.
func (p *PostgresStorage) SaveSecurityContradiction(ctx context.Context, con *models.SecurityContradiction) error {
	refsJSON, _ := json.Marshal(con.EvidenceRefs)
	followupJSON, _ := json.Marshal(con.SuggestedFollowup)

	query := `
		INSERT INTO security_contradictions (
			id, target_id, asset_id, endpoint, contradiction_type, status, severity,
			title, description, expectation_id, observed_state, evidence_refs, explanation, suggested_followup,
			created_at, updated_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5, $6, $7,
			$8, $9, NULLIF($10, ''), $11, $12, $13, $14,
			$15, $16
		) ON CONFLICT (id) DO UPDATE SET
			status = EXCLUDED.status,
			severity = EXCLUDED.severity,
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			explanation = EXCLUDED.explanation,
			suggested_followup = EXCLUDED.suggested_followup,
			updated_at = EXCLUDED.updated_at
	`
	if con.CreatedAt.IsZero() {
		con.CreatedAt = time.Now().UTC()
	}
	if con.UpdatedAt.IsZero() {
		con.UpdatedAt = time.Now().UTC()
	}
	_, err := p.db.ExecContext(ctx, query,
		con.ID, con.TargetID, con.AssetID, con.Endpoint, string(con.ContradictionType), string(con.Status), con.Severity,
		con.Title, con.Description, con.ExpectationID, string(con.ObservedState), refsJSON, con.Explanation, followupJSON,
		con.CreatedAt, con.UpdatedAt,
	)
	return err
}

func (p *PostgresStorage) GetSecurityContradiction(ctx context.Context, id string) (*models.SecurityContradiction, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), endpoint, contradiction_type, status, severity,
		       title, description, COALESCE(expectation_id, ''), observed_state, evidence_refs, explanation, suggested_followup,
		       created_at, updated_at
		FROM security_contradictions
		WHERE id = $1
	`
	row := p.db.QueryRowContext(ctx, query, id)
	con := &models.SecurityContradiction{}
	var typeStr, statusStr, stateStr string
	var refsJSON, followupJSON []byte

	err := row.Scan(
		&con.ID, &con.TargetID, &con.AssetID, &con.Endpoint, &typeStr, &statusStr, &con.Severity,
		&con.Title, &con.Description, &con.ExpectationID, &stateStr, &refsJSON, &con.Explanation, &followupJSON,
		&con.CreatedAt, &con.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}

	con.ContradictionType = models.ContradictionType(typeStr)
	con.Status = models.ContradictionStatus(statusStr)
	con.ObservedState = models.EpistemicObservationState(stateStr)
	_ = json.Unmarshal(refsJSON, &con.EvidenceRefs)
	_ = json.Unmarshal(followupJSON, &con.SuggestedFollowup)

	return con, nil
}

func (p *PostgresStorage) ListSecurityContradictions(ctx context.Context, targetID, assetID string) ([]*models.SecurityContradiction, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), endpoint, contradiction_type, status, severity,
		       title, description, COALESCE(expectation_id, ''), observed_state, evidence_refs, explanation, suggested_followup,
		       created_at, updated_at
		FROM security_contradictions
		WHERE target_id = $1 AND ($2 = '' OR asset_id = $2)
		ORDER BY created_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.SecurityContradiction
	for rows.Next() {
		con := &models.SecurityContradiction{}
		var typeStr, statusStr, stateStr string
		var refsJSON, followupJSON []byte

		if err := rows.Scan(
			&con.ID, &con.TargetID, &con.AssetID, &con.Endpoint, &typeStr, &statusStr, &con.Severity,
			&con.Title, &con.Description, &con.ExpectationID, &stateStr, &refsJSON, &con.Explanation, &followupJSON,
			&con.CreatedAt, &con.UpdatedAt,
		); err != nil {
			return nil, err
		}
		con.ContradictionType = models.ContradictionType(typeStr)
		con.Status = models.ContradictionStatus(statusStr)
		con.ObservedState = models.EpistemicObservationState(stateStr)
		_ = json.Unmarshal(refsJSON, &con.EvidenceRefs)
		_ = json.Unmarshal(followupJSON, &con.SuggestedFollowup)
		list = append(list, con)
	}
	return list, rows.Err()
}

// SaveSecurityOutlier records statistical peer group outliers.
func (p *PostgresStorage) SaveSecurityOutlier(ctx context.Context, out *models.SecurityOutlier) error {
	refsJSON, _ := json.Marshal(out.EvidenceRefs)
	detailsJSON, _ := json.Marshal(out.Details)

	query := `
		INSERT INTO security_outliers (
			id, target_id, asset_id, endpoint, comparison_group, observed_value, baseline_value,
			deviation_type, evidence_refs, confidence, details, created_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5, $6, $7,
			$8, $9, $10, $11, $12
		) ON CONFLICT (id) DO NOTHING
	`
	if out.CreatedAt.IsZero() {
		out.CreatedAt = time.Now().UTC()
	}
	_, err := p.db.ExecContext(ctx, query,
		out.ID, out.TargetID, out.AssetID, out.Endpoint, out.ComparisonGroup, out.ObservedValue, out.BaselineValue,
		out.DeviationType, refsJSON, out.Confidence, detailsJSON, out.CreatedAt,
	)
	return err
}

func (p *PostgresStorage) ListSecurityOutliers(ctx context.Context, targetID, assetID string) ([]*models.SecurityOutlier, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), endpoint, comparison_group, observed_value, baseline_value,
		       deviation_type, evidence_refs, confidence, details, created_at
		FROM security_outliers
		WHERE target_id = $1 AND ($2 = '' OR asset_id = $2)
		ORDER BY created_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.SecurityOutlier
	for rows.Next() {
		out := &models.SecurityOutlier{}
		var refsJSON, detailsJSON []byte

		if err := rows.Scan(
			&out.ID, &out.TargetID, &out.AssetID, &out.Endpoint, &out.ComparisonGroup, &out.ObservedValue, &out.BaselineValue,
			&out.DeviationType, &refsJSON, &out.Confidence, &detailsJSON, &out.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(refsJSON, &out.EvidenceRefs)
		_ = json.Unmarshal(detailsJSON, &out.Details)
		list = append(list, out)
	}
	return list, rows.Err()
}

// RecordTimelineEvent records a unified chronological event.
func (p *PostgresStorage) RecordTimelineEvent(ctx context.Context, ev *models.EvidenceTimelineEvent) error {
	provJSON, _ := json.Marshal(ev.Provenance)
	detailsJSON, _ := json.Marshal(ev.Details)

	query := `
		INSERT INTO evidence_timeline_events (
			id, target_id, asset_id, event_type, summary, epistemic_status, timestamp, provenance, reference_id, details
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5, $6, $7, $8, $9, $10
		) ON CONFLICT (id) DO NOTHING
	`
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	_, err := p.db.ExecContext(ctx, query,
		ev.ID, ev.TargetID, ev.AssetID, ev.EventType, ev.Summary, string(ev.EpistemicStatus),
		ev.Timestamp, provJSON, ev.ReferenceID, detailsJSON,
	)
	return err
}

func (p *PostgresStorage) ListTimelineEvents(ctx context.Context, targetID, assetID string, limit int) ([]*models.EvidenceTimelineEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), event_type, summary, epistemic_status, timestamp, provenance, reference_id, details
		FROM evidence_timeline_events
		WHERE ($1 = '' OR target_id = $1) AND ($2 = '' OR asset_id = $2)
		ORDER BY timestamp DESC
		LIMIT $3
	`
	rows, err := p.db.QueryContext(ctx, query, targetID, assetID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.EvidenceTimelineEvent
	for rows.Next() {
		ev := &models.EvidenceTimelineEvent{}
		var statusStr string
		var provJSON, detailsJSON []byte

		if err := rows.Scan(
			&ev.ID, &ev.TargetID, &ev.AssetID, &ev.EventType, &ev.Summary, &statusStr,
			&ev.Timestamp, &provJSON, &ev.ReferenceID, &detailsJSON,
		); err != nil {
			return nil, err
		}
		ev.EpistemicStatus = models.EpistemicStatus(statusStr)
		_ = json.Unmarshal(provJSON, &ev.Provenance)
		_ = json.Unmarshal(detailsJSON, &ev.Details)
		list = append(list, ev)
	}
	return list, rows.Err()
}
