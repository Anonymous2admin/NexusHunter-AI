package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// SaveReasoningSignal persists a deterministic security signal.
func (p *PostgresStorage) SaveReasoningSignal(ctx context.Context, sig *models.ReasoningSignal) error {
	obsJSON, _ := json.Marshal(sig.SourceObservations)
	evJSON, _ := json.Marshal(sig.SourceEvidence)
	metaJSON, _ := json.Marshal(sig.Metadata)

	query := `
		INSERT INTO reasoning_signals (
			id, target_id, asset_id, endpoint, signal_type, category, title, description,
			epistemic_status, status, severity_of_attention, source_observations, source_evidence,
			detector, detector_version, metadata, created_at, updated_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5, $6, $7, $8,
			$9, $10, $11, $12, $13,
			$14, $15, $16, $17, NOW()
		) ON CONFLICT (id) DO UPDATE SET
			status = EXCLUDED.status,
			severity_of_attention = EXCLUDED.severity_of_attention,
			source_evidence = EXCLUDED.source_evidence,
			metadata = EXCLUDED.metadata,
			updated_at = NOW()
	`

	createdAt := sig.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	_, err := p.db.ExecContext(ctx, query,
		sig.ID,
		sig.TargetID,
		sig.AssetID,
		sig.Endpoint,
		string(sig.SignalType),
		sig.Category,
		sig.Title,
		sig.Description,
		string(sig.EpistemicStatus),
		string(sig.Status),
		string(sig.SeverityOfAttention),
		obsJSON,
		evJSON,
		sig.Detector,
		sig.DetectorVersion,
		metaJSON,
		createdAt,
	)
	return err
}

// GetReasoningSignal retrieves a single signal by ID.
func (p *PostgresStorage) GetReasoningSignal(ctx context.Context, id string) (*models.ReasoningSignal, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), COALESCE(endpoint, ''), signal_type, category,
		       title, description, epistemic_status, status, severity_of_attention,
		       source_observations, source_evidence, detector, detector_version, metadata, created_at, updated_at
		FROM reasoning_signals
		WHERE id = $1
	`
	row := p.db.QueryRowContext(ctx, query, id)

	var sig models.ReasoningSignal
	var obsJSON, evJSON, metaJSON []byte

	err := row.Scan(
		&sig.ID,
		&sig.TargetID,
		&sig.AssetID,
		&sig.Endpoint,
		&sig.SignalType,
		&sig.Category,
		&sig.Title,
		&sig.Description,
		&sig.EpistemicStatus,
		&sig.Status,
		&sig.SeverityOfAttention,
		&obsJSON,
		&evJSON,
		&sig.Detector,
		&sig.DetectorVersion,
		&metaJSON,
		&sig.CreatedAt,
		&sig.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}

	_ = json.Unmarshal(obsJSON, &sig.SourceObservations)
	_ = json.Unmarshal(evJSON, &sig.SourceEvidence)
	_ = json.Unmarshal(metaJSON, &sig.Metadata)

	return &sig, nil
}

// ListReasoningSignals retrieves signals for a target and optional asset.
func (p *PostgresStorage) ListReasoningSignals(ctx context.Context, targetID, assetID string) ([]*models.ReasoningSignal, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), COALESCE(endpoint, ''), signal_type, category,
		       title, description, epistemic_status, status, severity_of_attention,
		       source_observations, source_evidence, detector, detector_version, metadata, created_at, updated_at
		FROM reasoning_signals
		WHERE target_id = $1 AND ($2 = '' OR asset_id = $2)
		ORDER BY created_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*models.ReasoningSignal
	for rows.Next() {
		var sig models.ReasoningSignal
		var obsJSON, evJSON, metaJSON []byte
		if err := rows.Scan(
			&sig.ID,
			&sig.TargetID,
			&sig.AssetID,
			&sig.Endpoint,
			&sig.SignalType,
			&sig.Category,
			&sig.Title,
			&sig.Description,
			&sig.EpistemicStatus,
			&sig.Status,
			&sig.SeverityOfAttention,
			&obsJSON,
			&evJSON,
			&sig.Detector,
			&sig.DetectorVersion,
			&metaJSON,
			&sig.CreatedAt,
			&sig.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(obsJSON, &sig.SourceObservations)
		_ = json.Unmarshal(evJSON, &sig.SourceEvidence)
		_ = json.Unmarshal(metaJSON, &sig.Metadata)
		res = append(res, &sig)
	}
	return res, rows.Err()
}

// UpdateSignalStatus changes the lifecycle state of a signal.
func (p *PostgresStorage) UpdateSignalStatus(ctx context.Context, id string, status models.SignalStatus) error {
	query := `UPDATE reasoning_signals SET status = $1, updated_at = NOW() WHERE id = $2`
	res, err := p.db.ExecContext(ctx, query, string(status), id)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// SaveHypothesisGroup persists a cluster of mutually competing hypotheses.
func (p *PostgresStorage) SaveHypothesisGroup(ctx context.Context, group *models.HypothesisGroup) error {
	sigJSON, _ := json.Marshal(group.Signals)
	hypoJSON, _ := json.Marshal(group.HypothesisIDs)

	query := `
		INSERT INTO hypothesis_groups (
			id, target_id, asset_id, subject, signals, hypothesis_ids, active_investigation,
			has_competing_theories, created_at, updated_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5, $6, NULLIF($7, ''),
			$8, NOW(), NOW()
		) ON CONFLICT (id) DO UPDATE SET
			subject = EXCLUDED.subject,
			signals = EXCLUDED.signals,
			hypothesis_ids = EXCLUDED.hypothesis_ids,
			active_investigation = EXCLUDED.active_investigation,
			updated_at = NOW()
	`
	_, err := p.db.ExecContext(ctx, query,
		group.ID,
		group.TargetID,
		group.AssetID,
		group.Subject,
		sigJSON,
		hypoJSON,
		group.ActiveInvestigation,
		group.HasCompetingTheories,
	)
	return err
}

// GetHypothesisGroup loads a group by ID.
func (p *PostgresStorage) GetHypothesisGroup(ctx context.Context, id string) (*models.HypothesisGroup, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), subject, signals, hypothesis_ids,
		       COALESCE(active_investigation, ''), has_competing_theories, created_at, updated_at
		FROM hypothesis_groups
		WHERE id = $1
	`
	var grp models.HypothesisGroup
	var sigJSON, hypoJSON []byte

	err := p.db.QueryRowContext(ctx, query, id).Scan(
		&grp.ID,
		&grp.TargetID,
		&grp.AssetID,
		&grp.Subject,
		&sigJSON,
		&hypoJSON,
		&grp.ActiveInvestigation,
		&grp.HasCompetingTheories,
		&grp.CreatedAt,
		&grp.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}

	_ = json.Unmarshal(sigJSON, &grp.Signals)
	_ = json.Unmarshal(hypoJSON, &grp.HypothesisIDs)

	// Fetch hypotheses belonging to group
	hypos, _ := p.ListHypothesesByGroup(ctx, grp.ID)
	for _, h := range hypos {
		grp.Hypotheses = append(grp.Hypotheses, *h)
	}

	return &grp, nil
}

// ListHypothesisGroups lists groups for a target.
func (p *PostgresStorage) ListHypothesisGroups(ctx context.Context, targetID string) ([]*models.HypothesisGroup, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), subject, signals, hypothesis_ids,
		       COALESCE(active_investigation, ''), has_competing_theories, created_at, updated_at
		FROM hypothesis_groups
		WHERE target_id = $1
		ORDER BY created_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*models.HypothesisGroup
	for rows.Next() {
		var grp models.HypothesisGroup
		var sigJSON, hypoJSON []byte
		if err := rows.Scan(
			&grp.ID,
			&grp.TargetID,
			&grp.AssetID,
			&grp.Subject,
			&sigJSON,
			&hypoJSON,
			&grp.ActiveInvestigation,
			&grp.HasCompetingTheories,
			&grp.CreatedAt,
			&grp.UpdatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(sigJSON, &grp.Signals)
		_ = json.Unmarshal(hypoJSON, &grp.HypothesisIDs)

		hypos, _ := p.ListHypothesesByGroup(ctx, grp.ID)
		for _, h := range hypos {
			grp.Hypotheses = append(grp.Hypotheses, *h)
		}
		res = append(res, &grp)
	}
	return res, rows.Err()
}

// SaveHypothesis stores a formal hypothesis.
func (p *PostgresStorage) SaveHypothesis(ctx context.Context, hyp *models.Hypothesis) error {
	sigJSON, _ := json.Marshal(hyp.SupportingSignals)
	supEvJSON, _ := json.Marshal(hyp.SupportingEvidence)
	conEvJSON, _ := json.Marshal(hyp.ContradictingEvidence)
	altJSON, _ := json.Marshal(hyp.AlternativeHypotheses)
	recJSON, _ := json.Marshal(hyp.RecommendedInvestigations)
	breakdownJSON, _ := json.Marshal(hyp.PriorityBreakdown)

	query := `
		INSERT INTO hypotheses (
			id, group_id, target_id, asset_id, endpoint, title, description, category,
			epistemic_status, status, reasoning_method, supporting_signals, supporting_evidence,
			contradicting_evidence, alternative_hypotheses, recommended_investigations,
			evidence_strength, investigation_priority, priority_breakdown, created_at, updated_at
		) VALUES (
			$1, $2, $3, NULLIF($4, ''), $5, $6, $7, $8,
			$9, $10, $11, $12, $13,
			$14, $15, $16,
			$17, $18, $19, NOW(), NOW()
		) ON CONFLICT (id) DO UPDATE SET
			title = EXCLUDED.title,
			description = EXCLUDED.description,
			status = EXCLUDED.status,
			supporting_evidence = EXCLUDED.supporting_evidence,
			contradicting_evidence = EXCLUDED.contradicting_evidence,
			evidence_strength = EXCLUDED.evidence_strength,
			investigation_priority = EXCLUDED.investigation_priority,
			priority_breakdown = EXCLUDED.priority_breakdown,
			updated_at = NOW()
	`
	_, err := p.db.ExecContext(ctx, query,
		hyp.ID,
		hyp.GroupID,
		hyp.TargetID,
		hyp.AssetID,
		hyp.Endpoint,
		hyp.Title,
		hyp.Description,
		string(hyp.Category),
		string(hyp.EpistemicStatus),
		string(hyp.Status),
		hyp.ReasoningMethod,
		sigJSON,
		supEvJSON,
		conEvJSON,
		altJSON,
		recJSON,
		hyp.EvidenceStrength,
		hyp.InvestigationPriority,
		breakdownJSON,
	)
	if err != nil {
		return err
	}

	for _, fc := range hyp.FalsificationConditions {
		_ = p.SaveFalsificationCondition(ctx, &fc)
	}
	for _, req := range hyp.MissingEvidence {
		_ = p.SaveEvidenceRequirement(ctx, &req)
	}

	return nil
}

// GetHypothesis retrieves a hypothesis with its sub-entities.
func (p *PostgresStorage) GetHypothesis(ctx context.Context, id string) (*models.Hypothesis, error) {
	query := `
		SELECT id, group_id, target_id, COALESCE(asset_id, ''), COALESCE(endpoint, ''), title, description,
		       category, epistemic_status, status, reasoning_method, supporting_signals,
		       supporting_evidence, contradicting_evidence, alternative_hypotheses,
		       recommended_investigations, evidence_strength, investigation_priority,
		       priority_breakdown, created_at, updated_at
		FROM hypotheses
		WHERE id = $1
	`
	var hyp models.Hypothesis
	var sigJSON, supEvJSON, conEvJSON, altJSON, recJSON, breakdownJSON []byte

	err := p.db.QueryRowContext(ctx, query, id).Scan(
		&hyp.ID,
		&hyp.GroupID,
		&hyp.TargetID,
		&hyp.AssetID,
		&hyp.Endpoint,
		&hyp.Title,
		&hyp.Description,
		&hyp.Category,
		&hyp.EpistemicStatus,
		&hyp.Status,
		&hyp.ReasoningMethod,
		&sigJSON,
		&supEvJSON,
		&conEvJSON,
		&altJSON,
		&recJSON,
		&hyp.EvidenceStrength,
		&hyp.InvestigationPriority,
		&breakdownJSON,
		&hyp.CreatedAt,
		&hyp.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}

	_ = json.Unmarshal(sigJSON, &hyp.SupportingSignals)
	_ = json.Unmarshal(supEvJSON, &hyp.SupportingEvidence)
	_ = json.Unmarshal(conEvJSON, &hyp.ContradictingEvidence)
	_ = json.Unmarshal(altJSON, &hyp.AlternativeHypotheses)
	_ = json.Unmarshal(recJSON, &hyp.RecommendedInvestigations)
	_ = json.Unmarshal(breakdownJSON, &hyp.PriorityBreakdown)

	fals, _ := p.ListFalsificationConditions(ctx, hyp.ID)
	for _, f := range fals {
		hyp.FalsificationConditions = append(hyp.FalsificationConditions, *f)
	}

	reqs, _ := p.ListEvidenceRequirements(ctx, hyp.ID)
	for _, r := range reqs {
		hyp.MissingEvidence = append(hyp.MissingEvidence, *r)
	}

	return &hyp, nil
}

// ListHypotheses returns hypotheses for a target.
func (p *PostgresStorage) ListHypotheses(ctx context.Context, targetID string) ([]*models.Hypothesis, error) {
	query := `
		SELECT id, group_id, target_id, COALESCE(asset_id, ''), COALESCE(endpoint, ''), title, description,
		       category, epistemic_status, status, reasoning_method, supporting_signals,
		       supporting_evidence, contradicting_evidence, alternative_hypotheses,
		       recommended_investigations, evidence_strength, investigation_priority,
		       priority_breakdown, created_at, updated_at
		FROM hypotheses
		WHERE target_id = $1
		ORDER BY investigation_priority DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*models.Hypothesis
	for rows.Next() {
		var hyp models.Hypothesis
		var sigJSON, supEvJSON, conEvJSON, altJSON, recJSON, breakdownJSON []byte

		if err := rows.Scan(
			&hyp.ID,
			&hyp.GroupID,
			&hyp.TargetID,
			&hyp.AssetID,
			&hyp.Endpoint,
			&hyp.Title,
			&hyp.Description,
			&hyp.Category,
			&hyp.EpistemicStatus,
			&hyp.Status,
			&hyp.ReasoningMethod,
			&sigJSON,
			&supEvJSON,
			&conEvJSON,
			&altJSON,
			&recJSON,
			&hyp.EvidenceStrength,
			&hyp.InvestigationPriority,
			&breakdownJSON,
			&hyp.CreatedAt,
			&hyp.UpdatedAt,
		); err != nil {
			return nil, err
		}

		_ = json.Unmarshal(sigJSON, &hyp.SupportingSignals)
		_ = json.Unmarshal(supEvJSON, &hyp.SupportingEvidence)
		_ = json.Unmarshal(conEvJSON, &hyp.ContradictingEvidence)
		_ = json.Unmarshal(altJSON, &hyp.AlternativeHypotheses)
		_ = json.Unmarshal(recJSON, &hyp.RecommendedInvestigations)
		_ = json.Unmarshal(breakdownJSON, &hyp.PriorityBreakdown)

		fals, _ := p.ListFalsificationConditions(ctx, hyp.ID)
		for _, f := range fals {
			hyp.FalsificationConditions = append(hyp.FalsificationConditions, *f)
		}
		reqs, _ := p.ListEvidenceRequirements(ctx, hyp.ID)
		for _, r := range reqs {
			hyp.MissingEvidence = append(hyp.MissingEvidence, *r)
		}

		res = append(res, &hyp)
	}
	return res, rows.Err()
}

// ListHypothesesByGroup retrieves hypotheses belonging to a group.
func (p *PostgresStorage) ListHypothesesByGroup(ctx context.Context, groupID string) ([]*models.Hypothesis, error) {
	query := `
		SELECT id, group_id, target_id, COALESCE(asset_id, ''), COALESCE(endpoint, ''), title, description,
		       category, epistemic_status, status, reasoning_method, supporting_signals,
		       supporting_evidence, contradicting_evidence, alternative_hypotheses,
		       recommended_investigations, evidence_strength, investigation_priority,
		       priority_breakdown, created_at, updated_at
		FROM hypotheses
		WHERE group_id = $1
		ORDER BY evidence_strength DESC
	`
	rows, err := p.db.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*models.Hypothesis
	for rows.Next() {
		var hyp models.Hypothesis
		var sigJSON, supEvJSON, conEvJSON, altJSON, recJSON, breakdownJSON []byte

		if err := rows.Scan(
			&hyp.ID,
			&hyp.GroupID,
			&hyp.TargetID,
			&hyp.AssetID,
			&hyp.Endpoint,
			&hyp.Title,
			&hyp.Description,
			&hyp.Category,
			&hyp.EpistemicStatus,
			&hyp.Status,
			&hyp.ReasoningMethod,
			&sigJSON,
			&supEvJSON,
			&conEvJSON,
			&altJSON,
			&recJSON,
			&hyp.EvidenceStrength,
			&hyp.InvestigationPriority,
			&breakdownJSON,
			&hyp.CreatedAt,
			&hyp.UpdatedAt,
		); err != nil {
			return nil, err
		}

		_ = json.Unmarshal(sigJSON, &hyp.SupportingSignals)
		_ = json.Unmarshal(supEvJSON, &hyp.SupportingEvidence)
		_ = json.Unmarshal(conEvJSON, &hyp.ContradictingEvidence)
		_ = json.Unmarshal(altJSON, &hyp.AlternativeHypotheses)
		_ = json.Unmarshal(recJSON, &hyp.RecommendedInvestigations)
		_ = json.Unmarshal(breakdownJSON, &hyp.PriorityBreakdown)

		res = append(res, &hyp)
	}
	return res, rows.Err()
}

// UpdateHypothesisStatus transitions status.
func (p *PostgresStorage) UpdateHypothesisStatus(ctx context.Context, id string, status models.HypothesisStatus) error {
	query := `UPDATE hypotheses SET status = $1, updated_at = NOW() WHERE id = $2`
	_, err := p.db.ExecContext(ctx, query, string(status), id)
	return err
}

// UpdateHypothesisStatusWithGuard transitions status atomically checking the expected previous status.
func (p *PostgresStorage) UpdateHypothesisStatusWithGuard(ctx context.Context, id string, expectedStatus models.HypothesisStatus, newStatus models.HypothesisStatus) error {
	query := `UPDATE hypotheses SET status = $1, updated_at = NOW() WHERE id = $2 AND status = $3`
	res, err := p.db.ExecContext(ctx, query, string(newStatus), id, string(expectedStatus))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrInvalidState
	}
	return nil
}

// SaveFalsificationCondition stores a falsification test definition.
func (p *PostgresStorage) SaveFalsificationCondition(ctx context.Context, cond *models.FalsificationCondition) error {
	refsJSON, _ := json.Marshal(cond.EvidenceRefs)
	query := `
		INSERT INTO falsification_conditions (
			id, hypothesis_id, condition_description, required_evidence, validation_method,
			result, evidence_refs, evaluated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		) ON CONFLICT (id) DO UPDATE SET
			result = EXCLUDED.result,
			evidence_refs = EXCLUDED.evidence_refs,
			evaluated_at = EXCLUDED.evaluated_at
	`
	_, err := p.db.ExecContext(ctx, query,
		cond.ID,
		cond.HypothesisID,
		cond.ConditionDescription,
		cond.RequiredEvidence,
		cond.ValidationMethod,
		string(cond.Result),
		refsJSON,
		cond.EvaluatedAt,
	)
	return err
}

// ListFalsificationConditions retrieves falsification conditions for a hypothesis.
func (p *PostgresStorage) ListFalsificationConditions(ctx context.Context, hypothesisID string) ([]*models.FalsificationCondition, error) {
	query := `
		SELECT id, hypothesis_id, condition_description, required_evidence, validation_method,
		       result, evidence_refs, evaluated_at
		FROM falsification_conditions
		WHERE hypothesis_id = $1
	`
	rows, err := p.db.QueryContext(ctx, query, hypothesisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*models.FalsificationCondition
	for rows.Next() {
		var cond models.FalsificationCondition
		var refsJSON []byte
		if err := rows.Scan(
			&cond.ID,
			&cond.HypothesisID,
			&cond.ConditionDescription,
			&cond.RequiredEvidence,
			&cond.ValidationMethod,
			&cond.Result,
			&refsJSON,
			&cond.EvaluatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(refsJSON, &cond.EvidenceRefs)
		res = append(res, &cond)
	}
	return res, rows.Err()
}

// SaveEvidenceRequirement stores an unanswered intelligence requirement.
func (p *PostgresStorage) SaveEvidenceRequirement(ctx context.Context, req *models.EvidenceRequirement) error {
	query := `
		INSERT INTO evidence_requirements (
			id, hypothesis_id, description, importance, evidence_type, collection_method,
			status, satisfied_by_ref, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NOW()
		) ON CONFLICT (id) DO UPDATE SET
			status = EXCLUDED.status,
			satisfied_by_ref = EXCLUDED.satisfied_by_ref
	`
	_, err := p.db.ExecContext(ctx, query,
		req.ID,
		req.HypothesisID,
		req.Description,
		req.Importance,
		string(req.EvidenceType),
		req.CollectionMethod,
		string(req.Status),
		req.SatisfiedByRef,
	)
	return err
}

// ListEvidenceRequirements retrieves requirements for a hypothesis.
func (p *PostgresStorage) ListEvidenceRequirements(ctx context.Context, hypothesisID string) ([]*models.EvidenceRequirement, error) {
	query := `
		SELECT id, hypothesis_id, description, importance, evidence_type, collection_method,
		       status, COALESCE(satisfied_by_ref, ''), created_at
		FROM evidence_requirements
		WHERE hypothesis_id = $1
		ORDER BY created_at ASC
	`
	rows, err := p.db.QueryContext(ctx, query, hypothesisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*models.EvidenceRequirement
	for rows.Next() {
		var req models.EvidenceRequirement
		if err := rows.Scan(
			&req.ID,
			&req.HypothesisID,
			&req.Description,
			&req.Importance,
			&req.EvidenceType,
			&req.CollectionMethod,
			&req.Status,
			&req.SatisfiedByRef,
			&req.CreatedAt,
		); err != nil {
			return nil, err
		}
		res = append(res, &req)
	}
	return res, rows.Err()
}

// UpdateEvidenceRequirementStatus marks an evidence requirement as satisfied.
func (p *PostgresStorage) UpdateEvidenceRequirementStatus(ctx context.Context, id string, status models.RequirementStatus, satisfiedRef string) error {
	query := `UPDATE evidence_requirements SET status = $1, satisfied_by_ref = NULLIF($2, '') WHERE id = $3`
	_, err := p.db.ExecContext(ctx, query, string(status), satisfiedRef, id)
	return err
}

// SaveInvestigation stores an authorized investigation plan.
func (p *PostgresStorage) SaveInvestigation(ctx context.Context, inv *models.Investigation) error {
	stepsJSON, _ := json.Marshal(inv.Steps)
	factorsJSON, _ := json.Marshal(inv.PriorityFactors)
	evJSON, _ := json.Marshal(inv.GeneratedEvidence)

	query := `
		INSERT INTO investigations (
			id, target_id, asset_id, hypothesis_id, group_id, title, objective,
			priority, priority_score, priority_factors, status, steps, result_summary,
			generated_evidence, updated_hypothesis, created_by, created_at, completed_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, NULLIF($5, ''), $6, $7,
			$8, $9, $10, $11, $12, $13,
			$14, NULLIF($15, ''), $16, NOW(), $17
		) ON CONFLICT (id) DO UPDATE SET
			status = EXCLUDED.status,
			steps = EXCLUDED.steps,
			result_summary = EXCLUDED.result_summary,
			generated_evidence = EXCLUDED.generated_evidence,
			completed_at = EXCLUDED.completed_at
	`
	_, err := p.db.ExecContext(ctx, query,
		inv.ID,
		inv.TargetID,
		inv.AssetID,
		inv.HypothesisID,
		inv.GroupID,
		inv.Title,
		inv.Objective,
		inv.Priority,
		inv.PriorityScore,
		factorsJSON,
		string(inv.Status),
		stepsJSON,
		inv.ResultSummary,
		evJSON,
		inv.UpdatedHypothesis,
		inv.CreatedBy,
		inv.CompletedAt,
	)
	return err
}

// GetInvestigation retrieves an investigation plan by ID.
func (p *PostgresStorage) GetInvestigation(ctx context.Context, id string) (*models.Investigation, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), hypothesis_id, COALESCE(group_id, ''),
		       title, objective, priority, priority_score, priority_factors, status,
		       steps, COALESCE(result_summary, ''), generated_evidence, COALESCE(updated_hypothesis, ''),
		       created_by, created_at, completed_at
		FROM investigations
		WHERE id = $1
	`
	var inv models.Investigation
	var factorsJSON, stepsJSON, evJSON []byte

	err := p.db.QueryRowContext(ctx, query, id).Scan(
		&inv.ID,
		&inv.TargetID,
		&inv.AssetID,
		&inv.HypothesisID,
		&inv.GroupID,
		&inv.Title,
		&inv.Objective,
		&inv.Priority,
		&inv.PriorityScore,
		&factorsJSON,
		&inv.Status,
		&stepsJSON,
		&inv.ResultSummary,
		&evJSON,
		&inv.UpdatedHypothesis,
		&inv.CreatedBy,
		&inv.CreatedAt,
		&inv.CompletedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}

	_ = json.Unmarshal(factorsJSON, &inv.PriorityFactors)
	_ = json.Unmarshal(stepsJSON, &inv.Steps)
	_ = json.Unmarshal(evJSON, &inv.GeneratedEvidence)

	return &inv, nil
}

// ListInvestigations retrieves all investigations for a target.
func (p *PostgresStorage) ListInvestigations(ctx context.Context, targetID string) ([]*models.Investigation, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), hypothesis_id, COALESCE(group_id, ''),
		       title, objective, priority, priority_score, priority_factors, status,
		       steps, COALESCE(result_summary, ''), generated_evidence, COALESCE(updated_hypothesis, ''),
		       created_by, created_at, completed_at
		FROM investigations
		WHERE target_id = $1
		ORDER BY created_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*models.Investigation
	for rows.Next() {
		var inv models.Investigation
		var factorsJSON, stepsJSON, evJSON []byte

		if err := rows.Scan(
			&inv.ID,
			&inv.TargetID,
			&inv.AssetID,
			&inv.HypothesisID,
			&inv.GroupID,
			&inv.Title,
			&inv.Objective,
			&inv.Priority,
			&inv.PriorityScore,
			&factorsJSON,
			&inv.Status,
			&stepsJSON,
			&inv.ResultSummary,
			&evJSON,
			&inv.UpdatedHypothesis,
			&inv.CreatedBy,
			&inv.CreatedAt,
			&inv.CompletedAt,
		); err != nil {
			return nil, err
		}

		_ = json.Unmarshal(factorsJSON, &inv.PriorityFactors)
		_ = json.Unmarshal(stepsJSON, &inv.Steps)
		_ = json.Unmarshal(evJSON, &inv.GeneratedEvidence)

		res = append(res, &inv)
	}
	return res, rows.Err()
}

// UpdateInvestigationStatus updates an investigation's lifecycle state.
func (p *PostgresStorage) UpdateInvestigationStatus(ctx context.Context, id string, status models.InvestigationStatus, result string) error {
	query := `
		UPDATE investigations
		SET status = $1, result_summary = CASE WHEN $2 != '' THEN $2 ELSE result_summary END,
		    completed_at = CASE WHEN $1 IN ('COMPLETED', 'FAILED', 'CANCELLED') THEN NOW() ELSE completed_at END
		WHERE id = $3
	`
	_, err := p.db.ExecContext(ctx, query, string(status), result, id)
	return err
}

// SaveTrustBoundary records an observed or inferred boundary transition.
func (p *PostgresStorage) SaveTrustBoundary(ctx context.Context, tb *models.TrustBoundary) error {
	refsJSON, _ := json.Marshal(tb.EvidenceRefs)
	query := `
		INSERT INTO trust_boundaries (
			id, target_id, asset_id, boundary_name, from_tier, to_tier,
			epistemic_status, evidence_refs, notes, created_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5, $6, $7, $8, $9, NOW()
		) ON CONFLICT (id) DO UPDATE SET
			notes = EXCLUDED.notes,
			evidence_refs = EXCLUDED.evidence_refs
	`
	_, err := p.db.ExecContext(ctx, query,
		tb.ID,
		tb.TargetID,
		tb.AssetID,
		tb.BoundaryName,
		string(tb.FromTier),
		string(tb.ToTier),
		string(tb.EpistemicStatus),
		refsJSON,
		tb.Notes,
	)
	return err
}

// ListTrustBoundaries retrieves trust boundaries for a target.
func (p *PostgresStorage) ListTrustBoundaries(ctx context.Context, targetID, assetID string) ([]*models.TrustBoundary, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), boundary_name, from_tier, to_tier,
		       epistemic_status, evidence_refs, COALESCE(notes, ''), created_at
		FROM trust_boundaries
		WHERE target_id = $1 AND ($2 = '' OR asset_id = $2)
		ORDER BY created_at ASC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*models.TrustBoundary
	for rows.Next() {
		var tb models.TrustBoundary
		var refsJSON []byte
		if err := rows.Scan(
			&tb.ID,
			&tb.TargetID,
			&tb.AssetID,
			&tb.BoundaryName,
			&tb.FromTier,
			&tb.ToTier,
			&tb.EpistemicStatus,
			&refsJSON,
			&tb.Notes,
			&tb.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(refsJSON, &tb.EvidenceRefs)
		res = append(res, &tb)
	}
	return res, rows.Err()
}

// SaveAuthContext persists an authorized researcher context.
func (p *PostgresStorage) SaveAuthContext(ctx context.Context, ac *models.AuthContext) error {
	headersJSON, _ := json.Marshal(ac.Headers)
	query := `
		INSERT INTO auth_contexts (
			id, target_id, name, authorization_basis, scope_constraint, headers, is_active, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, NOW()
		) ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			authorization_basis = EXCLUDED.authorization_basis,
			scope_constraint = EXCLUDED.scope_constraint,
			headers = EXCLUDED.headers,
			is_active = EXCLUDED.is_active
	`
	_, err := p.db.ExecContext(ctx, query,
		ac.ID,
		ac.TargetID,
		ac.Name,
		ac.AuthorizationBasis,
		ac.ScopeConstraint,
		headersJSON,
		ac.IsActive,
	)
	return err
}

// ListAuthContexts lists authorized contexts for a target.
func (p *PostgresStorage) ListAuthContexts(ctx context.Context, targetID string) ([]*models.AuthContext, error) {
	query := `
		SELECT id, target_id, name, authorization_basis, scope_constraint, headers, is_active, created_at
		FROM auth_contexts
		WHERE target_id = $1
		ORDER BY created_at ASC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*models.AuthContext
	for rows.Next() {
		var ac models.AuthContext
		var headersJSON []byte
		if err := rows.Scan(
			&ac.ID,
			&ac.TargetID,
			&ac.Name,
			&ac.AuthorizationBasis,
			&ac.ScopeConstraint,
			&headersJSON,
			&ac.IsActive,
			&ac.CreatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(headersJSON, &ac.Headers)
		res = append(res, &ac)
	}
	return res, rows.Err()
}

// SavePermissionMatrixEntry records access decision with evidence.
func (p *PostgresStorage) SavePermissionMatrixEntry(ctx context.Context, entry *models.PermissionMatrixEntry) error {
	refsJSON, _ := json.Marshal(entry.EvidenceRefs)
	query := `
		INSERT INTO permission_matrix_entries (
			id, target_id, asset_id, endpoint, context_id, context_name, state,
			status_code, evidence_refs, observed_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5, $6, $7, $8, $9, NOW()
		) ON CONFLICT (id) DO UPDATE SET
			state = EXCLUDED.state,
			status_code = EXCLUDED.status_code,
			evidence_refs = EXCLUDED.evidence_refs,
			observed_at = NOW()
	`
	_, err := p.db.ExecContext(ctx, query,
		entry.ID,
		entry.TargetID,
		entry.AssetID,
		entry.Endpoint,
		entry.ContextID,
		entry.ContextName,
		string(entry.State),
		entry.StatusCode,
		refsJSON,
	)
	return err
}

// ListPermissionMatrix retrieves matrix entries for a target.
func (p *PostgresStorage) ListPermissionMatrix(ctx context.Context, targetID, assetID string) ([]*models.PermissionMatrixEntry, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), endpoint, context_id, context_name,
		       state, status_code, evidence_refs, observed_at
		FROM permission_matrix_entries
		WHERE target_id = $1 AND ($2 = '' OR asset_id = $2)
		ORDER BY endpoint ASC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*models.PermissionMatrixEntry
	for rows.Next() {
		var entry models.PermissionMatrixEntry
		var refsJSON []byte
		if err := rows.Scan(
			&entry.ID,
			&entry.TargetID,
			&entry.AssetID,
			&entry.Endpoint,
			&entry.ContextID,
			&entry.ContextName,
			&entry.State,
			&entry.StatusCode,
			&refsJSON,
			&entry.ObservedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(refsJSON, &entry.EvidenceRefs)
		res = append(res, &entry)
	}
	return res, rows.Err()
}

// SaveSecurityControl stores evaluated security control.
func (p *PostgresStorage) SaveSecurityControl(ctx context.Context, sc *models.SecurityControlRecord) error {
	refsJSON, _ := json.Marshal(sc.EvidenceRefs)
	query := `
		INSERT INTO security_control_records (
			id, target_id, asset_id, endpoint, control_name, expected_state,
			observed_state, is_contradicted, evidence_refs, confidence, evaluated_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5, $6, $7, $8, $9, $10, NOW()
		) ON CONFLICT (id) DO UPDATE SET
			observed_state = EXCLUDED.observed_state,
			is_contradicted = EXCLUDED.is_contradicted,
			evidence_refs = EXCLUDED.evidence_refs,
			confidence = EXCLUDED.confidence,
			evaluated_at = NOW()
	`
	_, err := p.db.ExecContext(ctx, query,
		sc.ID,
		sc.TargetID,
		sc.AssetID,
		sc.Endpoint,
		sc.ControlName,
		string(sc.ExpectedState),
		string(sc.ObservedState),
		sc.IsContradicted,
		refsJSON,
		sc.Confidence,
	)
	return err
}

// ListSecurityControls lists evaluated security controls.
func (p *PostgresStorage) ListSecurityControls(ctx context.Context, targetID, assetID string) ([]*models.SecurityControlRecord, error) {
	query := `
		SELECT id, target_id, COALESCE(asset_id, ''), COALESCE(endpoint, ''), control_name,
		       expected_state, observed_state, is_contradicted, evidence_refs, confidence, evaluated_at
		FROM security_control_records
		WHERE target_id = $1 AND ($2 = '' OR asset_id = $2)
		ORDER BY evaluated_at DESC
	`
	rows, err := p.db.QueryContext(ctx, query, targetID, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*models.SecurityControlRecord
	for rows.Next() {
		var sc models.SecurityControlRecord
		var refsJSON []byte
		if err := rows.Scan(
			&sc.ID,
			&sc.TargetID,
			&sc.AssetID,
			&sc.Endpoint,
			&sc.ControlName,
			&sc.ExpectedState,
			&sc.ObservedState,
			&sc.IsContradicted,
			&refsJSON,
			&sc.Confidence,
			&sc.EvaluatedAt,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(refsJSON, &sc.EvidenceRefs)
		res = append(res, &sc)
	}
	return res, rows.Err()
}

// RecordReasoningRun logs telemetry for a reasoning cycle.
func (p *PostgresStorage) RecordReasoningRun(ctx context.Context, run *models.ReasoningRun) error {
	query := `
		INSERT INTO reasoning_runs (
			id, target_id, asset_id, engine, engine_version, input_count,
			signals_count, hypotheses_count, duration_ms, status, error_message, created_at
		) VALUES (
			$1, $2, NULLIF($3, ''), $4, $5, $6, $7, $8, $9, $10, $11, NOW()
		)
	`
	_, err := p.db.ExecContext(ctx, query,
		run.ID,
		run.TargetID,
		run.AssetID,
		run.Engine,
		run.EngineVersion,
		run.InputCount,
		run.SignalsCount,
		run.HypothesesCount,
		run.DurationMs,
		run.Status,
		run.ErrorMessage,
	)
	return err
}
