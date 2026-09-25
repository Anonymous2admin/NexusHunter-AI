package evidence

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
)

// Storage defines the minimal persistence operations needed by the EvidenceEngine.
type Storage interface {
	SaveEvidence(ctx context.Context, ev *models.Evidence) error
	GetEvidence(ctx context.Context, id string) (*models.Evidence, error)
	ListEvidenceByTarget(ctx context.Context, targetID string) ([]*models.Evidence, error)
	ListEvidenceByAsset(ctx context.Context, assetID string) ([]*models.Evidence, error)
	ListEvidenceByObservation(ctx context.Context, obsID string) ([]*models.Evidence, error)

	SaveEvidenceDiff(ctx context.Context, diff *models.EvidenceDiff) error
	GetEvidenceDiff(ctx context.Context, id string) (*models.EvidenceDiff, error)

	SaveSecurityExpectation(ctx context.Context, exp *models.SecurityExpectation) error
	ListSecurityExpectations(ctx context.Context, targetID, assetID string) ([]*models.SecurityExpectation, error)

	SaveSecurityContradiction(ctx context.Context, con *models.SecurityContradiction) error
	ListSecurityContradictions(ctx context.Context, targetID, assetID string) ([]*models.SecurityContradiction, error)

	SaveSecurityOutlier(ctx context.Context, out *models.SecurityOutlier) error
	ListSecurityOutliers(ctx context.Context, targetID, assetID string) ([]*models.SecurityOutlier, error)

	RecordTimelineEvent(ctx context.Context, ev *models.EvidenceTimelineEvent) error
	ListTimelineEvents(ctx context.Context, targetID, assetID string, limit int) ([]*models.EvidenceTimelineEvent, error)
}

// EngineCoordinates coordinates evidence sanitization, canonical hashing, diffing, contradiction detection, and interest synthesis.
type Engine struct {
	sanitizer *Sanitizer
	canonical *Canonicalizer
	diff      *DifferentialEngine
	scopeVal  *scope.Validator
	storage   Storage
	logger    *slog.Logger
}

// NewEngine constructs the evidence intelligence engine.
func NewEngine(storage Storage, scopeVal *scope.Validator, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		sanitizer: NewSanitizer(),
		canonical: NewCanonicalizer(),
		diff:      NewDifferentialEngine(),
		scopeVal:  scopeVal,
		storage:   storage,
		logger:    logger,
	}
}

// RecordEvidence ingests raw evidence, performs centralized sanitization, canonicalizes, computes integrity SHA-256, and persists.
func (e *Engine) RecordEvidence(ctx context.Context, raw *models.Evidence) (*models.Evidence, error) {
	if raw == nil {
		return nil, fmt.Errorf("evidence cannot be nil")
	}

	// Assign ID if missing
	if raw.ID == "" {
		raw.ID = "ev-" + uuid.New().String()[:12]
	}
	if raw.CapturedAt.IsZero() {
		raw.CapturedAt = time.Now().UTC()
	}

	// 1. Centralized Sanitization Boundary
	sanitized := e.sanitizer.Sanitize(raw)
	e.logger.Info("evidence sanitized",
		slog.String("evidence_id", sanitized.ID),
		slog.Bool("is_redacted", sanitized.RedactionStatus.IsRedacted),
		slog.Int("redacted_fields_count", len(sanitized.RedactionStatus.RedactedFields)),
	)

	// 2. Canonical Serialization & SHA-256 Integrity Hashing
	hash, err := e.canonical.CanonicalizeAndHash(sanitized)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize evidence: %w", err)
	}
	sanitized.IntegrityHash = hash
	e.logger.Info("evidence hashed",
		slog.String("evidence_id", sanitized.ID),
		slog.String("sha256", hash),
	)

	// 3. Persist Evidence
	if e.storage != nil {
		if err := e.storage.SaveEvidence(ctx, sanitized); err != nil {
			return nil, fmt.Errorf("failed to save evidence: %w", err)
		}

		// 4. Record Timeline Event
		timelineEv := &models.EvidenceTimelineEvent{
			ID:              "tl-" + uuid.New().String()[:12],
			TargetID:        sanitized.TargetID,
			AssetID:         sanitized.AssetID,
			EventType:       "EVIDENCE_COLLECTED",
			Summary:         sanitized.Summary,
			EpistemicStatus: models.EpistemicObserved,
			Timestamp:       sanitized.CapturedAt,
			Provenance:      sanitized.Provenance,
			ReferenceID:     sanitized.ID,
			Details: map[string]interface{}{
				"evidence_type": sanitized.EvidenceType,
				"sha256":        sanitized.SHA256,
				"is_redacted":   sanitized.RedactionStatus.IsRedacted,
			},
		}
		if err := e.storage.RecordTimelineEvent(ctx, timelineEv); err != nil {
			e.logger.Error("failed to record evidence timeline event", slog.Any("error", err), slog.String("evidence_id", sanitized.ID))
			return nil, fmt.Errorf("failed to persist evidence timeline event: %w", err)
		}
	}

	return sanitized, nil
}

// CompareEvidence executes the 3-level comparative analysis between two evidence records.
func (e *Engine) CompareEvidence(ctx context.Context, evidenceAID, evidenceBID string, filterNoise bool) (*models.EvidenceDiff, error) {
	if e.storage == nil {
		return nil, fmt.Errorf("storage not configured")
	}

	evA, err := e.storage.GetEvidence(ctx, evidenceAID)
	if err != nil {
		return nil, fmt.Errorf("failed to get evidence A: %w", err)
	}
	evB, err := e.storage.GetEvidence(ctx, evidenceBID)
	if err != nil {
		return nil, fmt.Errorf("failed to get evidence B: %w", err)
	}

	// Strict guardrail: reject cross-target comparisons
	if evA.TargetID != evB.TargetID {
		return nil, fmt.Errorf("TARGET_MISMATCH_PROHIBITED: cross-target comparisons are not allowed (A target %s vs B target %s)", evA.TargetID, evB.TargetID)
	}

	diff, err := e.diff.ComputeDiff(evA, evB, filterNoise)
	if err != nil {
		return nil, err
	}

	if err := e.storage.SaveEvidenceDiff(ctx, diff); err != nil {
		return nil, fmt.Errorf("failed to save evidence diff: %w", err)
	}

	e.logger.Info("differential computed",
		slog.String("diff_id", diff.ID),
		slog.Bool("is_security_relevant", diff.IsSecurityRelevant),
		slog.String("category", diff.SemanticDiff.Category),
	)

	// Record timeline event
	if err := e.storage.RecordTimelineEvent(ctx, &models.EvidenceTimelineEvent{
		ID:              "tl-" + uuid.New().String()[:12],
		TargetID:        diff.TargetID,
		AssetID:         diff.AssetID,
		EventType:       "DIFF_COMPUTED",
		Summary:         diff.SemanticDiff.Meaning,
		EpistemicStatus: models.EpistemicDerived,
		Timestamp:       diff.ComputedAt,
		Provenance: models.EvidenceProvenance{
			Source:      models.SourceDifferentialEngine,
			OperationID: diff.ID,
			TargetID:    diff.TargetID,
			AssetID:     diff.AssetID,
			CapturedAt:  diff.ComputedAt,
			Initiator:   "differential_engine",
		},
		ReferenceID: diff.ID,
		Details: map[string]interface{}{
			"is_security_relevant": diff.IsSecurityRelevant,
			"category":             diff.SemanticDiff.Category,
		},
	}); err != nil {
		e.logger.Error("failed to record diff timeline event", slog.Any("error", err), slog.String("diff_id", diff.ID))
		return nil, fmt.Errorf("failed to persist diff timeline event: %w", err)
	}

	return diff, nil
}

// EvaluateContradiction performs deterministic contradiction evaluation between an expected model and an observed fact.
// Crucial: "NOT_OBSERVED" is strictly distinguished from "ABSENT".
func (e *Engine) EvaluateContradiction(
	ctx context.Context,
	targetID string,
	assetID string,
	endpoint string,
	expected *models.SecurityExpectation,
	observedState models.EpistemicObservationState,
	evidenceRefs []string,
) (*models.SecurityContradiction, error) {
	if expected == nil {
		return nil, fmt.Errorf("expected security model cannot be nil")
	}
	if strings.TrimSpace(targetID) == "" || strings.TrimSpace(assetID) == "" || strings.TrimSpace(endpoint) == "" {
		return nil, fmt.Errorf("targetID, assetID, and endpoint are strictly required for contradiction evaluation")
	}
	if len(evidenceRefs) == 0 {
		return nil, fmt.Errorf("at least one evidence reference is strictly required; cannot evaluate without evidence context")
	}

	// If observed matches expected, no contradiction exists
	if expected.ExpectedState == observedState {
		return nil, nil
	}

	// Deterministic evaluation
	var conType models.ContradictionType = models.ContradictionSecurityControl
	var status models.ContradictionStatus = models.ContradictionUnverified
	var severity = "MEDIUM"
	var explanation string
	var followup []string

	title := fmt.Sprintf("Contradiction: %s on %s", expected.ControlName, endpoint)

	if expected.ExpectedState == models.StatePresent && observedState == models.StateAbsent {
		// Control expected PRESENT, but proven ABSENT
		conType = models.ContradictionSecurityControl
		status = models.ContradictionConfirmedDeviation
		severity = "HIGH"
		explanation = fmt.Sprintf("Security control '%s' is expected (Source: %s) but was confirmed ABSENT in observed response.", expected.ControlName, expected.Source)
		followup = []string{
			"Verify if an alternative authentication or boundary control applies.",
			"Confirm if endpoint is deprecated or inadvertently exposed.",
		}
	} else if expected.ExpectedState == models.StatePresent && observedState == models.StateNotObserved {
		// Control expected PRESENT, but NOT OBSERVED (crucial: not the same as absent!)
		conType = models.ContradictionSecurityControl
		status = models.ContradictionUnverified
		severity = "MEDIUM"
		explanation = fmt.Sprintf("Security control '%s' was NOT OBSERVED in current evidence. Note: 'Not observed' does not establish absence; safe verification probe required.", expected.ControlName)
		followup = []string{
			"Perform controlled, authorized observation specifically verifying the presence of " + expected.ControlName,
			"Check whether the control is enforced at an outer proxy or downstream gateway.",
		}
	} else if expected.ExpectedState == models.StateAbsent && observedState == models.StatePresent {
		conType = models.ContradictionTrustBoundary
		status = models.ContradictionConfirmedDeviation
		severity = "HIGH"
		explanation = fmt.Sprintf("Control/Feature '%s' expected to be absent/restricted, but was observed PRESENT.", expected.ControlName)
		followup = []string{
			"Examine if internal functionality is leaking past the trust boundary.",
		}
	} else {
		conType = models.ContradictionBehavioral
		status = models.ContradictionInvestigating
		severity = "LOW"
		explanation = fmt.Sprintf("Expected state '%s' contradicts observed state '%s' for '%s'.", expected.ExpectedState, observedState, expected.ControlName)
		followup = []string{"Inspect telemetry and peer endpoint baseline."}
	}

	contradiction := &models.SecurityContradiction{
		ID:                "con-" + uuid.New().String()[:12],
		TargetID:          targetID,
		AssetID:           assetID,
		Endpoint:          endpoint,
		ContradictionType: conType,
		Status:            status,
		Severity:          severity,
		Title:             title,
		Description:       expected.Description,
		ExpectationID:     expected.ID,
		ObservedState:     observedState,
		EvidenceRefs:      evidenceRefs,
		Explanation:       explanation,
		SuggestedFollowup: followup,
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}

	if e.storage != nil {
		if err := e.storage.SaveSecurityContradiction(ctx, contradiction); err != nil {
			return nil, err
		}

		if err := e.storage.RecordTimelineEvent(ctx, &models.EvidenceTimelineEvent{
			ID:              "tl-" + uuid.New().String()[:12],
			TargetID:        targetID,
			AssetID:         assetID,
			EventType:       "CONTRADICTION_FLAGGED",
			Summary:         contradiction.Title,
			EpistemicStatus: models.EpistemicInferred,
			Timestamp:       contradiction.CreatedAt,
			Provenance: models.EvidenceProvenance{
				Source:      models.SourceDifferentialEngine,
				OperationID: contradiction.ID,
				TargetID:    targetID,
				AssetID:     assetID,
				CapturedAt:  contradiction.CreatedAt,
				Initiator:   "contradiction_engine",
			},
			ReferenceID: contradiction.ID,
			Details: map[string]interface{}{
				"contradiction_type": contradiction.ContradictionType,
				"status":             contradiction.Status,
				"severity":           contradiction.Severity,
			},
		}); err != nil {
			e.logger.Error("failed to record contradiction timeline event", slog.Any("error", err), slog.String("contradiction_id", contradiction.ID))
			return nil, fmt.Errorf("failed to persist contradiction timeline event: %w", err)
		}
	}

	e.logger.Info("contradiction created",
		slog.String("contradiction_id", contradiction.ID),
		slog.String("type", string(contradiction.ContradictionType)),
		slog.String("status", string(contradiction.Status)),
	)

	return contradiction, nil
}

// SynthesizeAssetInterest computes deterministic, evidence-backed reasons why an asset warrants researcher attention.
func (e *Engine) SynthesizeAssetInterest(ctx context.Context, targetID, assetID, hostname string) (*models.AssetInterestSummary, error) {
	summary := &models.AssetInterestSummary{
		AssetID:           assetID,
		Hostname:          hostname,
		TargetID:          targetID,
		Score:             0,
		Reasons:           []models.InterestReason{},
		LinkedEvidenceIDs: []string{},
		EvaluatedAt:       time.Now().UTC(),
	}

	if e.storage == nil {
		return summary, nil
	}

	// 1. Evidence items for this asset
	evidenceList, _ := e.storage.ListEvidenceByAsset(ctx, assetID)
	for _, ev := range evidenceList {
		summary.LinkedEvidenceIDs = append(summary.LinkedEvidenceIDs, ev.ID)
	}

	// 2. Contradictions for this asset
	contradictions, _ := e.storage.ListSecurityContradictions(ctx, targetID, assetID)
	if len(contradictions) > 0 {
		var conRefs []string
		for _, c := range contradictions {
			conRefs = append(conRefs, c.EvidenceRefs...)
		}
		summary.Reasons = append(summary.Reasons, models.InterestReason{
			FactorName:   "CONTRADICTION_IDENTIFIED",
			Description:  fmt.Sprintf("%d structural security contradictions identified against expected security model.", len(contradictions)),
			EvidenceRefs: conRefs,
			Weight:       30,
		})
		summary.Score += 30
	}

	// 3. Outliers for this asset
	outliers, _ := e.storage.ListSecurityOutliers(ctx, targetID, assetID)
	if len(outliers) > 0 {
		var outRefs []string
		for _, o := range outliers {
			outRefs = append(outRefs, o.EvidenceRefs...)
		}
		summary.Reasons = append(summary.Reasons, models.InterestReason{
			FactorName:   "BEHAVIORAL_OUTLIER",
			Description:  fmt.Sprintf("%d statistical or behavioral outliers relative to peer comparison baseline.", len(outliers)),
			EvidenceRefs: outRefs,
			Weight:       25,
		})
		summary.Score += 25
	}

	// 4. Evidence count check
	if len(evidenceList) > 0 {
		summary.Reasons = append(summary.Reasons, models.InterestReason{
			FactorName:   "EVIDENCE_BACKED_OBSERVATIONS",
			Description:  fmt.Sprintf("Asset has %d structured, verifiable cryptographic evidence records.", len(evidenceList)),
			EvidenceRefs: summary.LinkedEvidenceIDs,
			Weight:       15,
		})
		summary.Score += 15
	}

	if summary.Score > 100 {
		summary.Score = 100
	}

	return summary, nil
}

// VerifyEvidenceIntegrity recalculates the canonical SHA-256 hash of a stored evidence record to detect tampering.
func (e *Engine) VerifyEvidenceIntegrity(ctx context.Context, evidenceID string) (*models.EvidenceIntegrityResult, error) {
	if e.storage == nil {
		return nil, fmt.Errorf("storage not configured")
	}

	ev, err := e.storage.GetEvidence(ctx, evidenceID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve evidence %s: %w", evidenceID, err)
	}
	if ev == nil {
		return nil, fmt.Errorf("evidence not found: %s", evidenceID)
	}

	// Make a shallow copy and recalculate canonical hash
	copyEv := *ev
	computedHash, err := e.canonical.CanonicalizeAndHash(&copyEv)
	if err != nil {
		return nil, fmt.Errorf("failed to compute canonical hash: %w", err)
	}

	isTampered := ev.SHA256 != "" && ev.SHA256 != computedHash
	return &models.EvidenceIntegrityResult{
		EvidenceID:       ev.ID,
		OriginalSHA256:   ev.SHA256,
		ComputedSHA256:   computedHash,
		IsTampered:       isTampered,
		VerifiedAt:       time.Now().UTC(),
		CanonicalMatches: !isTampered,
	}, nil
}

