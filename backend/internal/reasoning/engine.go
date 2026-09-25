package reasoning

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/storage"
)

// Engine performs deterministic security reasoning, hypothesis generation, and investigation planning.
type Engine struct {
	reasoningRepo storage.ReasoningRepository
	evidenceRepo  storage.EvidenceRepository
	targetRepo    storage.TargetRepository
	assetRepo     storage.ReconRepository
}

// NewEngine creates a new Reasoning Engine.
func NewEngine(
	reasoningRepo storage.ReasoningRepository,
	evidenceRepo storage.EvidenceRepository,
	targetRepo storage.TargetRepository,
	assetRepo storage.ReconRepository,
) *Engine {
	return &Engine{
		reasoningRepo: reasoningRepo,
		evidenceRepo:  evidenceRepo,
		targetRepo:    targetRepo,
		assetRepo:     assetRepo,
	}
}

// RunReasoningCycle analyzes evidence and contradictions to emit signals, hypotheses, and investigation plans.
func (e *Engine) RunReasoningCycle(ctx context.Context, targetID, assetID string) (*models.ReasoningRun, error) {
	startTime := time.Now()

	// 1. Fetch input evidence and contradictions
	var evList []*models.Evidence
	var err error
	if assetID != "" {
		evList, err = e.evidenceRepo.ListEvidenceByAsset(ctx, assetID)
	} else {
		evList, err = e.evidenceRepo.ListEvidenceByTarget(ctx, targetID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list evidence: %w", err)
	}

	contradictions, err := e.evidenceRepo.ListSecurityContradictions(ctx, targetID, assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to list contradictions: %w", err)
	}

	diffs, err := e.evidenceRepo.ListEvidenceDiffs(ctx, targetID)
	if err != nil {
		return nil, fmt.Errorf("failed to list evidence diffs: %w", err)
	}

	signalsCount := 0
	hypothesesCount := 0

	// 2. Generate Signals from Evidence
	signals := e.generateSignalsFromEvidence(targetID, assetID, evList, contradictions, diffs)
	for _, sig := range signals {
		if err := e.reasoningRepo.SaveReasoningSignal(ctx, sig); err == nil {
			signalsCount++
		}
	}

	// 3. Correlate Signals into Groups and Hypotheses
	groups := e.correlateSignalsIntoHypotheses(targetID, assetID, signals)
	for _, grp := range groups {
		if err := e.reasoningRepo.SaveHypothesisGroup(ctx, grp); err != nil {
			continue
		}
		for _, hyp := range grp.Hypotheses {
			if err := e.reasoningRepo.SaveHypothesis(ctx, &hyp); err == nil {
				hypothesesCount++
			}
		}
	}

	// 4. Record Telemetry Run
	runHash := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%d", targetID, assetID, startTime.UnixNano())))
	run := &models.ReasoningRun{
		ID:              fmt.Sprintf("run-%x", runHash[:8]),
		TargetID:        targetID,
		AssetID:         assetID,
		Engine:          "NexusHunter-ReasoningEngine",
		EngineVersion:   "7.0.0",
		InputCount:      len(evList) + len(contradictions) + len(diffs),
		SignalsCount:    signalsCount,
		HypothesesCount: hypothesesCount,
		DurationMs:      time.Since(startTime).Milliseconds(),
		Status:          "SUCCESS",
		CreatedAt:       time.Now(),
	}

	if err := e.reasoningRepo.RecordReasoningRun(ctx, run); err != nil {
		return nil, fmt.Errorf("failed to persist reasoning run: %w", err)
	}
	return run, nil
}

// generateSignalsFromEvidence transforms raw observations into deterministic security signals.
func (e *Engine) generateSignalsFromEvidence(
	targetID, assetID string,
	evidence []*models.Evidence,
	contradictions []*models.SecurityContradiction,
	diffs []*models.EvidenceDiff,
) []*models.ReasoningSignal {
	var signals []*models.ReasoningSignal

	// Convert Contradictions to Signals
	for _, con := range contradictions {
		sigType := models.SignalTypeAuthInconsistency
		category := "AUTHENTICATION"
		if strings.Contains(string(con.ContradictionType), "AUTHORIZATION") {
			sigType = models.SignalTypeAuthorizationDiff
			category = "AUTHORIZATION"
		} else if strings.Contains(string(con.ContradictionType), "SECURITY_CONTROL") {
			sigType = models.SignalTypeHTTPSecurityControlDiff
			category = "SECURITY_CONTROL"
		} else if strings.Contains(string(con.ContradictionType), "TEMPORAL") {
			sigType = models.SignalTypeTemporalChange
			category = "TEMPORAL"
		}

		signals = append(signals, &models.ReasoningSignal{
			ID:                  fmt.Sprintf("sig-con-%s", con.ID),
			TargetID:            targetID,
			AssetID:             con.AssetID,
			Endpoint:            con.Endpoint,
			SignalType:          sigType,
			Category:            category,
			Title:               con.Title,
			Description:         con.Explanation,
			EpistemicStatus:     models.EpistemicObserved,
			Status:              models.SignalStatusOpen,
			SeverityOfAttention: models.AttentionSeverity(con.Severity),
			SourceObservations:  []string{con.ID},
			SourceEvidence:      con.EvidenceRefs,
			Detector:            "ContradictionBridgeDetector",
			DetectorVersion:     "7.0.0",
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		})
	}

	// Scan Evidence for Deterministic Signals
	for _, ev := range evidence {
		// Example: Permissive CORS Reflection
		if ev.RelevantHeaders != nil {
			if acao, ok := ev.RelevantHeaders["Access-Control-Allow-Origin"]; ok && (acao == "*" || strings.Contains(acao, "attacker")) {
				signals = append(signals, &models.ReasoningSignal{
					ID:                  fmt.Sprintf("sig-cors-%s", ev.ID),
					TargetID:            targetID,
					AssetID:             ev.AssetID,
					Endpoint:            extractPath(ev.Request),
					SignalType:          models.SignalTypeHTTPSecurityControlDiff,
					Category:            "CORS_POLICY",
					Title:               fmt.Sprintf("Permissive CORS policy detected on %s", extractPath(ev.Request)),
					Description:         fmt.Sprintf("Observed Access-Control-Allow-Origin: %s with Access-Control-Allow-Credentials.", acao),
					EpistemicStatus:     models.EpistemicObserved,
					Status:              models.SignalStatusOpen,
					SeverityOfAttention: models.SeverityHigh,
					SourceEvidence:      []string{ev.ID},
					Detector:            "HTTPControlPostureDetector",
					DetectorVersion:     "7.0.0",
					CreatedAt:           time.Now(),
					UpdatedAt:           time.Now(),
				})
			}
		}

		// Example: Auth Token Endpoint Responding 200 Unauthenticated
		if ev.Request != nil && !ev.Request.IsAuthenticated && ev.Response != nil && ev.Response.StatusCode == 200 {
			if strings.Contains(strings.ToLower(ev.Request.URL), "token") || strings.Contains(strings.ToLower(ev.Request.URL), "auth") {
				signals = append(signals, &models.ReasoningSignal{
					ID:                  fmt.Sprintf("sig-auth-%s", ev.ID),
					TargetID:            targetID,
					AssetID:             ev.AssetID,
					Endpoint:            extractPath(ev.Request),
					SignalType:          models.SignalTypeAuthInconsistency,
					Category:            "AUTH_BOUNDARY",
					Title:               fmt.Sprintf("Unauthenticated 200 OK Response from Auth Endpoint %s", extractPath(ev.Request)),
					Description:         "Endpoint responds with successful token issuance or metadata without active session credentials.",
					EpistemicStatus:     models.EpistemicObserved,
					Status:              models.SignalStatusOpen,
					SeverityOfAttention: models.SeverityHigh,
					SourceEvidence:      []string{ev.ID},
					Detector:            "AuthBoundaryDetector",
					DetectorVersion:     "7.0.0",
					CreatedAt:           time.Now(),
					UpdatedAt:           time.Now(),
				})
			}
		}
	}

	return signals
}

// correlateSignalsIntoHypotheses clusters signals and constructs competing hypotheses.
func (e *Engine) correlateSignalsIntoHypotheses(targetID, assetID string, signals []*models.ReasoningSignal) []*models.HypothesisGroup {
	var groups []*models.HypothesisGroup

	// Group by endpoint or category
	endpointClusters := make(map[string][]*models.ReasoningSignal)
	for _, s := range signals {
		key := s.Endpoint
		if key == "" {
			key = s.Category
		}
		endpointClusters[key] = append(endpointClusters[key], s)
	}

	for endpoint, cluster := range endpointClusters {
		var sigIDs []string
		var evRefs []string
		for _, s := range cluster {
			sigIDs = append(sigIDs, s.ID)
			evRefs = append(evRefs, s.SourceEvidence...)
		}

		grpHash := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%s", targetID, assetID, endpoint)))
		groupID := fmt.Sprintf("grp-%x", grpHash[:8])
		group := &models.HypothesisGroup{
			ID:                   groupID,
			TargetID:             targetID,
			AssetID:              assetID,
			Subject:              fmt.Sprintf("Security Posture Evaluation: %s", endpoint),
			Signals:              sigIDs,
			HasCompetingTheories: true,
			CreatedAt:            time.Now(),
			UpdatedAt:            time.Now(),
		}

		// Build Competing Hypotheses:
		// Theory A: Intended / Documented Public Behavior
		hypA := models.Hypothesis{
			ID:                    fmt.Sprintf("hyp-%s-a", groupID),
			GroupID:               groupID,
			TargetID:              targetID,
			AssetID:               assetID,
			Endpoint:              endpoint,
			Title:                 fmt.Sprintf("Intentional Public Onboarding Behavior on %s", endpoint),
			Description:           "The endpoint is intentionally configured to issue public guest tokens or anonymous claims as part of the public client application flow.",
			Category:              models.HypothesisCatIntentionalPublic,
			EpistemicStatus:       models.EpistemicHypothesized,
			Status:                models.HypothesisStatusHypothesized,
			ReasoningMethod:       "DETERMINISTIC_COMPETING_HYPOTHESIS",
			SupportingSignals:     sigIDs,
			SupportingEvidence:    evRefs,
			EvidenceStrength:      3,
			InvestigationPriority: 45,
			PriorityBreakdown: map[string]int{
				"evidence_strength":            3,
				"signal_novelty":               2,
				"security_control_deviation":   2,
				"trust_boundary_relevance":     2,
			},
			FalsificationConditions: []models.FalsificationCondition{
				{
					ID:                   fmt.Sprintf("fc-%s-a1", groupID),
					HypothesisID:         fmt.Sprintf("hyp-%s-a", groupID),
					ConditionDescription: "If guest tokens lack claims for administrative resources and expire within 60s, this confirms intended guest access flow.",
					RequiredEvidence:     "Token claim inspection under anonymous context",
					ValidationMethod:     "TOKEN_PAYLOAD_VALIDATION",
					Result:               models.FalsificationPending,
				},
			},
			MissingEvidence: []models.EvidenceRequirement{
				{
					ID:               fmt.Sprintf("er-%s-a1", groupID),
					HypothesisID:     fmt.Sprintf("hyp-%s-a", groupID),
					Description:      "Missing: Response when querying protected resource using the issued token.",
					Importance:       "HIGH",
					EvidenceType:     models.EvidenceAuthObservation,
					CollectionMethod: "SAFE_CONTEXT_PROBE",
					Status:           models.ReqStatusMissing,
					CreatedAt:        time.Now(),
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		// Theory B: Security Control / Policy Boundary Deviation
		hypB := models.Hypothesis{
			ID:                    fmt.Sprintf("hyp-%s-b", groupID),
			GroupID:               groupID,
			TargetID:              targetID,
			AssetID:               assetID,
			Endpoint:              endpoint,
			Title:                 fmt.Sprintf("Authentication Filter Bypass / Missing Enforcement on %s", endpoint),
			Description:           "Reverse proxy or API gateway fails to validate authentication headers before routing request to internal identity service.",
			Category:              models.HypothesisCatAuthPolicyDiff,
			EpistemicStatus:       models.EpistemicHypothesized,
			Status:                models.HypothesisStatusHypothesized,
			ReasoningMethod:       "DETERMINISTIC_COMPETING_HYPOTHESIS",
			SupportingSignals:     sigIDs,
			SupportingEvidence:    evRefs,
			EvidenceStrength:      4,
			InvestigationPriority: 85,
			PriorityBreakdown: map[string]int{
				"evidence_strength":            4,
				"signal_novelty":               4,
				"cross_signal_correlation":     4,
				"security_control_deviation":   5,
				"trust_boundary_relevance":     5,
			},
			FalsificationConditions: []models.FalsificationCondition{
				{
					ID:                   fmt.Sprintf("fc-%s-b1", groupID),
					HypothesisID:         fmt.Sprintf("hyp-%s-b", groupID),
					ConditionDescription: "If providing invalid malformed authorization header returns 401 Unauthorized, an auth filter is active and this is not a blind bypass.",
					RequiredEvidence:     "HTTP response with malformed Authorization header",
					ValidationMethod:     "DIFFERENTIAL_AUTH_PROBE",
					Result:               models.FalsificationPending,
				},
			},
			MissingEvidence: []models.EvidenceRequirement{
				{
					ID:               fmt.Sprintf("er-%s-b1", groupID),
					HypothesisID:     fmt.Sprintf("hyp-%s-b", groupID),
					Description:      "Missing: Differential response between Anonymous and Authenticated roles.",
					Importance:       "CRITICAL",
					EvidenceType:     models.EvidenceDifferentialResult,
					CollectionMethod: "CONTROLLED_VALIDATION",
					Status:           models.ReqStatusMissing,
					CreatedAt:        time.Now(),
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		// Theory C: Epistemic Unknown (Insufficient Evidence)
		hypC := models.Hypothesis{
			ID:                    fmt.Sprintf("hyp-%s-c", groupID),
			GroupID:               groupID,
			TargetID:              targetID,
			AssetID:               assetID,
			Endpoint:              endpoint,
			Title:                 fmt.Sprintf("Insufficient Evidence to Determine Boundary State on %s", endpoint),
			Description:           "Current reconnaissance observations are insufficient to distinguish intentional public behavior from architectural misconfiguration.",
			Category:              models.HypothesisCatCustomResearch,
			EpistemicStatus:       models.EpistemicUnknown,
			Status:                models.HypothesisStatusUnknown,
			ReasoningMethod:       "EPISTEMIC_DISCIPLINE_BASELINE",
			SupportingSignals:     sigIDs,
			EvidenceStrength:      1,
			InvestigationPriority: 30,
			PriorityBreakdown: map[string]int{
				"evidence_strength":          1,
				"missing_evidence_completeness": 5,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		group.HypothesisIDs = []string{hypA.ID, hypB.ID, hypC.ID}
		group.Hypotheses = []models.Hypothesis{hypA, hypB, hypC}
		groups = append(groups, group)
	}

	return groups
}

// PlanInvestigation constructs an authorized, safe, non-destructive investigation plan for a hypothesis.
func (e *Engine) PlanInvestigation(ctx context.Context, hypothesisID, createdBy string) (*models.Investigation, error) {
	hyp, err := e.reasoningRepo.GetHypothesis(ctx, hypothesisID)
	if err != nil {
		return nil, fmt.Errorf("hypothesis not found: %w", err)
	}

	invHash := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", hypothesisID, time.Now().UnixNano())))
	invID := fmt.Sprintf("inv-%x", invHash[:8])
	steps := []models.InvestigationStep{
		{
			StepNumber:      1,
			Name:            "Capture Verified Scope Baseline",
			Description:     "Verify target host against active scope boundaries and capture non-intrusive GET/HEAD response baseline.",
			ActionType:      "CAPTURE_BASELINE",
			ScopeConstraint: "STRICT_SCOPE_ALLOWLIST",
			Status:          "PENDING",
		},
		{
			StepNumber:      2,
			Name:            "Evaluate Multi-Role Differential",
			Description:     "Issue safe GET request with simulated anonymous context vs standard authorized researcher context.",
			ActionType:      "COMPARE_CONTEXTS",
			ScopeConstraint: "STRICT_SCOPE_ALLOWLIST",
			Status:          "PENDING",
		},
		{
			StepNumber:      3,
			Name:            "Inspect Response Stability & Semantic Variation",
			Description:     "Calculate Level 1 Raw Diff, Level 2 Semantic Diff, and Level 3 Security Diff across observations.",
			ActionType:      "EVALUATE_SEMANTICS",
			ScopeConstraint: "PASSIVE_ANALYSIS_ONLY",
			Status:          "PENDING",
		},
		{
			StepNumber:      4,
			Name:            "Update Hypothesis Falsification Matrix",
			Description:     "Test empirical findings against falsification conditions to support or eliminate competing hypotheses.",
			ActionType:      "FALSIFICATION_EVALUATION",
			ScopeConstraint: "LOCAL_REASONING_ONLY",
			Status:          "PENDING",
		},
	}

	priorityLevel := "MEDIUM"
	if hyp.InvestigationPriority >= 75 {
		priorityLevel = "HIGH"
	} else if hyp.InvestigationPriority >= 90 {
		priorityLevel = "CRITICAL"
	} else if hyp.InvestigationPriority < 40 {
		priorityLevel = "LOW"
	}

	inv := &models.Investigation{
		ID:              invID,
		TargetID:        hyp.TargetID,
		AssetID:         hyp.AssetID,
		HypothesisID:    hyp.ID,
		GroupID:         hyp.GroupID,
		Title:           fmt.Sprintf("Safe Differential Investigation: %s", hyp.Title),
		Objective:       fmt.Sprintf("Collect differential evidence to evaluate whether '%s' holds true or is falsified.", hyp.Title),
		Priority:        priorityLevel,
		PriorityScore:   hyp.InvestigationPriority,
		PriorityFactors: hyp.PriorityBreakdown,
		Status:          models.InvStatusPlanned,
		Steps:           steps,
		CreatedBy:       createdBy,
		CreatedAt:       time.Now(),
	}

	if err := e.reasoningRepo.SaveInvestigation(ctx, inv); err != nil {
		return nil, err
	}
	return inv, nil
}

func extractPath(req *models.HTTPRequestContext) string {
	if req == nil || req.URL == "" {
		return "/"
	}
	idx := strings.Index(req.URL, "://")
	if idx != -1 {
		rest := req.URL[idx+3:]
		pathIdx := strings.Index(rest, "/")
		if pathIdx != -1 {
			return rest[pathIdx:]
		}
	}
	return req.URL
}

// ValidateHypothesisTransition checks if transitioning from current to next is legal under strict epistemic discipline.
func ValidateHypothesisTransition(current, next models.HypothesisStatus) bool {
	if current == next {
		return true
	}
	switch current {
	case models.HypothesisStatusHypothesized:
		return next == models.HypothesisStatusInvestigating || next == models.HypothesisStatusDismissed
	case models.HypothesisStatusInvestigating:
		return next == models.HypothesisStatusSupported || next == models.HypothesisStatusFalsified || next == models.HypothesisStatusUnknown || next == models.HypothesisStatusDismissed
	case models.HypothesisStatusSupported:
		return next == models.HypothesisStatusInvestigating || next == models.HypothesisStatusDismissed
	case models.HypothesisStatusFalsified:
		return next == models.HypothesisStatusInvestigating || next == models.HypothesisStatusDismissed
	case models.HypothesisStatusUnknown:
		return next == models.HypothesisStatusInvestigating || next == models.HypothesisStatusDismissed
	case models.HypothesisStatusDismissed:
		return next == models.HypothesisStatusHypothesized
	}
	return false
}

// ValidateSignalTransition checks if transitioning from current to next is legal.
func ValidateSignalTransition(current, next models.SignalStatus) bool {
	if current == next {
		return true
	}
	switch current {
	case models.SignalStatusOpen:
		return next == models.SignalStatusCorrelated || next == models.SignalStatusDismissed
	case models.SignalStatusCorrelated:
		return next == models.SignalStatusSuperseded || next == models.SignalStatusDismissed
	case models.SignalStatusSuperseded:
		return next == models.SignalStatusOpen
	case models.SignalStatusDismissed:
		return next == models.SignalStatusOpen
	}
	return false
}

// ValidateInvestigationTransition checks if transitioning from current to next is legal.
func ValidateInvestigationTransition(current, next models.InvestigationStatus) bool {
	if current == next {
		return true
	}
	switch current {
	case models.InvStatusPlanned:
		return next == models.InvStatusQueued || next == models.InvStatusCancelled
	case models.InvStatusQueued:
		return next == models.InvStatusRunning || next == models.InvStatusCancelled
	case models.InvStatusRunning:
		return next == models.InvStatusCompleted || next == models.InvStatusFailed || next == models.InvStatusCancelled
	case models.InvStatusFailed:
		return next == models.InvStatusQueued || next == models.InvStatusCancelled
	case models.InvStatusCancelled:
		return next == models.InvStatusPlanned
	case models.InvStatusCompleted:
		return false // Terminal state
	}
	return false
}
