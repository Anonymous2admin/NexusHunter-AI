package planner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
)

var (
	ErrActionNotAllowed      = errors.New("action type is not in the authorized validation allowlist")
	ErrTargetOutOfScope      = errors.New("plan step target URL is outside authorized scope")
	ErrDestructiveAction     = errors.New("plan step contains unauthorized destructive or exploit language")
	ErrPrematureConfirmation = errors.New("plan invalidly claims confirmed vulnerability without conclusive proof")
)

// AllowedActionTypes is the strict, deterministic allowlist for validation steps.
var AllowedActionTypes = map[string]bool{
	"FETCH_URL":             true,
	"COMPARE_RESPONSES":     true,
	"INSPECT_HEADERS":       true,
	"EXTRACT_JS_REFERENCE":  true,
	"CHECK_STATUS_CODE":     true,
	"VERIFY_DNS":            true,
	"INSPECT_TLS":           true,
	"SAFE_METADATA_CHECK":   true,
}

// BannedExploitWords flags any autonomous exploit or credential theft attempts.
var BannedExploitWords = []string{
	"exploit",
	"inject",
	"bypass",
	"brute_force",
	"dump_database",
	"steal_credential",
	"sqli_payload",
	"rce_payload",
	"reverse_shell",
	"privilege_escalation",
	"dos_attack",
}

// Service defines the AI Hunting Planner interface.
type Service interface {
	GenerateInvestigationPlan(ctx context.Context, target *models.Target, assetID string, input PlannerContext) (*models.InvestigationPlan, error)
	ValidatePlan(plan *models.InvestigationPlan, target *models.Target) error
	ApproveStep(ctx context.Context, planID string, stepNumber int) (*models.InvestigationPlan, error)
}

// PlannerContext aggregates current intelligence and evidence for the AI advisor.
type PlannerContext struct {
	Asset             *models.Asset            `json:"asset,omitempty"`
	Services          []*models.HTTPService    `json:"services"`
	JSReferences      []*models.JSReference    `json:"js_references"`
	CloudReferences   []*models.CloudReference `json:"cloud_references"`
	WAFObservation    *models.WAFObservation   `json:"waf_observation,omitempty"`
	HypothesisID      string                   `json:"hypothesis_id,omitempty"`
	HypothesisTitle   string                   `json:"hypothesis_title,omitempty"`
	SourceEvidenceIDs []string                 `json:"source_evidence_ids"`
}

type plannerService struct {
	scopeSvc scope.ScopeService
	plans    map[string]*models.InvestigationPlan
}

// NewService creates an initialized AI Hunting Planner service.
func NewService(scopeSvc scope.ScopeService) Service {
	return &plannerService{
		scopeSvc: scopeSvc,
		plans:    make(map[string]*models.InvestigationPlan),
	}
}

func randomID(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

// GenerateInvestigationPlan synthesizes an investigation plan and human validation checklist.
func (s *plannerService) GenerateInvestigationPlan(ctx context.Context, target *models.Target, assetID string, input PlannerContext) (*models.InvestigationPlan, error) {
	if target == nil {
		return nil, scope.ErrTargetNil
	}

	planID := randomID("plan")
	title := "Structured Asset Surface & Boundary Investigation"
	hypothesis := "Asset exposes differentiated endpoints or structural references requiring controlled verification"
	if input.HypothesisTitle != "" {
		hypothesis = input.HypothesisTitle
		title = fmt.Sprintf("Investigation: %s", input.HypothesisTitle)
	}

	observedFacts := make([]string, 0)
	missingEvidence := make([]string, 0)
	steps := make([]models.InvestigationPlanStep, 0)

	// Build observed facts from context
	if len(input.Services) > 0 {
		svc := input.Services[0]
		observedFacts = append(observedFacts, fmt.Sprintf("Observed HTTP Service %s with status %d (Server: %s)", svc.URL, svc.StatusCode, svc.ServerHeader))
	}

	if len(input.JSReferences) > 0 {
		observedFacts = append(observedFacts, fmt.Sprintf("Identified %d structural references in JavaScript assets", len(input.JSReferences)))
	}
	if len(input.CloudReferences) > 0 {
		observedFacts = append(observedFacts, fmt.Sprintf("Identified %d cloud infrastructure references (%s)", len(input.CloudReferences), input.CloudReferences[0].Provider))
	}
	if input.WAFObservation != nil && input.WAFObservation.Provider != "None Detected" {
		observedFacts = append(observedFacts, fmt.Sprintf("Active WAF observed: %s (State: %s)", input.WAFObservation.Provider, input.WAFObservation.ThrottlingState))
	}

	missingEvidence = append(missingEvidence, "Conclusive response diff under controlled authentication states")
	missingEvidence = append(missingEvidence, "Explicit server confirmation of route accessibility")

	// Synthesize safe validation steps
	stepNum := 1
	baseURL := fmt.Sprintf("https://%s", target.RootDomain)
	if input.Asset != nil && input.Asset.Hostname != "" {
		baseURL = fmt.Sprintf("https://%s", input.Asset.Hostname)
	}

	// Step 1: Inspect baseline headers
	steps = append(steps, models.InvestigationPlanStep{
		StepNumber:      stepNum,
		ActionType:      "INSPECT_HEADERS",
		Description:     "Retrieve and verify HTTP response headers for security controls and routing tags",
		TargetURL:       baseURL,
		Status:          "PENDING",
		ApprovedByHuman: false,
	})
	stepNum++

	// Step 2: Check status codes for discovered endpoints
	if len(input.JSReferences) > 0 {
		targetEndpoint := input.JSReferences[0].NormalizedValue
		if strings.HasPrefix(targetEndpoint, "/") {
			targetEndpoint = baseURL + targetEndpoint
		}
		steps = append(steps, models.InvestigationPlanStep{
			StepNumber:      stepNum,
			ActionType:      "CHECK_STATUS_CODE",
			Description:     fmt.Sprintf("Probe route '%s' with non-destructive GET request", input.JSReferences[0].NormalizedValue),
			TargetURL:       targetEndpoint,
			Status:          "PENDING",
			ApprovedByHuman: false,
		})
		stepNum++
	}

	// Step 3: Safe Cloud metadata/public status probe if present
	if len(input.CloudReferences) > 0 {
		cloudRef := input.CloudReferences[0]
		steps = append(steps, models.InvestigationPlanStep{
			StepNumber:      stepNum,
			ActionType:      "SAFE_METADATA_CHECK",
			Description:     fmt.Sprintf("Safe read-only HEAD probe on %s %s (%s)", cloudRef.Provider, cloudRef.ResourceType, cloudRef.NormalizedTarget),
			TargetURL:       cloudRef.RawReference,
			Status:          "PENDING",
			ApprovedByHuman: false,
		})
		stepNum++
	}

	plan := &models.InvestigationPlan{
		ID:                     planID,
		TargetID:               target.ID,
		AssetID:                assetID,
		HypothesisID:           input.HypothesisID,
		Title:                  title,
		Reason:                 "Deductive intelligence pipeline generated hypothesis requiring human-directed verification",
		Hypothesis:             hypothesis,
		WhyInteresting: models.WhyInteresting{
			ObservedFacts:   observedFacts,
			Deduction:       "Structural configuration deviates from standard hardened baseline",
			MissingEvidence: missingEvidence,
		},
		RequiredEvidence:       []string{"BASELINE_HTTP_RESPONSE", "ROUTE_ACCESSIBILITY_PROOF"},
		EvidenceRequiredCount:  2,
		EvidenceSatisfiedCount: 0,
		SafeValidation:         "Controlled read-only HTTP GET/HEAD checks with strict rate limiting",
		ExpectedObservation:    "Status code divergence or non-standard route authorization challenge",
		AlternativeExplanation: "Public-by-design static asset or standard reverse proxy redirect",
		StopCondition:          "Halt immediately if HTTP 429 received, WAF trips, or server returns unexpected 5xx",
		ScopeRequirements:      []string{fmt.Sprintf("Target must be within %s", target.RootDomain)},
		Risk:                   "LOW",
		Confidence:             "MEDIUM",
		EpistemicStatus:        "HYPOTHESIZED",
		Status:                 "PLANNED",
		SourceEvidenceIDs:      input.SourceEvidenceIDs,
		Steps:                  steps,
		CreatedAt:              time.Now().UTC(),
		UpdatedAt:              time.Now().UTC(),
	}

	// Validate plan rigorously
	if err := s.ValidatePlan(plan, target); err != nil {
		return nil, fmt.Errorf("plan validation failed: %w", err)
	}

	s.plans[plan.ID] = plan
	return plan, nil
}

// ValidatePlan enforces all safety, scope, and non-destructive requirements deterministically.
func (s *plannerService) ValidatePlan(plan *models.InvestigationPlan, target *models.Target) error {
	if plan == nil {
		return errors.New("nil plan")
	}

	// Check epistemic status transition rule
	if plan.EpistemicStatus == "CONFIRMED" && plan.EvidenceSatisfiedCount < plan.EvidenceRequiredCount {
		return ErrPrematureConfirmation
	}

	for _, step := range plan.Steps {
		// 1. Action type allowlist
		if !AllowedActionTypes[step.ActionType] {
			return fmt.Errorf("%w: '%s'", ErrActionNotAllowed, step.ActionType)
		}

		// 2. Exploit words rejection
		descLower := strings.ToLower(step.Description)
		for _, banned := range BannedExploitWords {
			if strings.Contains(descLower, banned) {
				return fmt.Errorf("%w: detected '%s' in step description", ErrDestructiveAction, banned)
			}
		}

		// 3. Scope validation on target URL
		if step.TargetURL != "" && s.scopeSvc != nil && target != nil {
			if u, err := url.Parse(step.TargetURL); err == nil && u.Hostname() != "" {
				// Only validate host if it is not an external cloud reference check
				if step.ActionType != "SAFE_METADATA_CHECK" {
					dec := s.scopeSvc.Evaluate(target, u.Hostname(), step.TargetURL)
					if !dec.InScope {
						return fmt.Errorf("%w: %s is not in scope (%s)", ErrTargetOutOfScope, step.TargetURL, dec.Reason)
					}
				}
			}
		}
	}

	return nil
}

// ApproveStep updates step status following human authorization.
func (s *plannerService) ApproveStep(ctx context.Context, planID string, stepNumber int) (*models.InvestigationPlan, error) {
	plan, exists := s.plans[planID]
	if !exists {
		return nil, errors.New("plan not found")
	}

	for i := range plan.Steps {
		if plan.Steps[i].StepNumber == stepNumber {
			now := time.Now().UTC()
			plan.Steps[i].ApprovedByHuman = true
			plan.Steps[i].ApprovedAt = &now
			plan.Steps[i].Status = "APPROVED"
			plan.Status = "APPROVED"
			plan.UpdatedAt = now
			return plan, nil
		}
	}

	return nil, errors.New("step number not found in plan")
}
