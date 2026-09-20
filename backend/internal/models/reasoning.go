package models

import (
	"time"
)

// SignalStatus defines the lifecycle of a deterministic security signal.
type SignalStatus string

const (
	SignalStatusOpen       SignalStatus = "OPEN"
	SignalStatusCorrelated SignalStatus = "CORRELATED"
	SignalStatusSuperseded SignalStatus = "SUPERSEDED"
	SignalStatusDismissed  SignalStatus = "DISMISSED"
)

// ReasoningSignalType categorizes deterministic observations of interest.
// Crucial: A Signal is NOT a vulnerability declaration.
type ReasoningSignalType string

const (
	SignalTypeAuthInconsistency         ReasoningSignalType = "AUTH_INCONSISTENCY"
	SignalTypeAuthorizationDiff         ReasoningSignalType = "AUTHORIZATION_INCONSISTENCY"
	SignalTypeHTTPSecurityControlDiff   ReasoningSignalType = "HTTP_SECURITY_CONTROL"
	SignalTypeInfrastructureAnomaly     ReasoningSignalType = "INFRASTRUCTURE_ANOMALY"
	SignalTypeApplicationBehavior       ReasoningSignalType = "APPLICATION_BEHAVIOR"
	SignalTypeTemporalChange            ReasoningSignalType = "TEMPORAL_CHANGE"
)

// AttentionSeverity guides researcher prioritization without declaring vulnerability impact.
type AttentionSeverity string

const (
	SeverityInfo     AttentionSeverity = "INFO"
	SeverityLow      AttentionSeverity = "LOW"
	SeverityMedium   AttentionSeverity = "MEDIUM"
	SeverityHigh     AttentionSeverity = "HIGH"
)

// ReasoningSignal represents a deterministic observation derived from raw evidence and observations.
type ReasoningSignal struct {
	ID                  string              `json:"id"`
	TargetID            string              `json:"target_id"`
	AssetID             string              `json:"asset_id,omitempty"`
	Endpoint            string              `json:"endpoint,omitempty"`
	SignalType          ReasoningSignalType `json:"signal_type"`
	Category            string              `json:"category"` // e.g. "AUTH_BOUNDARY", "HEADER_POSTURE", "CDN_DRIFT"
	Title               string              `json:"title"`
	Description         string              `json:"description"`
	EpistemicStatus     EpistemicStatus     `json:"epistemic_status"` // e.g. "OBSERVED", "DERIVED"
	Status              SignalStatus        `json:"status"`
	SeverityOfAttention AttentionSeverity   `json:"severity_of_attention"`
	SourceObservations  []string            `json:"source_observations,omitempty"`
	SourceEvidence      []string            `json:"source_evidence"`
	Detector            string              `json:"detector"`
	DetectorVersion     string              `json:"detector_version"`
	Metadata            map[string]any      `json:"metadata,omitempty"`
	CreatedAt           time.Time           `json:"created_at"`
	UpdatedAt           time.Time           `json:"updated_at"`
}

// HypothesisCategory classifies competing explanations for observed security signals.
type HypothesisCategory string

const (
	HypothesisCatAuthPolicyDiff         HypothesisCategory = "AUTH_POLICY_DIFF"
	HypothesisCatResourceOwnership      HypothesisCategory = "RESOURCE_OWNERSHIP_DIFF"
	HypothesisCatLegacyBehavior         HypothesisCategory = "LEGACY_ENDPOINT_BEHAVIOR"
	HypothesisCatCDNOriginDiscrepancy   HypothesisCategory = "CDN_ORIGIN_DISCREPANCY"
	HypothesisCatIntentionalPublic      HypothesisCategory = "INTENTIONAL_PUBLIC_SERVICE"
	HypothesisCatControlRegression      HypothesisCategory = "SECURITY_CONTROL_REGRESSION"
	HypothesisCatStateTransitionAnomaly HypothesisCategory = "STATE_TRANSITION_ANOMALY"
	HypothesisCatCustomResearch         HypothesisCategory = "CUSTOM_RESEARCH"
)

// HypothesisStatus represents the strict state machine of a hypothesis.
// "HYPOTHESIZED" must NEVER be converted to "CONFIRMED".
type HypothesisStatus string

const (
	HypothesisStatusHypothesized  HypothesisStatus = "HYPOTHESIZED"
	HypothesisStatusInvestigating HypothesisStatus = "INVESTIGATING"
	HypothesisStatusSupported     HypothesisStatus = "SUPPORTED"
	HypothesisStatusRejected      HypothesisStatus = "REJECTED"
	HypothesisStatusFalsified     HypothesisStatus = "FALSIFIED"
	HypothesisStatusDismissed     HypothesisStatus = "DISMISSED"
	HypothesisStatusUnknown       HypothesisStatus = "UNKNOWN"
)

// FalsificationResult tracks whether empirical testing has disproven the hypothesis.
type FalsificationResult string

const (
	FalsificationPending       FalsificationResult = "PENDING"
	FalsificationSurvivedTest  FalsificationResult = "SURVIVED_TEST"
	FalsificationFalsified     FalsificationResult = "FALSIFIED"
	FalsificationNotTested     FalsificationResult = "NOT_TESTED"
)

// FalsificationCondition articulates: "What empirical evidence would prove this hypothesis wrong?"
type FalsificationCondition struct {
	ID                   string              `json:"id"`
	HypothesisID         string              `json:"hypothesis_id"`
	ConditionDescription string              `json:"condition_description"`
	RequiredEvidence     string              `json:"required_evidence"`
	ValidationMethod     string              `json:"validation_method"`
	Result               FalsificationResult `json:"result"`
	EvidenceRefs         []string            `json:"evidence_refs,omitempty"`
	EvaluatedAt          *time.Time          `json:"evaluated_at,omitempty"`
}

// RequirementStatus tracks missing intelligence required to substantiate or falsify a hypothesis.
type RequirementStatus string

const (
	ReqStatusMissing       RequirementStatus = "MISSING"
	ReqStatusAvailable     RequirementStatus = "AVAILABLE"
	ReqStatusCollecting    RequirementStatus = "COLLECTING"
	ReqStatusSatisfied     RequirementStatus = "SATISFIED"
	ReqStatusImpossible    RequirementStatus = "IMPOSSIBLE"
	ReqStatusNotApplicable RequirementStatus = "NOT_APPLICABLE"
)

// EvidenceRequirement specifies an unanswered question or missing observation.
type EvidenceRequirement struct {
	ID               string            `json:"id"`
	HypothesisID     string            `json:"hypothesis_id"`
	Description      string            `json:"description"`
	Importance       string            `json:"importance"` // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	EvidenceType     EvidenceType      `json:"evidence_type"`
	CollectionMethod string            `json:"collection_method"`
	Status           RequirementStatus `json:"status"`
	SatisfiedByRef   string            `json:"satisfied_by_ref,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
}

// Hypothesis represents a formal, testable explanation for security signals.
type Hypothesis struct {
	ID                         string                   `json:"id"`
	GroupID                    string                   `json:"group_id"`
	TargetID                   string                   `json:"target_id"`
	AssetID                    string                   `json:"asset_id,omitempty"`
	Endpoint                   string                   `json:"endpoint,omitempty"`
	Title                      string                   `json:"title"`
	Description                string                   `json:"description"`
	Category                   HypothesisCategory       `json:"category"`
	EpistemicStatus            EpistemicStatus          `json:"epistemic_status"` // Starts as "HYPOTHESIZED"
	Status                     HypothesisStatus         `json:"status"`
	ReasoningMethod            string                   `json:"reasoning_method"`
	SupportingSignals          []string                 `json:"supporting_signals"`
	SupportingEvidence         []string                 `json:"supporting_evidence"`
	ContradictingEvidence      []string                 `json:"contradicting_evidence"`
	AlternativeHypotheses      []string                 `json:"alternative_hypotheses,omitempty"`
	MissingEvidence            []EvidenceRequirement    `json:"missing_evidence,omitempty"`
	FalsificationConditions    []FalsificationCondition `json:"falsification_conditions,omitempty"`
	RecommendedInvestigations []string                 `json:"recommended_investigations,omitempty"`
	EvidenceStrength           int                      `json:"evidence_strength"` // 0 to 5
	InvestigationPriority      int                      `json:"investigation_priority"` // 0 to 100
	PriorityBreakdown          map[string]int           `json:"priority_breakdown,omitempty"`
	CreatedAt                  time.Time                `json:"created_at"`
	UpdatedAt                  time.Time                `json:"updated_at"`
}

// HypothesisGroup binds mutually competing hypotheses for the same observed signals.
// Principle: Never produce only one explanation when competing alternatives exist.
type HypothesisGroup struct {
	ID                   string       `json:"id"`
	TargetID             string       `json:"target_id"`
	AssetID              string       `json:"asset_id,omitempty"`
	Subject              string       `json:"subject"` // e.g. "Endpoint /v1/auth/token authorization posture"
	Signals              []string     `json:"signals"`
	HypothesisIDs        []string     `json:"hypothesis_ids"`
	Hypotheses           []Hypothesis `json:"hypotheses,omitempty"`
	ActiveInvestigation  string       `json:"active_investigation,omitempty"`
	HasCompetingTheories bool         `json:"has_competing_theories"`
	CreatedAt            time.Time    `json:"created_at"`
	UpdatedAt            time.Time    `json:"updated_at"`
}

// InvestigationStatus tracks safe, bounded investigation plans.
type InvestigationStatus string

const (
	InvStatusPlanned   InvestigationStatus = "PLANNED"
	InvStatusQueued    InvestigationStatus = "QUEUED"
	InvStatusRunning   InvestigationStatus = "RUNNING"
	InvStatusCompleted InvestigationStatus = "COMPLETED"
	InvStatusFailed    InvestigationStatus = "FAILED"
	InvStatusCancelled InvestigationStatus = "CANCELLED"
)

// InvestigationStep describes an atomic, authorized, non-destructive probe action.
type InvestigationStep struct {
	StepNumber       int       `json:"step_number"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	ActionType       string    `json:"action_type"` // e.g. "CAPTURE_BASELINE", "COMPARE_CONTEXTS", "EVALUATE_SEMANTICS"
	ScopeConstraint  string    `json:"scope_constraint"`
	Status           string    `json:"status"` // "PENDING", "COMPLETED", "FAILED", "SKIPPED"
	ResultEvidenceID string    `json:"result_evidence_id,omitempty"`
	ExecutedAt       *time.Time `json:"executed_at,omitempty"`
}

// Investigation represents an auditable plan to collect differential evidence.
type Investigation struct {
	ID                 string              `json:"id"`
	TargetID           string              `json:"target_id"`
	AssetID            string              `json:"asset_id,omitempty"`
	HypothesisID       string              `json:"hypothesis_id"`
	GroupID            string              `json:"group_id,omitempty"`
	Title              string              `json:"title"`
	Objective          string              `json:"objective"`
	Priority           string              `json:"priority"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	PriorityScore      int                 `json:"priority_score"`
	PriorityFactors    map[string]int      `json:"priority_factors,omitempty"`
	Status             InvestigationStatus `json:"status"`
	Steps              []InvestigationStep `json:"steps"`
	ResultSummary      string              `json:"result_summary,omitempty"`
	GeneratedEvidence  []string            `json:"generated_evidence,omitempty"`
	UpdatedHypothesis  string              `json:"updated_hypothesis,omitempty"`
	CreatedBy          string              `json:"created_by"`
	CreatedAt          time.Time           `json:"created_at"`
	CompletedAt        *time.Time          `json:"completed_at,omitempty"`
}

// TrustBoundaryTier denotes an architectural tier without assuming internal details.
type TrustBoundaryTier string

const (
	TierPublicInternet     TrustBoundaryTier = "PUBLIC_INTERNET"
	TierCDNEffectiveEdge   TrustBoundaryTier = "CDN_EDGE"
	TierReverseProxy       TrustBoundaryTier = "REVERSE_PROXY"
	TierApplicationGateway TrustBoundaryTier = "APPLICATION_GATEWAY"
	TierAuthService        TrustBoundaryTier = "AUTH_SERVICE"
	TierInternalAPI        TrustBoundaryTier = "INTERNAL_API"
	TierDatabaseStorage    TrustBoundaryTier = "DATABASE_STORAGE"
)

// TrustBoundary represents observed or inferred security perimeter transitions.
// Epistemic discipline: never claim internal knowledge unless direct evidence proves it.
type TrustBoundary struct {
	ID              string            `json:"id"`
	TargetID        string            `json:"target_id"`
	AssetID         string            `json:"asset_id,omitempty"`
	BoundaryName    string            `json:"boundary_name"`
	FromTier        TrustBoundaryTier `json:"from_tier"`
	ToTier          TrustBoundaryTier `json:"to_tier"`
	EpistemicStatus EpistemicStatus   `json:"epistemic_status"` // "OBSERVED", "INFERRED", "HYPOTHESIZED", "UNKNOWN"
	EvidenceRefs    []string          `json:"evidence_refs"`
	Notes           string            `json:"notes,omitempty"`
	CreatedAt       time.Time         `json:"created_at"`
}

// AuthContext represents a researcher-provided, authorized identity session context.
// NexusHunter never automatically invents privileged accounts.
type AuthContext struct {
	ID                 string            `json:"id"`
	TargetID           string            `json:"target_id"`
	Name               string            `json:"name"` // e.g. "Anonymous", "Role A - Auditor", "Role B - Viewer"
	AuthorizationBasis string            `json:"authorization_basis"` // e.g. "Test Account #12 granted by Security Team"
	ScopeConstraint    string            `json:"scope_constraint"`
	Headers            map[string]string `json:"headers,omitempty"` // Sanitized headers
	IsActive           bool              `json:"is_active"`
	CreatedAt          time.Time         `json:"created_at"`
}

// PermissionState models access decisions strictly grounded in verified evidence.
type PermissionState string

const (
	PermissionAllow         PermissionState = "ALLOW"
	PermissionDeny          PermissionState = "DENY"
	PermissionUnknown       PermissionState = "UNKNOWN"
	PermissionNotTested     PermissionState = "NOT_TESTED"
	PermissionNotApplicable PermissionState = "NOT_APPLICABLE"
)

// PermissionMatrixEntry maps an authorized context to an endpoint with evidence.
type PermissionMatrixEntry struct {
	ID            string          `json:"id"`
	TargetID      string          `json:"target_id"`
	AssetID       string          `json:"asset_id,omitempty"`
	Endpoint      string          `json:"endpoint"`
	ContextID     string          `json:"context_id"`
	ContextName   string          `json:"context_name"`
	State         PermissionState `json:"state"`
	StatusCode    int             `json:"status_code,omitempty"`
	EvidenceRefs  []string        `json:"evidence_refs"`
	ObservedAt    time.Time       `json:"observed_at"`
}

// SecurityControlRecord represents the evaluated posture of standard controls.
type SecurityControlRecord struct {
	ID            string                    `json:"id"`
	TargetID      string                    `json:"target_id"`
	AssetID       string                    `json:"asset_id,omitempty"`
	Endpoint      string                    `json:"endpoint,omitempty"`
	ControlName   string                    `json:"control_name"`
	ExpectedState EpistemicObservationState `json:"expected_state"`
	ObservedState EpistemicObservationState `json:"observed_state"`
	IsContradicted bool                     `json:"is_contradicted"`
	EvidenceRefs  []string                  `json:"evidence_refs"`
	Confidence    float64                   `json:"confidence"`
	EvaluatedAt   time.Time                 `json:"evaluated_at"`
}

// ReasoningProvenance stores cryptographic reproducibility and audit data for reasoning objects.
type ReasoningProvenance struct {
	ReasoningID     string    `json:"reasoning_id"`
	Engine          string    `json:"engine"`
	EngineVersion   string    `json:"engine_version"`
	Algorithm       string    `json:"algorithm"`
	InputIDs        []string  `json:"input_ids"`
	EvidenceIDs     []string  `json:"evidence_ids"`
	Configuration   string    `json:"configuration_hash"`
	CreatedAt       time.Time `json:"created_at"`
}

// ReasoningRun logs structured telemetry of each reasoning batch execution.
type ReasoningRun struct {
	ID            string    `json:"id"`
	TargetID      string    `json:"target_id"`
	AssetID       string    `json:"asset_id,omitempty"`
	Engine        string    `json:"engine"`
	EngineVersion string    `json:"engine_version"`
	InputCount    int       `json:"input_count"`
	SignalsCount  int       `json:"signals_count"`
	HypothesesCount int     `json:"hypotheses_count"`
	DurationMs    int64     `json:"duration_ms"`
	Status        string    `json:"status"` // "SUCCESS", "PARTIAL", "FAILED"
	ErrorMessage  string    `json:"error_message,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}
