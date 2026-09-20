package models

import (
	"time"
)

// EvidenceType defines the controlled enum/type system for first-class evidence.
type EvidenceType string

const (
	EvidenceHTTPRequest           EvidenceType = "HTTP_REQUEST"
	EvidenceHTTPResponse          EvidenceType = "HTTP_RESPONSE"
	EvidenceHeaderObservation     EvidenceType = "HEADER_OBSERVATION"
	EvidenceDNSObservation        EvidenceType = "DNS_OBSERVATION"
	EvidenceTLSObservation        EvidenceType = "TLS_OBSERVATION"
	EvidenceRedirectChain         EvidenceType = "REDIRECT_CHAIN"
	EvidenceTechnologyObservation  EvidenceType = "TECHNOLOGY_OBSERVATION"
	EvidenceAuthObservation       EvidenceType = "AUTHORIZATION_OBSERVATION"
	EvidenceStateTransition       EvidenceType = "STATE_TRANSITION"
	EvidenceDifferentialResult    EvidenceType = "DIFFERENTIAL_RESULT"
	EvidenceValidationResult      EvidenceType = "VALIDATION_RESULT"
	EvidenceScreenshotReference   EvidenceType = "SCREENSHOT_REFERENCE"
	EvidenceTypeTimelineEvent     EvidenceType = "TIMELINE_EVENT"
	EvidenceGraphRelationship     EvidenceType = "GRAPH_RELATIONSHIP"
)

// EvidenceSource specifies the exact operational subsystem producing the evidence.
type EvidenceSource string

const (
	SourceReconHTTP            EvidenceSource = "RECON_HTTP"
	SourceReconCrawler         EvidenceSource = "RECON_CRAWLER"
	SourceControlledValidation EvidenceSource = "CONTROLLED_VALIDATION"
	SourceDifferentialEngine   EvidenceSource = "DIFFERENTIAL_ENGINE"
	SourceTemporalDiff         EvidenceSource = "TEMPORAL_DIFF"
	SourceManualProbe          EvidenceSource = "MANUAL_PROBE"
	SourceSecurityObservation  EvidenceSource = "SECURITY_OBSERVATION"
)

// EvidenceProvenance explicitly tracks the origin, operation, and authorization of the evidence.
type EvidenceProvenance struct {
	Source      EvidenceSource `json:"source"`
	OperationID string         `json:"operation_id"`
	TargetID    string         `json:"target_id"`
	AssetID     string         `json:"asset_id,omitempty"`
	CapturedAt  time.Time      `json:"captured_at"`
	Initiator   string         `json:"initiator"` // e.g. "recon_engine", "controlled_validator", "researcher"
	Notes       string         `json:"notes,omitempty"`
}

// ScopeDecisionRecord captures the verifiable scope authorization decision for this evidence.
type ScopeDecisionRecord struct {
	IsInScope     bool      `json:"is_in_scope"`
	TargetID      string    `json:"target_id"`
	EvaluatedHost string    `json:"evaluated_host"`
	EvaluatedURL  string    `json:"evaluated_url,omitempty"`
	RuleMatched   string    `json:"rule_matched"`
	Reason        string    `json:"reason"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
}

// RedactionStatusRecord tracks which sensitive keys or secrets were redacted before hashing and storage.
type RedactionStatusRecord struct {
	IsRedacted     bool      `json:"is_redacted"`
	RedactedFields []string  `json:"redacted_fields"`
	SanitizedAt    time.Time `json:"sanitized_at"`
}

// HTTPRequestContext records the outbound HTTP request context.
type HTTPRequestContext struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Headers         map[string]string `json:"headers"`
	BodySummary     string            `json:"body_summary,omitempty"`
	BodyLength      int               `json:"body_length"`
	IsAuthenticated bool              `json:"is_authenticated"`
	AuthContextRole string            `json:"auth_context_role,omitempty"`
}

// HTTPResponseContext records the observed HTTP response.
type HTTPResponseContext struct {
	StatusCode     int               `json:"status_code"`
	Headers        map[string]string `json:"headers"`
	BodySnippet    string            `json:"body_snippet,omitempty"`
	BodyLength     int               `json:"body_length"`
	BodyHash       string            `json:"body_hash"`
	ContentType    string            `json:"content_type"`
	ResponseTimeMs int64             `json:"response_time_ms"`
}

// DNSContext records DNS resolution evidence.
type DNSContext struct {
	Hostname    string   `json:"hostname"`
	IPAddresses []string `json:"ip_addresses"`
	CNAMEs      []string `json:"cnames,omitempty"`
	TTL         int      `json:"ttl,omitempty"`
}

// TLSMetadataContext records cryptographic TLS context.
type TLSMetadataContext struct {
	Version            string    `json:"version"`
	CipherSuite        string    `json:"cipher_suite"`
	Issuer             string    `json:"issuer"`
	Subject            string    `json:"subject"`
	SANs               []string  `json:"sans,omitempty"`
	ValidUntil         time.Time `json:"valid_until"`
	MutualTLSRequired  bool      `json:"mutual_tls_required"`
}

// Evidence represents a first-class structured evidence record with provenance and integrity hash.
type Evidence struct {
	ID                      string                 `json:"id"`
	TargetID                string                 `json:"target_id"`
	AssetID                 string                 `json:"asset_id,omitempty"`
	ObservationID           string                 `json:"observation_id,omitempty"`
	CandidateID             string                 `json:"candidate_id,omitempty"`
	Source                  EvidenceSource         `json:"source"`
	EvidenceType            EvidenceType           `json:"evidence_type"`
	Summary                 string                 `json:"summary"`
	CapturedAt              time.Time              `json:"captured_at"`
	StatusCode              int                    `json:"status_code,omitempty"`
	Request                 *HTTPRequestContext    `json:"request,omitempty"`
	Response                *HTTPResponseContext   `json:"response,omitempty"`
	RelevantHeaders         map[string]string      `json:"relevant_headers,omitempty"`
	RedirectChain           []string               `json:"redirect_chain,omitempty"`
	DNSContext              *DNSContext            `json:"dns_context,omitempty"`
	TLSMetadata             *TLSMetadataContext    `json:"tls_metadata,omitempty"`
	ValidationContext       map[string]interface{} `json:"validation_context,omitempty"`
	ScopeDecision           ScopeDecisionRecord    `json:"scope_decision"`
	RedactionStatus         RedactionStatusRecord  `json:"redaction_status"`
	CanonicalRepresentation string                 `json:"canonical_representation,omitempty"`
	SHA256                  string                 `json:"sha256"` // Integrity hash over canonical representation
	Provenance              EvidenceProvenance     `json:"provenance"`
	Metadata                map[string]interface{} `json:"metadata,omitempty"`
}

// DifferentialRequest specifies the two evidence items or observations to compare.
type DifferentialRequest struct {
	TargetID     string `json:"target_id"`
	EvidenceAID  string `json:"evidence_a_id"`
	EvidenceBID  string `json:"evidence_b_id"`
	FilterNoise  bool   `json:"filter_noise"`
}

// Level1RawDiff represents technical/syntactic differences.
type Level1RawDiff struct {
	StatusFrom        int               `json:"status_from"`
	StatusTo          int               `json:"status_to"`
	StatusChanged     bool              `json:"status_changed"`
	BodyLengthDelta   int               `json:"body_length_delta"`
	BodyHashA         string            `json:"body_hash_a"`
	BodyHashB         string            `json:"body_hash_b"`
	BodyHashChanged   bool              `json:"body_hash_changed"`
	AddedHeaders      map[string]string `json:"added_headers,omitempty"`
	RemovedHeaders    map[string]string `json:"removed_headers,omitempty"`
	ModifiedHeaders   map[string]string `json:"modified_headers,omitempty"`
	ResponseTimeDelta int64             `json:"response_time_delta_ms"`
}

// Level2SemanticDiff represents meaningful behavioral/protocol differences.
type Level2SemanticDiff struct {
	Category              string `json:"category"` // e.g. "AUTHORIZATION_RESPONSE", "CONTENT_TYPE", "ERROR_STRUCTURE"
	Meaning               string `json:"meaning"`
	AuthBehaviorChanged   bool   `json:"auth_behavior_changed"`
	ContentTypeChanged    bool   `json:"content_type_changed"`
	RedirectChanged       bool   `json:"redirect_changed"`
	ErrorPayloadDetected  bool   `json:"error_payload_detected"`
	StateTransitionDetected bool `json:"state_transition_detected"`
}

// Level3SecurityDiff represents why a security researcher should care, without asserting a vulnerability.
type Level3SecurityDiff struct {
	ObservationContext   string   `json:"observation_context"`
	RelevanceExplanation string   `json:"relevance_explanation"`
	RequiresFollowup     bool     `json:"requires_followup"`
	SuggestedQuestions   []string `json:"suggested_questions"`
}

// EvidenceDiff captures the three-level difference model between two observations.
type EvidenceDiff struct {
	ID                 string             `json:"id"`
	TargetID           string             `json:"target_id"`
	AssetID            string             `json:"asset_id,omitempty"`
	EvidenceAID        string             `json:"evidence_a_id"`
	EvidenceBID        string             `json:"evidence_b_id"`
	RawDiff            Level1RawDiff      `json:"raw_diff"`
	SemanticDiff       Level2SemanticDiff `json:"semantic_diff"`
	SecurityDiff       Level3SecurityDiff `json:"security_diff"`
	IsNoiseFiltered    bool               `json:"is_noise_filtered"`
	IsSecurityRelevant bool               `json:"is_security_relevant"`
	ComputedAt         time.Time          `json:"computed_at"`
}

// EpistemicObservationState defines strict observation classifications.
// "NOT_OBSERVED" is strictly distinguished from "ABSENT".
type EpistemicObservationState string

const (
	StatePresent       EpistemicObservationState = "PRESENT"
	StateAbsent        EpistemicObservationState = "ABSENT"
	StateNotObserved   EpistemicObservationState = "NOT_OBSERVED"
	StateUnknown       EpistemicObservationState = "UNKNOWN"
	StateNotApplicable EpistemicObservationState = "NOT_APPLICABLE"
)

// ExpectedModelSource indicates the authority for the security expectation.
type ExpectedModelSource string

const (
	SourceExplicitPolicy     ExpectedModelSource = "EXPLICIT_POLICY"
	SourcePeerBaseline       ExpectedModelSource = "PEER_BASELINE"
	SourceHistoricalBaseline ExpectedModelSource = "HISTORICAL_BASELINE"
)

// SecurityExpectation represents the expected security model for an asset or endpoint.
type SecurityExpectation struct {
	ID            string                    `json:"id"`
	TargetID      string                    `json:"target_id"`
	AssetID       string                    `json:"asset_id,omitempty"`
	Endpoint      string                    `json:"endpoint,omitempty"`
	ControlName   string                    `json:"control_name"` // e.g. "AUTH_REQUIRED", "MFA_ENFORCED", "HSTS_ENABLED"
	Source        ExpectedModelSource       `json:"source"`
	ExpectedState EpistemicObservationState `json:"expected_state"`
	Description   string                    `json:"description"`
	RuleDetails   map[string]interface{}    `json:"rule_details,omitempty"`
	CreatedAt     time.Time                 `json:"created_at"`
}

// ContradictionType categorizes structural contradictions.
type ContradictionType string

const (
	ContradictionAuthentication   ContradictionType = "AUTHENTICATION_CONTRADICTION"
	ContradictionAuthorization    ContradictionType = "AUTHORIZATION_CONTRADICTION"
	ContradictionSecurityControl  ContradictionType = "SECURITY_CONTROL_CONTRADICTION"
	ContradictionProtocol         ContradictionType = "PROTOCOL_CONTRADICTION"
	ContradictionConfiguration    ContradictionType = "CONFIGURATION_CONTRADICTION"
	ContradictionTrustBoundary    ContradictionType = "TRUST_BOUNDARY_CONTRADICTION"
	ContradictionTemporal         ContradictionType = "TEMPORAL_CONTRADICTION"
	ContradictionBehavioral       ContradictionType = "BEHAVIORAL_CONTRADICTION"
	ContradictionBusinessRule     ContradictionType = "BUSINESS_RULE_CONTRADICTION"
)

// ContradictionStatus tracks the investigation state of a contradiction.
// Crucial principle: A contradiction is NEVER automatically labeled a VULNERABILITY.
type ContradictionStatus string

const (
	ContradictionUnverified          ContradictionStatus = "UNVERIFIED"
	ContradictionInvestigating       ContradictionStatus = "INVESTIGATING"
	ContradictionConfirmedDeviation  ContradictionStatus = "CONFIRMED_DEVIATION"
	ContradictionRejected            ContradictionStatus = "REJECTED"
	ContradictionDismissed           ContradictionStatus = "DISMISSED"
)

// SecurityContradiction represents an identified contradiction between the Expected and Observed models.
type SecurityContradiction struct {
	ID                string                    `json:"id"`
	TargetID          string                    `json:"target_id"`
	AssetID           string                    `json:"asset_id,omitempty"`
	Endpoint          string                    `json:"endpoint,omitempty"`
	ContradictionType ContradictionType         `json:"contradiction_type"`
	Status            ContradictionStatus       `json:"status"`
	Severity          string                    `json:"severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Title             string                    `json:"title"`
	Description       string                    `json:"description"`
	ExpectationID     string                    `json:"expectation_id,omitempty"`
	ObservedState     EpistemicObservationState `json:"observed_state"`
	EvidenceRefs      []string                  `json:"evidence_refs"`
	Explanation       string                    `json:"explanation"`
	SuggestedFollowup []string                  `json:"suggested_followup"`
	CreatedAt         time.Time                 `json:"created_at"`
	UpdatedAt         time.Time                 `json:"updated_at"`
}

// SecurityOutlier records a statistical or structural outlier relative to a peer comparison group.
type SecurityOutlier struct {
	ID              string                 `json:"id"`
	TargetID        string                 `json:"target_id"`
	AssetID         string                 `json:"asset_id,omitempty"`
	Endpoint        string                 `json:"endpoint,omitempty"`
	ComparisonGroup string                 `json:"comparison_group"` // e.g. "PEER_API_ENDPOINTS", "SUBDOMAIN_AUTH_PATTERNS"
	ObservedValue   string                 `json:"observed_value"`
	BaselineValue   string                 `json:"baseline_value"`
	DeviationType   string                 `json:"deviation_type"`
	EvidenceRefs    []string               `json:"evidence_refs"`
	Confidence      float64                `json:"confidence"`
	Details         map[string]interface{} `json:"details,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
}

// EpistemicStatus qualifies the epistemological confidence of an intelligence node or graph relationship.
type EpistemicStatus string

const (
	EpistemicObserved     EpistemicStatus = "OBSERVED"
	EpistemicDerived      EpistemicStatus = "DERIVED"
	EpistemicInferred     EpistemicStatus = "INFERRED"
	EpistemicHypothesized EpistemicStatus = "HYPOTHESIZED"
	EpistemicValidating   EpistemicStatus = "VALIDATING"
	EpistemicSupported    EpistemicStatus = "SUPPORTED"
	EpistemicRejected     EpistemicStatus = "REJECTED"
	EpistemicDismissed    EpistemicStatus = "DISMISSED"
	EpistemicUnknown      EpistemicStatus = "UNKNOWN"
)

// InterestReason describes one deterministic, evidence-backed factor making an asset interesting.
type InterestReason struct {
	FactorName    string   `json:"factor_name"` // e.g. "NEW_ASSET", "AUTH_DEVIATION", "CONTRADICTION_IDENTIFIED"
	Description   string   `json:"description"`
	EvidenceRefs  []string `json:"evidence_refs"`
	Weight        int      `json:"weight"`
}

// AssetInterestSummary exposes the deterministic "Why is this interesting?" synthesis for researchers.
type AssetInterestSummary struct {
	AssetID          string           `json:"asset_id"`
	Hostname         string           `json:"hostname"`
	TargetID         string           `json:"target_id"`
	Score            int              `json:"score"`
	Reasons          []InterestReason `json:"reasons"`
	LinkedEvidenceIDs []string        `json:"linked_evidence_ids"`
	EvaluatedAt      time.Time        `json:"evaluated_at"`
}

// EvidenceTimelineEvent represents a unified chronological event in the investigation lifecycle.
type EvidenceTimelineEvent struct {
	ID              string                 `json:"id"`
	TargetID        string                 `json:"target_id"`
	AssetID         string                 `json:"asset_id,omitempty"`
	EventType       string                 `json:"event_type"` // "RECON_OBSERVATION", "EVIDENCE_COLLECTED", "DIFF_COMPUTED", "CONTRADICTION_FLAGGED", "OUTLIER_FLAGGED", "VALIDATION_PERFORMED"
	Summary         string                 `json:"summary"`
	EpistemicStatus EpistemicStatus        `json:"epistemic_status"`
	Timestamp       time.Time              `json:"timestamp"`
	Provenance      EvidenceProvenance     `json:"provenance"`
	ReferenceID     string                 `json:"reference_id,omitempty"`
	Details         map[string]interface{} `json:"details,omitempty"`
}

// EvidenceIntegrityResult reports whether a stored evidence record has been tampered with.
type EvidenceIntegrityResult struct {
	EvidenceID       string    `json:"evidence_id"`
	OriginalSHA256   string    `json:"original_sha256"`
	ComputedSHA256   string    `json:"computed_sha256"`
	IsTampered       bool      `json:"is_tampered"`
	VerifiedAt       time.Time `json:"verified_at"`
	CanonicalMatches bool      `json:"canonical_matches"`
}

