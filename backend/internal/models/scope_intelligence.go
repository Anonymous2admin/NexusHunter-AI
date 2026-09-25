package models

import "time"

// ScopeNormalization captures an exact transformation applied during scope import.
type ScopeNormalization struct {
	Original   string `json:"original"`
	Normalized string `json:"normalized"`
	Field      string `json:"field"`
	Reason     string `json:"reason"`
	Severity   string `json:"severity"` // "INFO", "WARNING", "CRITICAL"
}

// ScopeSource records where a scope rule or definition originated.
type ScopeSource struct {
	FileName  string `json:"file_name"`
	Format    string `json:"format"` // "BURP_SUITE", "ADVANCED_SCOPE", "HACKERONE", "BUGCROWD", "RAW_LIST"
	RuleCount int    `json:"rule_count"`
}

// PathRule defines a specific URI path boundary.
type PathRule struct {
	Path       string `json:"path"`
	MatchExact bool   `json:"match_exact"`
	Excluded   bool   `json:"excluded"`
}

// CanonicalScope is the unified internal representation of authorized research boundaries.
type CanonicalScope struct {
	PrimaryRootDomain string               `json:"primary_root_domain"`
	RootDomains       []string             `json:"root_domains"`
	IncludeHosts      []AdvancedScopeRule  `json:"include_hosts"`
	ExcludeHosts      []AdvancedScopeRule  `json:"exclude_hosts"`
	IncludeURLs       []AdvancedScopeRule  `json:"include_urls"`
	ExcludeURLs       []AdvancedScopeRule  `json:"exclude_urls"`
	PathRules         []PathRule           `json:"path_rules"`
	SourceFiles       []ScopeSource        `json:"source_files"`
	Normalizations    []ScopeNormalization `json:"normalizations"`
}

// RootDomainCandidate represents an extracted root domain awaiting human confirmation.
type RootDomainCandidate struct {
	ID               string `json:"id"`
	NormalizedDomain string `json:"normalized_domain"`
	SourceFile       string `json:"source_file"`
	SourcePath       string `json:"source_path"`
	SourceRuleID     string `json:"source_rule_id,omitempty"`
	Evidence         string `json:"evidence"`
	Confidence       string `json:"confidence"` // "HIGH", "MEDIUM", "LOW"
	Status           string `json:"status"`     // "DISCOVERED", "SELECTED", "REJECTED", "AMBIGUOUS"
}

// ScopeImportReview presents the pre-creation summary and verification details.
type ScopeImportReview struct {
	ID                 string                 `json:"id"`
	FileName           string                 `json:"file_name"`
	Status             string                 `json:"status"` // "PENDING_CONFIRMATION", "CONFIRMED", "REJECTED"
	RootDomains        []RootDomainCandidate  `json:"root_domains"`
	SelectedRootDomain string                 `json:"selected_root_domain"`
	RulesDiscovered    int                    `json:"rules_discovered"`
	IncludeHostsCount  int                    `json:"include_hosts_count"`
	ExcludeHostsCount  int                    `json:"exclude_hosts_count"`
	RegexRulesCount    int                    `json:"regex_rules_count"`
	PathRulesCount     int                    `json:"path_rules_count"`
	WarningsCount      int                    `json:"warnings_count"`
	AmbiguousCount     int                    `json:"ambiguous_count"`
	Normalizations               []ScopeNormalization   `json:"normalizations"`
	CanonicalScope               *CanonicalScope        `json:"canonical_scope"`
	OriginalFileSHA256           string                 `json:"original_file_sha256"`
	CanonicalScopeSHA256         string                 `json:"canonical_scope_sha256"`
	NormalizationManifestSHA256  string                 `json:"normalization_manifest_sha256"`
	SelectionReason              string                 `json:"selection_reason,omitempty"`
	TargetID                     string                 `json:"target_id,omitempty"`
	ConfirmedBy                  string                 `json:"confirmed_by,omitempty"`
	CreatedAt                    time.Time              `json:"created_at"`
	ConfirmedAt                  *time.Time             `json:"confirmed_at,omitempty"`
}

// JSAsset records a discovered JavaScript file and its fetch/provenance metadata.
type JSAsset struct {
	ID            string    `json:"id"`
	TargetID      string    `json:"target_id"`
	AssetID       string    `json:"asset_id"`
	URL           string    `json:"url"`
	ParentURL     string    `json:"parent_url"`
	DiscoveredAt  time.Time `json:"discovered_at"`
	ScopeDecision struct {
		InScope bool   `json:"in_scope"`
		Reason  string `json:"reason"`
	} `json:"scope_decision"`
	ContentSHA256 string    `json:"content_sha256"`
	ByteSize      int64     `json:"byte_size"`
	IsThirdParty  bool      `json:"is_third_party"`
	FetchStatus   string    `json:"fetch_status"` // "FETCHED", "SKIPPED_OUT_OF_SCOPE", "FAILED", "SIZE_EXCEEDED"
	LineCount     int       `json:"line_count"`
	CreatedAt     time.Time `json:"created_at"`
}

// JSReference stores an extracted structural observation from a JavaScript asset.
type JSReference struct {
	ID              string    `json:"id"`
	TargetID        string    `json:"target_id"`
	AssetID         string    `json:"asset_id"`
	JSAssetID       string    `json:"js_asset_id"`
	SourceURL       string    `json:"source_url"`
	Category        string    `json:"category"` // "API_ROUTE", "URL", "CLOUD_REFERENCE", "TECH_REFERENCE", "CONFIG_REFERENCE", "SECRET_INDICATOR"
	ExtractedValue  string    `json:"extracted_value"`
	NormalizedValue string    `json:"normalized_value"`
	LineNumber      int       `json:"line_number,omitempty"`
	ByteOffset      int64     `json:"byte_offset,omitempty"`
	SourceFragment  string    `json:"source_fragment,omitempty"`
	ScopeStatus     string    `json:"scope_status"` // "IN_SCOPE", "OUT_OF_SCOPE", "UNKNOWN"
	Confidence      string    `json:"confidence"`   // "HIGH", "MEDIUM", "LOW"
	EvidenceID      string    `json:"evidence_id,omitempty"`
	ProvenanceSHA   string    `json:"provenance_sha"`
	CreatedAt       time.Time `json:"created_at"`
}

// JSSecretIndicator stores redacted, hash-verified secret-like structures. Raw secrets are NEVER stored.
type JSSecretIndicator struct {
	ID            string    `json:"id"`
	TargetID      string    `json:"target_id"`
	AssetID       string    `json:"asset_id"`
	JSAssetID     string    `json:"js_asset_id"`
	SecretType    string    `json:"secret_type"`    // "AWS_KEY", "JWT_TOKEN", "GENERIC_API_KEY", "PRIVATE_KEY"
	Location      string    `json:"location"`       // "line 42, col 12"
	MaskedPreview string    `json:"masked_preview"` // "AKIA************7X2"
	SHA256        string    `json:"sha256"`         // Hash of raw secret for correlation only
	Confidence    string    `json:"confidence"`     // "HIGH", "MEDIUM", "LOW"
	SourceJSAsset string    `json:"source_js_asset"`
	EvidenceID    string    `json:"evidence_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// CloudReference records observed cloud infrastructure references.
type CloudReference struct {
	ID               string    `json:"id"`
	TargetID         string    `json:"target_id"`
	AssetID          string    `json:"asset_id,omitempty"`
	Provider         string    `json:"provider"`      // "AWS", "AZURE", "GCP", "CLOUDFLARE", "DIGITALOCEAN", "OTHER"
	ResourceType     string    `json:"resource_type"`  // "S3_BUCKET", "BLOB_CONTAINER", "GCS_BUCKET", "CLOUDFRONT", "UNKNOWN"
	RawReference     string    `json:"raw_reference"`
	NormalizedTarget string    `json:"normalized_target"`
	SourceOrigin     string    `json:"source_origin"` // "HTTP_RESPONSE", "JS_ASSET", "DNS_RECORD", "TLS_SAN", "SCOPE_FILE"
	SourceLocation   string    `json:"source_location"`
	ScopeStatus      string    `json:"scope_status"`      // "IN_SCOPE", "OUT_OF_SCOPE", "UNKNOWN"
	ValidationStatus string    `json:"validation_status"` // "UNCHECKED", "SAFE_PROBED", "VERIFIED_PUBLIC", "VERIFIED_PRIVATE", "UNAUTHORIZED"
	StatusCode       int       `json:"status_code,omitempty"`
	PublicAccessible bool      `json:"public_accessible"`
	EvidenceID       string    `json:"evidence_id,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// WAFObservation records detected WAF provider signatures and adaptive throttling health.
type WAFObservation struct {
	ID                  string    `json:"id"`
	TargetID            string    `json:"target_id"`
	AssetID             string    `json:"asset_id,omitempty"`
	Provider            string    `json:"provider"` // "Cloudflare", "AWS WAF", "Akamai", "Fastly", "Imperva", "ModSecurity", "Generic WAF", "None Detected"
	Confidence          string    `json:"confidence"` // "HIGH", "MEDIUM", "LOW"
	EvidenceIDs         []string  `json:"evidence_ids"`
	MatchedIndicators   []string  `json:"matched_indicators"`
	ObservedHeaders     []string  `json:"observed_headers"`
	ThrottlingState     string    `json:"throttling_state"` // "NORMAL", "RATE_LIMITED", "REPEATED_429", "SUSTAINED_BLOCK", "PAUSED"
	CurrentRateLimitRPS float64   `json:"current_rate_limit_rps"`
	RetryAfterSeconds   int       `json:"retry_after_seconds,omitempty"`
	CircuitBreakerOpen  bool      `json:"circuit_breaker_open"`
	ThrottleReason      string    `json:"throttle_reason,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// WhyInteresting articulates the exact epistemic rationale without jumping to conclusions.
type WhyInteresting struct {
	ObservedFacts   []string `json:"observed_facts"`
	Deduction       string   `json:"deduction"`
	MissingEvidence []string `json:"missing_evidence"`
}

// InvestigationPlanStep defines an atomic, safe, non-destructive step requiring human authorization.
type InvestigationPlanStep struct {
	StepNumber        int        `json:"step_number"`
	ActionType        string     `json:"action_type"` // Must belong to AllowedActionTypes
	Description       string     `json:"description"`
	TargetURL         string     `json:"target_url"`
	Status            string     `json:"status"` // "PENDING", "APPROVED", "EXECUTED", "BLOCKED", "SKIPPED"
	ApprovedByHuman   bool       `json:"approved_by_human"`
	ApprovedAt        *time.Time `json:"approved_at,omitempty"`
	ResultEvidenceID  string     `json:"result_evidence_id,omitempty"`
	ResultObservation string     `json:"result_observation,omitempty"`
}

// InvestigationPlan represents an AI-generated, human-guided structured research checklist.
type InvestigationPlan struct {
	ID                     string                  `json:"id"`
	TargetID               string                  `json:"target_id"`
	AssetID                string                  `json:"asset_id,omitempty"`
	HypothesisID           string                  `json:"hypothesis_id,omitempty"`
	Title                  string                  `json:"title"`
	Reason                 string                  `json:"reason"`
	Hypothesis             string                  `json:"hypothesis"`
	WhyInteresting         WhyInteresting          `json:"why_interesting"`
	RequiredEvidence       []string                `json:"required_evidence"`
	EvidenceRequiredCount  int                     `json:"evidence_required_count"`
	EvidenceSatisfiedCount int                     `json:"evidence_satisfied_count"`
	SafeValidation         string                  `json:"safe_validation"`
	ExpectedObservation    string                  `json:"expected_observation"`
	AlternativeExplanation string                  `json:"alternative_explanation"`
	StopCondition          string                  `json:"stop_condition"`
	ScopeRequirements      []string                `json:"scope_requirements"`
	Risk                   string                  `json:"risk"`       // "LOW", "MEDIUM", "HIGH"
	Confidence             string                  `json:"confidence"` // "HIGH", "MEDIUM", "LOW"
	EpistemicStatus        string                  `json:"epistemic_status"` // "OBSERVED", "DERIVED", "INFERRED", "HYPOTHESIZED", "VALIDATING", "SUPPORTED", "REJECTED", "DISMISSED"
	Status                 string                  `json:"status"`     // "PLANNED", "APPROVED", "RUNNING", "COMPLETED", "DISMISSED"
	SourceEvidenceIDs      []string                `json:"source_evidence_ids"`
	Steps                  []InvestigationPlanStep `json:"steps"`
	CreatedAt              time.Time               `json:"created_at"`
	UpdatedAt              time.Time               `json:"updated_at"`
}
