package models

import (
	"time"
)

// TargetStatus represents the operational status of a security testing target.
type TargetStatus string

const (
	TargetStatusActive   TargetStatus = "ACTIVE"
	TargetStatusInactive TargetStatus = "INACTIVE"
	TargetStatusArchived TargetStatus = "ARCHIVED"
)

// JobStatus represents the state of a scan job in the lifecycle.
type JobStatus string

const (
	JobStatusQueued    JobStatus = "QUEUED"
	JobStatusRunning   JobStatus = "RUNNING"
	JobStatusCompleted JobStatus = "COMPLETED"
	JobStatusFailed    JobStatus = "FAILED"
	JobStatusCancelled JobStatus = "CANCELLED"
)

// Target defines an authorized security research target with explicit boundaries.
type Target struct {
	ID                 string               `json:"id"`
	Name               string               `json:"name"`
	RootDomain         string               `json:"root_domain"`
	AllowedDomains     []string             `json:"allowed_domains"`
	AllowedURLPatterns []string             `json:"allowed_url_patterns"`
	ExcludedPatterns   []string             `json:"excluded_patterns"`
	ScopeConfig           *AdvancedScopeConfig `json:"scope_config,omitempty"`
	RawScopeJSON          string               `json:"raw_scope_json,omitempty"`
	ScopeImportID         string               `json:"scope_import_id,omitempty"`
	CanonicalScopeHash    string               `json:"canonical_scope_hash,omitempty"`
	ConfirmationTimestamp *time.Time           `json:"confirmation_timestamp,omitempty"`
	Status                TargetStatus         `json:"status"`
	CreatedAt          time.Time            `json:"created_at"`
	UpdatedAt          time.Time            `json:"updated_at"`
}

// AdvancedScopeRule defines fine-grained regex matching matching Burp Suite and Bug Bounty schemas.
type AdvancedScopeRule struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`               // host regex, e.g. "^.*\\.arc\\.io$"
	Port     string `json:"port,omitempty"`     // port regex, e.g. "^443$", "^.*$"
	Protocol string `json:"protocol,omitempty"` // "any", "http", "https", or regex
	File     string `json:"file,omitempty"`     // path regex, e.g. "^/.*$"
}

// AdvancedScopeConfig holds Burp Suite style include/exclude scope configuration.
type AdvancedScopeConfig struct {
	AdvancedMode bool                `json:"advanced_mode"`
	Include      []AdvancedScopeRule `json:"include"`
	Exclude      []AdvancedScopeRule `json:"exclude"`
}

// TargetScopeRule represents a discrete scope rule associated with a target.
type TargetScopeRule struct {
	ID        string    `json:"id"`
	TargetID  string    `json:"target_id"`
	RuleType  string    `json:"rule_type"` // e.g. "DOMAIN", "URL_PATTERN", "EXCLUSION"
	Pattern   string    `json:"pattern"`
	CreatedAt time.Time `json:"created_at"`
}

// ScanJob represents an execution unit attributable to a configured target and scope.
type ScanJob struct {
	ID          string                 `json:"id"`
	TargetID    string                 `json:"target_id"`
	Type        string                 `json:"type"`
	Status      JobStatus              `json:"status"`
	CreatedAt   time.Time              `json:"created_at"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Event represents an internal system event for telemetry and real-time distribution.
type Event struct {
	EventID   string                 `json:"event_id"`
	EventType string                 `json:"event_type"`
	JobID     string                 `json:"job_id,omitempty"`
	TargetID  string                 `json:"target_id,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Payload   map[string]interface{} `json:"payload,omitempty"`
}

// Standard Event Type constants
const (
	EventJobCreated          = "job.created"
	EventJobStarted          = "job.started"
	EventJobCompleted        = "job.completed"
	EventJobFailed           = "job.failed"
	EventJobCancelled        = "job.cancelled"
	EventAssetDiscovered     = "asset.discovered"
	EventFindingCreated      = "finding.created"
	EventReconStarted        = "recon.started"
	EventSubdomainDiscovered = "subdomain.discovered"
	EventDNSResolved         = "dns.resolved"
	EventHTTPProbed          = "http.probed"
	EventURLDiscovered       = "url.discovered"
	EventAssetCreated        = "asset.created"
	EventReconProgress       = "recon.progress"
	EventReconCompleted      = "recon.completed"
	EventReconFailed         = "recon.failed"
	EventScopeSkipped        = "scope.skipped"
	EventAssetUpdated        = "asset.updated"

	EventAnalysisStarted   = "analysis.started"
	EventAnalysisCompleted = "analysis.completed"
	EventAnalysisFailed    = "analysis.failed"
	EventCandidateCreated  = "candidate.created"
	EventCandidateUpdated  = "candidate.updated"
	EventSignalDetected    = "signal.detected"

	EventTechnologyDetected  = "technology.detected"
	EventTechnologyChanged   = "technology.changed"
	EventServiceUpdated      = "service.updated"
	EventAssetChangeDetected = "asset.change_detected"
)

// Asset represents a discovered host or subdomain attributable to an authorized target.
type Asset struct {
	ID        string    `json:"id"`
	TargetID  string    `json:"target_id"`
	Hostname  string    `json:"hostname"`
	AssetType string    `json:"asset_type"` // e.g., "ROOT_DOMAIN", "SUBDOMAIN", "IP"
	Status    string    `json:"status"`     // e.g., "DISCOVERED", "RESOLVED", "LIVE", "UNRESPONSIVE"
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// DNSRecord captures an authoritative DNS observation for an asset.
type DNSRecord struct {
	ID         string    `json:"id"`
	AssetID    string    `json:"asset_id"`
	RecordType string    `json:"record_type"` // "A", "AAAA", "CNAME"
	Value      string    `json:"value"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// HTTPService captures verified HTTP protocol availability on an asset.
type HTTPService struct {
	ID           string    `json:"id"`
	AssetID      string    `json:"asset_id"`
	URL          string    `json:"url"`
	StatusCode   int       `json:"status_code"`
	ContentType  string    `json:"content_type,omitempty"`
	ResponseTime int64     `json:"response_time_ms"` // in milliseconds
	FinalURL     string    `json:"final_url,omitempty"`
	ServerHeader string    `json:"server_header,omitempty"`
	TLSVersion   string    `json:"tls_version,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
}

// URLRecord captures a discovered or crawled HTTP endpoint belonging strictly in scope.
type URLRecord struct {
	ID        string    `json:"id"`
	AssetID   string    `json:"asset_id"`
	URL       string    `json:"url"`
	Source    string    `json:"source"` // "SEED", "CRAWLER", "ROBOTS", "SITEMAP"
	Depth     int       `json:"depth"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// ReconRun encapsulates a scoped reconnaissance execution instance.
type ReconRun struct {
	ID                 string     `json:"id"`
	JobID              string     `json:"job_id"`
	TargetID           string     `json:"target_id"`
	Status             JobStatus  `json:"status"`
	HostsDiscovered    int        `json:"hosts_discovered"`
	HostsResolved      int        `json:"hosts_resolved"`
	HTTPProbed         int        `json:"http_probed"`
	URLsDiscovered     int        `json:"urls_discovered"`
	URLsCrawled        int        `json:"urls_crawled"`
	Errors             int        `json:"errors"`
	SkippedOutOfScope  int        `json:"skipped_out_of_scope"`
	StartedAt          time.Time  `json:"started_at"`
	CompletedAt        *time.Time `json:"completed_at,omitempty"`
}

// ReconProgress encapsulates real-time execution progress counters.
type ReconProgress struct {
	HostsDiscovered   int `json:"hosts_discovered"`
	HostsResolved     int `json:"hosts_resolved"`
	HTTPProbed        int `json:"http_probed"`
	URLsDiscovered    int `json:"urls_discovered"`
	URLsCrawled       int `json:"urls_crawled"`
	Errors            int `json:"errors"`
	SkippedOutOfScope int `json:"skipped_out_of_scope"`
}

// ConfidenceLevel defines the reliability metric for technology findings.
type ConfidenceLevel string

const (
	ConfidenceLow    ConfidenceLevel = "LOW"
	ConfidenceMedium ConfidenceLevel = "MEDIUM"
	ConfidenceHigh   ConfidenceLevel = "HIGH"
)

// TechnologyObservation represents a passive evidence-based detection of a software technology.
type TechnologyObservation struct {
	ID              string          `json:"id"`
	AssetID         string          `json:"asset_id"`
	TargetID        string          `json:"target_id"`
	ServiceID       string          `json:"service_id,omitempty"`
	TechnologyName  string          `json:"technology_name"`
	Category        string          `json:"category"` // e.g., "web_server", "web_framework", "cms", "cdn"
	Version         *string         `json:"version"`  // NULL if cannot be reliably determined (no guessing)
	Confidence      ConfidenceLevel `json:"confidence"`
	DetectionSource string          `json:"detection_source"` // "response_header", "html_meta", "html_body", "script_src", "cookie", "path", etc.
	Evidence        string          `json:"evidence"`
	FirstSeen       time.Time       `json:"first_seen"`
	LastSeen        time.Time       `json:"last_seen"`
}

// ServiceObservation represents enhanced passive fingerprinting of an HTTP service.
type ServiceObservation struct {
	ID              string            `json:"id"`
	AssetID         string            `json:"asset_id"`
	TargetID        string            `json:"target_id"`
	ServiceIdentity string            `json:"service_identity"` // e.g. "https://example.com:443"
	Scheme          string            `json:"scheme"`
	Port            int               `json:"port"`
	StatusCode      int               `json:"status_code"`
	PageTitle       string            `json:"page_title,omitempty"`
	WebServer       string            `json:"web_server,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`
	ContentLength   int64             `json:"content_length"`
	ResponseTimeMS  int64             `json:"response_time_ms"`
	TLSVersion      string            `json:"tls_version,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	FirstSeen       time.Time         `json:"first_seen"`
	LastSeen        time.Time         `json:"last_seen"`
}

// SecurityObservation captures passive observation of HTTP security mechanisms (NOT vulnerabilities).
type SecurityObservation struct {
	ID           string    `json:"id"`
	AssetID      string    `json:"asset_id"`
	TargetID     string    `json:"target_id"`
	ServiceID    string    `json:"service_id,omitempty"`
	PropertyName string    `json:"property_name"` // e.g., "Strict-Transport-Security", "Content-Security-Policy"
	IsPresent    bool      `json:"is_present"`
	Details      string    `json:"details,omitempty"`
	RawValue     string    `json:"raw_value,omitempty"`
	ObservedAt   time.Time `json:"observed_at"`
}

// AssetTag represents an organizational or operational tag on an asset.
type AssetTag struct {
	ID         string    `json:"id"`
	AssetID    string    `json:"asset_id"`
	TargetID   string    `json:"target_id"`
	Tag        string    `json:"tag"` // e.g. "production", "staging", "api", "admin", "cdn", "static", "unknown"
	IsInferred bool      `json:"is_inferred"`
	CreatedAt  time.Time `json:"created_at"`
	CreatedBy  string    `json:"created_by"`
}

// AssetChangeType defines kinds of state transitions detected between scans.
type AssetChangeType string
type ChangeType = AssetChangeType

const (
	ChangeNewAsset          AssetChangeType = "NEW_ASSET"
	ChangeRemovedAsset      AssetChangeType = "REMOVED_ASSET"
	ChangeChangedService    AssetChangeType = "CHANGED_SERVICE"
	ChangeNewTechnology     AssetChangeType = "NEW_TECHNOLOGY"
	ChangeRemovedTechnology AssetChangeType = "REMOVED_TECHNOLOGY"
	ChangeNewURL            AssetChangeType = "NEW_URL"
	ChangeRemovedURL        AssetChangeType = "REMOVED_URL"
)

// AssetChange records historical transitions between scans.
type AssetChange struct {
	ID            string                 `json:"id"`
	TargetID      string                 `json:"target_id"`
	AssetID       string                 `json:"asset_id"`
	ChangeType    AssetChangeType        `json:"change_type"`
	EntityType    string                 `json:"entity_type"` // "asset", "service", "technology", "url"
	EntityID      string                 `json:"entity_id"`
	PreviousState map[string]interface{} `json:"previous_state,omitempty"`
	CurrentState  map[string]interface{} `json:"current_state,omitempty"`
	DetectedAt    time.Time              `json:"detected_at"`
}

// PageAsset captures a static script, stylesheet, sourcemap, or API path observed in HTML.
type PageAsset struct {
	ID         string    `json:"id"`
	AssetID    string    `json:"asset_id"`
	TargetID   string    `json:"target_id"`
	URL        string    `json:"url"`
	AssetType  string    `json:"asset_type"` // "script", "stylesheet", "sourcemap", "api_endpoint", "static"
	SourcePage string    `json:"source_page"`
	IsInScope  bool      `json:"is_in_scope"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// Pagination and Filter definitions
type TechnologyFilter struct {
	TargetID       string          `json:"target_id"`
	AssetID        string          `json:"asset_id,omitempty"`
	Category       string          `json:"category,omitempty"`
	TechnologyName string          `json:"technology_name,omitempty"`
	Confidence     ConfidenceLevel `json:"confidence,omitempty"`
	MinConfidence  ConfidenceLevel `json:"min_confidence,omitempty"`
	Name           string          `json:"name,omitempty"`
	Search         string          `json:"search,omitempty"`
	Limit          int             `json:"limit"`
	Offset         int             `json:"offset"`
}

type ServiceFilter struct {
	TargetID   string `json:"target_id"`
	AssetID    string `json:"asset_id,omitempty"`
	Scheme     string `json:"scheme,omitempty"`
	Port       int    `json:"port,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	WebServer  string `json:"web_server,omitempty"`
	Search     string `json:"search,omitempty"`
	Limit      int    `json:"limit"`
	Offset     int    `json:"offset"`
}

type ChangeFilter struct {
	TargetID   string          `json:"target_id"`
	AssetID    string          `json:"asset_id,omitempty"`
	ChangeType AssetChangeType `json:"change_type,omitempty"`
	EntityType string          `json:"entity_type,omitempty"`
	Limit      int             `json:"limit"`
	Offset     int             `json:"offset"`
}

type AssetFilter struct {
	TargetID string `json:"target_id"`
	Hostname string `json:"hostname,omitempty"`
	Status   string `json:"status,omitempty"`
	Tag      string `json:"tag,omitempty"`
	Limit    int    `json:"limit"`
	Offset   int    `json:"offset"`
}

// TargetIntelligenceSummary provides a high-level overview of a target's intelligence state.
type TargetIntelligenceSummary struct {
	TargetID            string            `json:"target_id"`
	TotalAssets         int               `json:"total_assets"`
	ActiveAssets        int               `json:"active_assets"`
	TotalServices       int               `json:"total_services"`
	TotalTechnologies   int               `json:"total_technologies"`
	TotalURLs           int               `json:"total_urls"`
	TotalChanges        int               `json:"total_changes"`
	TopCategories       map[string]int    `json:"top_categories"`
	TopTechnologies     map[string]int    `json:"top_technologies"`
	SecurityPosture     map[string]int    `json:"security_posture"` // counts of present vs absent security observations
	InferredTagsCount   map[string]int    `json:"inferred_tags_count"`
	RecentChanges       []*AssetChange    `json:"recent_changes"`
}

// AssetDetail provides complete, drill-down intelligence for an individual asset.
type AssetDetail struct {
	Asset                *Asset                   `json:"asset"`
	DNSRecords           []*DNSRecord             `json:"dns_records"`
	Services             []*ServiceObservation    `json:"services"`
	Technologies         []*TechnologyObservation `json:"technologies"`
	SecurityObservations []*SecurityObservation   `json:"security_observations"`
	Tags                 []*AssetTag              `json:"tags"`
	PageAssets           []*PageAsset             `json:"page_assets"`
	URLs                 []*URLRecord             `json:"urls"`
	Changes              []*AssetChange           `json:"changes"`
}

// Phase 4: AI Analysis & Finding Candidate Models

type CandidateState string

const (
	CandidateStateObservation     CandidateState = "OBSERVATION"
	CandidateStateSignal          CandidateState = "SIGNAL"
	CandidateStateCandidate       CandidateState = "CANDIDATE"
	CandidateStateNeedsValidation CandidateState = "NEEDS_VALIDATION"
	CandidateStateValidating      CandidateState = "VALIDATING"
	CandidateStateValidated       CandidateState = "VALIDATED"
	CandidateStateRejected        CandidateState = "REJECTED"
	CandidateStateDismissed       CandidateState = "DISMISSED"
	CandidateStateDuplicate       CandidateState = "DUPLICATE"
	CandidateStateReadyForReview  CandidateState = "READY_FOR_REVIEW"
	CandidateStateReported        CandidateState = "REPORTED"
	CandidateStateResolved        CandidateState = "RESOLVED"
)

type AnalysisRunStatus string

const (
	AnalysisRunStatusPending   AnalysisRunStatus = "PENDING"
	AnalysisRunStatusRunning   AnalysisRunStatus = "RUNNING"
	AnalysisRunStatusCompleted AnalysisRunStatus = "COMPLETED"
	AnalysisRunStatusFailed    AnalysisRunStatus = "FAILED"
)

type AnalysisRun struct {
	ID              string            `json:"id"`
	TargetID        string            `json:"target_id"`
	AssetID         string            `json:"asset_id,omitempty"`
	Status          AnalysisRunStatus `json:"status"`
	Provider        string            `json:"provider"`
	Model           string            `json:"model"`
	SignalsCount    int               `json:"signals_count"`
	CandidatesCount int               `json:"candidates_count"`
	Summary         string            `json:"summary,omitempty"`
	ConfidenceNotes string            `json:"confidence_notes,omitempty"`
	Error           string            `json:"error,omitempty"`
	ExecutionTimeMS int               `json:"execution_time_ms"`
	CreatedAt       time.Time         `json:"created_at"`
	CompletedAt     *time.Time        `json:"completed_at,omitempty"`
}

type SecuritySignal struct {
	ID            string         `json:"id"`
	AnalysisRunID string         `json:"analysis_run_id,omitempty"`
	TargetID      string         `json:"target_id"`
	AssetID       string         `json:"asset_id"`
	SignalType    string         `json:"signal_type"`
	SeverityHint  string         `json:"severity_hint"`
	Evidence      string         `json:"evidence"`
	Source        string         `json:"source"`
	URL           string         `json:"url,omitempty"`
	Details       map[string]any `json:"details,omitempty"`
	DetectedAt    time.Time      `json:"detected_at"`
}

type FindingCandidate struct {
	ID                      string            `json:"id"`
	AnalysisRunID           string            `json:"analysis_run_id,omitempty"`
	TargetID                string            `json:"target_id"`
	AssetID                 string            `json:"asset_id"`
	Category                string            `json:"category"`
	Title                   string            `json:"title"`
	Description             string            `json:"description"`
	State                   CandidateState    `json:"state"`
	ConfidenceScore         float64           `json:"confidence_score"`
	Reasoning               string            `json:"reasoning"`
	MissingEvidence         string            `json:"missing_evidence"`
	ValidationSteps         []string          `json:"validation_steps"`
	EvidenceReferences      []string          `json:"evidence_references"`
	RecommendedVerification string            `json:"recommended_verification"`
	IsMock                  bool              `json:"is_mock"`
	CreatedAt               time.Time         `json:"created_at"`
	UpdatedAt               time.Time         `json:"updated_at"`
	Evidence                []*CandidateEvidence `json:"evidence,omitempty"`
	Signals                 []*SecuritySignal `json:"signals,omitempty"`
}

type CandidateEvidence struct {
	ID          string         `json:"id"`
	CandidateID string         `json:"candidate_id"`
	EvidenceType string        `json:"evidence_type"`
	ReferenceID string         `json:"reference_id"`
	Summary     string         `json:"summary"`
	SHA256      string         `json:"sha256"`
	Details     map[string]any `json:"details,omitempty"`
	CollectedAt time.Time      `json:"collected_at"`
}

type CandidateFilter struct {
	TargetID string         `json:"target_id"`
	AssetID  string         `json:"asset_id,omitempty"`
	Category string         `json:"category,omitempty"`
	State    CandidateState `json:"state,omitempty"`
	Search   string         `json:"search,omitempty"`
	Limit    int            `json:"limit"`
	Offset   int            `json:"offset"`
}

type TriggerAnalysisRequest struct {
	TargetID string `json:"target_id"`
	AssetID  string `json:"asset_id,omitempty"`
}

type UpdateCandidateStateRequest struct {
	State  CandidateState `json:"state"`
	Reason string         `json:"reason"`
}



