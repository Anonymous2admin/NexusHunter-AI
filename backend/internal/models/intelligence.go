package models

import (
	"time"
)

// GraphNodeType defines the entity classification in the Asset Relationship Graph.
type GraphNodeType string

const (
	GraphNodeTarget         GraphNodeType = "TARGET"
	GraphNodeDomain         GraphNodeType = "DOMAIN"
	GraphNodeSubdomain      GraphNodeType = "SUBDOMAIN"
	GraphNodeIP             GraphNodeType = "IP"
	GraphNodeDNSRecord      GraphNodeType = "DNS_RECORD"
	GraphNodeHTTPService    GraphNodeType = "HTTP_SERVICE"
	GraphNodeURL            GraphNodeType = "URL"
	GraphNodeEndpoint       GraphNodeType = "ENDPOINT"
	GraphNodeTechnology     GraphNodeType = "TECHNOLOGY"
	GraphNodeJavaScript     GraphNodeType = "JAVASCRIPT"
	GraphNodeAPI            GraphNodeType = "API"
	GraphNodeAuthBoundary   GraphNodeType = "AUTH_BOUNDARY"
	GraphNodeSecuritySignal GraphNodeType = "SECURITY_SIGNAL"
	GraphNodeCandidate      GraphNodeType = "CANDIDATE"
	GraphNodeFinding        GraphNodeType = "FINDING"
	GraphNodeChange         GraphNodeType = "CHANGE"
)

// GraphEdgeType defines semantic directed relationships in the Asset Relationship Graph.
type GraphEdgeType string

const (
	GraphEdgeResolvesTo     GraphEdgeType = "RESOLVES_TO"
	GraphEdgeHosts          GraphEdgeType = "HOSTS"
	GraphEdgeServes         GraphEdgeType = "SERVES"
	GraphEdgeReferences     GraphEdgeType = "REFERENCES"
	GraphEdgeDiscoveredFrom GraphEdgeType = "DISCOVERED_FROM"
	GraphEdgeUses           GraphEdgeType = "USES"
	GraphEdgeRedirectsTo    GraphEdgeType = "REDIRECTS_TO"
	GraphEdgeBelongsTo      GraphEdgeType = "BELONGS_TO"
	GraphEdgeChangedFrom    GraphEdgeType = "CHANGED_FROM"
	GraphEdgeRelatedTo      GraphEdgeType = "RELATED_TO"
	GraphEdgeTriggers       GraphEdgeType = "TRIGGERS"
	GraphEdgeSupports         GraphEdgeType = "SUPPORTS"
	GraphEdgeContradicts      GraphEdgeType = "CONTRADICTS"
	GraphEdgeExpectedTo       GraphEdgeType = "EXPECTED_TO"
	GraphEdgeObservedAs       GraphEdgeType = "OBSERVED_AS"
	GraphEdgeDeviatesFrom     GraphEdgeType = "DEVIATES_FROM"
	GraphEdgeDerivedFrom      GraphEdgeType = "DERIVED_FROM"
	GraphEdgeRequiresEvidence GraphEdgeType = "REQUIRES_EVIDENCE"
)

// GraphNode represents an entity in the attack surface relationship graph.
type GraphNode struct {
	ID              string                 `json:"id"`
	TargetID        string                 `json:"target_id"`
	AssetID         string                 `json:"asset_id,omitempty"`
	Type            GraphNodeType          `json:"type"`
	Label           string                 `json:"label"`
	EpistemicStatus EpistemicStatus        `json:"epistemic_status,omitempty"`
	Properties      map[string]interface{} `json:"properties,omitempty"`
	FirstSeen       time.Time              `json:"first_seen"`
	LastSeen        time.Time              `json:"last_seen"`
}

// GraphEdge represents a directed, typed relationship between two graph nodes.
type GraphEdge struct {
	ID              string                 `json:"id"`
	TargetID        string                 `json:"target_id"`
	SourceNodeID    string                 `json:"source_node_id"`
	TargetNodeID    string                 `json:"target_node_id"`
	Relationship    GraphEdgeType          `json:"relationship"`
	EpistemicStatus EpistemicStatus        `json:"epistemic_status,omitempty"`
	Weight          float64                `json:"weight"`
	Properties      map[string]interface{} `json:"properties,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
}

// GraphData holds the nodes and edges for visualization and traversal.
type GraphData struct {
	TargetID   string            `json:"target_id"`
	Nodes      []*GraphNode      `json:"nodes"`
	Edges      []*GraphEdge      `json:"edges"`
	TotalNodes int               `json:"total_nodes"`
	TotalEdges int               `json:"total_edges"`
	Metrics    map[string]int    `json:"metrics"`
}

// TemporalChangeType categorizes differences between successive observations.
type TemporalChangeType string

const (
	TemporalChangeNewAsset             TemporalChangeType = "NEW_ASSET"
	TemporalChangeRemovedAsset         TemporalChangeType = "REMOVED_ASSET"
	TemporalChangeNewEndpoint          TemporalChangeType = "NEW_ENDPOINT"
	TemporalChangeRemovedEndpoint      TemporalChangeType = "REMOVED_ENDPOINT"
	TemporalChangeNewTechnology        TemporalChangeType = "NEW_TECHNOLOGY"
	TemporalChangeTechnologyChanged    TemporalChangeType = "TECHNOLOGY_CHANGED"
	TemporalChangeHTTPBehaviorChanged  TemporalChangeType = "HTTP_BEHAVIOR_CHANGED"
	TemporalChangeSecurityHeaderChanged TemporalChangeType = "SECURITY_HEADER_CHANGED"
	TemporalChangeDNSChanged           TemporalChangeType = "DNS_CHANGED"
	TemporalChangeRedirectChanged      TemporalChangeType = "REDIRECT_CHANGED"
	TemporalChangeAuthObsChanged       TemporalChangeType = "AUTH_OBSERVATION_CHANGED"
)

// TemporalChangeRecord tracks what changed between scans with provenance and confidence.
type TemporalChangeRecord struct {
	ID            string                 `json:"id"`
	TargetID      string                 `json:"target_id"`
	AssetID       string                 `json:"asset_id,omitempty"`
	ChangeType    TemporalChangeType     `json:"change_type"`
	Summary       string                 `json:"summary"`
	PreviousValue string                 `json:"previous_value"`
	CurrentValue  string                 `json:"current_value"`
	Source        string                 `json:"source"`
	Confidence    float64                `json:"confidence"`
	FirstSeen     time.Time              `json:"first_seen"`
	LastSeen      time.Time              `json:"last_seen"`
	DetectedAt    time.Time              `json:"detected_at"`
	Details       map[string]interface{} `json:"details,omitempty"`
}

// SecurityState represents an observed authorization or access state.
type SecurityState string

const (
	StateUnauthenticated  SecurityState = "UNAUTHENTICATED"
	StateAuthenticated    SecurityState = "AUTHENTICATED"
	StateAuthorized       SecurityState = "AUTHORIZED"
	StateResourceOwner    SecurityState = "RESOURCE_OWNER"
	StateResourceNonOwner SecurityState = "RESOURCE_NON_OWNER"
	StateSessionActive    SecurityState = "SESSION_ACTIVE"
	StateSessionExpired   SecurityState = "SESSION_EXPIRED"
	StateA                SecurityState = "STATE_A"
	StateB                SecurityState = "STATE_B"
)

// InvariantSignal records an observed state-machine or access-boundary inconsistency.
type InvariantSignal struct {
	ID                 string        `json:"id"`
	TargetID           string        `json:"target_id"`
	AssetID            string        `json:"asset_id"`
	Endpoint           string        `json:"endpoint"`
	StateFrom          SecurityState `json:"state_from"`
	StateTo            SecurityState `json:"state_to"`
	ObservedCondition  string        `json:"observed_condition"`
	InvariantViolation string        `json:"invariant_violation"`
	Confidence         float64       `json:"confidence"`
	Evidence           string        `json:"evidence"`
	DetectedAt         time.Time     `json:"detected_at"`
}

// BehaviorDifference holds normalized comparative observations between two requests.
type BehaviorDifference struct {
	ID                  string                 `json:"id"`
	TargetID            string                 `json:"target_id"`
	AssetID             string                 `json:"asset_id"`
	ProbeAURL           string                 `json:"probe_a_url"`
	ProbeBURL           string                 `json:"probe_b_url"`
	ContextA            string                 `json:"context_a"`
	ContextB            string                 `json:"context_b"`
	StatusDiff          bool                   `json:"status_diff"`
	LengthDiff          int                    `json:"length_diff"`
	HeaderDiff          []string               `json:"header_diff"`
	BodyDiffFingerprint string                 `json:"body_diff_fingerprint"`
	StateChangeObserved bool                   `json:"state_change_observed"`
	TimingDeltaMS       int                    `json:"timing_delta_ms"`
	IsMeaningful        bool                   `json:"is_meaningful"`
	NormalizedDetails   map[string]interface{} `json:"normalized_details,omitempty"`
	DetectedAt          time.Time              `json:"detected_at"`
}

// PriorityFactor explains one component of the transparent investigation score.
type PriorityFactor struct {
	Name        string  `json:"name"`
	Score       int     `json:"score"` // positive or negative contribution
	Weight      float64 `json:"weight"`
	Explanation string  `json:"explanation"`
}

// ClusterStatus represents lifecycle of an investigation cluster.
type ClusterStatus string

const (
	ClusterStatusActive       ClusterStatus = "ACTIVE"
	ClusterStatusInvestigating ClusterStatus = "INVESTIGATING"
	ClusterStatusValidating   ClusterStatus = "VALIDATING"
	ClusterStatusValidated    ClusterStatus = "VALIDATED"
	ClusterStatusRejected     ClusterStatus = "REJECTED"
	ClusterStatusClosed       ClusterStatus = "CLOSED"
)

// InvestigationCluster aggregates correlated independent signals into an actionable investigation.
type InvestigationCluster struct {
	ID                    string                  `json:"id"`
	TargetID              string                  `json:"target_id"`
	Title                 string                  `json:"title"`
	Category              string                  `json:"category"`
	PriorityScore         int                     `json:"priority_score"` // 0 - 100 transparent score
	PriorityExplanation   string                  `json:"priority_explanation"`
	PriorityFactors       []PriorityFactor        `json:"priority_factors"`
	RelatedAssets         []string                `json:"related_assets"`
	RelatedEndpoints      []string                `json:"related_endpoints"`
	RelatedSignals        []*SecuritySignal       `json:"related_signals"`
	RelatedChanges        []*TemporalChangeRecord `json:"related_changes"`
	EvidenceItems         []*CandidateEvidence    `json:"evidence_items"`
	Confidence            float64                 `json:"confidence"`
	Reason                string                  `json:"reason"`
	RecommendedValidation []string                `json:"recommended_validation"`
	Status                ClusterStatus           `json:"status"`
	CreatedAt             time.Time               `json:"created_at"`
	UpdatedAt             time.Time               `json:"updated_at"`
}

// ResearchMemory captures cumulative historical context for a research target.
type ResearchMemory struct {
	TargetID                  string                  `json:"target_id"`
	KnownAssetsCount          int                     `json:"known_assets_count"`
	KnownEndpointsCount        int                     `json:"known_endpoints_count"`
	KnownTechnologiesCount    int                     `json:"known_technologies_count"`
	TotalHistoricalChanges    int                     `json:"total_historical_changes"`
	ActiveInvestigationsCount int                     `json:"active_investigations_count"`
	ValidatedFindingsCount    int                     `json:"validated_findings_count"`
	RejectedCandidatesCount   int                     `json:"rejected_candidates_count"`
	RecentWhatChanged         []*TemporalChangeRecord `json:"recent_what_changed"`
	DeservesReinvestigation   []*InvestigationCluster `json:"deserves_reinvestigation"`
	LastScanAt                time.Time               `json:"last_scan_at"`
}

// ControlledValidationRequest initiates non-destructive safe verification.
type ControlledValidationRequest struct {
	TargetID     string `json:"target_id"`
	CandidateID  string `json:"candidate_id,omitempty"`
	ClusterID    string `json:"cluster_id,omitempty"`
	VerificationStep string `json:"verification_step,omitempty"`
}

// ControlledValidationResult encapsulates the non-destructive outcome.
type ControlledValidationResult struct {
	ID           string                 `json:"id"`
	CandidateID  string                 `json:"candidate_id,omitempty"`
	ClusterID    string                 `json:"cluster_id,omitempty"`
	Success      bool                   `json:"success"`
	State        CandidateState         `json:"state"`
	EvidenceItem *CandidateEvidence     `json:"evidence_item,omitempty"`
	Observations []string               `json:"observations"`
	OutputFact   string                 `json:"output_fact"`
	ExecutedAt   time.Time              `json:"executed_at"`
}
