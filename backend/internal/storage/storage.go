package storage

import (
	"context"
	"errors"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

var (
	ErrNotFound = errors.New("record not found")
	ErrConflict = errors.New("record already exists")
)

// TargetRepository specifies storage operations for authorized research targets.
type TargetRepository interface {
	Create(ctx context.Context, target *models.Target) error
	GetByID(ctx context.Context, id string) (*models.Target, error)
	List(ctx context.Context) ([]*models.Target, error)
	Update(ctx context.Context, target *models.Target) error
	Delete(ctx context.Context, id string) error
}

// JobRepository specifies storage operations for scan jobs.
type JobRepository interface {
	Create(ctx context.Context, job *models.ScanJob) error
	GetByID(ctx context.Context, id string) (*models.ScanJob, error)
	List(ctx context.Context, targetID string) ([]*models.ScanJob, error)
	Update(ctx context.Context, job *models.ScanJob) error
}

// EventRepository specifies storage operations for audit and telemetry events.
type EventRepository interface {
	Record(ctx context.Context, event *models.Event) error
	ListRecent(ctx context.Context, limit int) ([]*models.Event, error)
}

// ReconRepository specifies storage operations for reconnaissance assets, DNS, HTTP services, URLs, and runs.
type ReconRepository interface {
	SaveAsset(ctx context.Context, asset *models.Asset) error
	GetAssetByHostname(ctx context.Context, targetID, hostname string) (*models.Asset, error)
	ListAssets(ctx context.Context, targetID string) ([]*models.Asset, error)
	UpdateAssetStatus(ctx context.Context, id string, status string) error

	SaveDNSRecord(ctx context.Context, record *models.DNSRecord) error
	ListDNSRecords(ctx context.Context, assetID string) ([]*models.DNSRecord, error)

	SaveHTTPService(ctx context.Context, svc *models.HTTPService) error
	ListHTTPServices(ctx context.Context, targetID string) ([]*models.HTTPService, error)

	SaveURL(ctx context.Context, u *models.URLRecord) error
	ListURLs(ctx context.Context, targetID string) ([]*models.URLRecord, error)

	SaveReconRun(ctx context.Context, run *models.ReconRun) error
	GetReconRunByJobID(ctx context.Context, jobID string) (*models.ReconRun, error)
	UpdateReconRun(ctx context.Context, run *models.ReconRun) error
}

// AssetIntelligenceRepository specifies storage operations for technology fingerprinting, service observations, security observations, tags, changes, and page assets.
type AssetIntelligenceRepository interface {
	SaveTechnologyObservation(ctx context.Context, obs *models.TechnologyObservation) error
	ListTechnologyObservations(ctx context.Context, filter models.TechnologyFilter) ([]*models.TechnologyObservation, int, error)

	SaveServiceObservation(ctx context.Context, obs *models.ServiceObservation) error
	ListServiceObservations(ctx context.Context, filter models.ServiceFilter) ([]*models.ServiceObservation, int, error)

	SaveSecurityObservation(ctx context.Context, obs *models.SecurityObservation) error
	ListSecurityObservations(ctx context.Context, targetID, assetID string) ([]*models.SecurityObservation, error)

	AddAssetTag(ctx context.Context, tag *models.AssetTag) error
	RemoveAssetTag(ctx context.Context, assetID, tag string) error
	ListAssetTags(ctx context.Context, assetID string) ([]*models.AssetTag, error)
	ListTagsForTarget(ctx context.Context, targetID string) ([]*models.AssetTag, error)

	RecordAssetChange(ctx context.Context, change *models.AssetChange) error
	ListAssetChanges(ctx context.Context, filter models.ChangeFilter) ([]*models.AssetChange, int, error)

	SavePageAsset(ctx context.Context, pa *models.PageAsset) error
	ListPageAssets(ctx context.Context, assetID string) ([]*models.PageAsset, error)

	GetTargetIntelligence(ctx context.Context, targetID string) (*models.TargetIntelligenceSummary, error)
	GetAssetDetail(ctx context.Context, targetID, assetID string) (*models.AssetDetail, error)
	ListAssetsFiltered(ctx context.Context, filter models.AssetFilter) ([]*models.Asset, int, error)
}

// AIAnalysisRepository specifies storage operations for AI analysis runs, signals, and finding candidates.
type AIAnalysisRepository interface {
	SaveAnalysisRun(ctx context.Context, run *models.AnalysisRun) error
	GetAnalysisRun(ctx context.Context, id string) (*models.AnalysisRun, error)
	ListAnalysisRuns(ctx context.Context, targetID string) ([]*models.AnalysisRun, error)
	UpdateAnalysisRun(ctx context.Context, run *models.AnalysisRun) error

	SaveSecuritySignal(ctx context.Context, signal *models.SecuritySignal) error
	ListSecuritySignals(ctx context.Context, targetID, assetID string) ([]*models.SecuritySignal, error)

	SaveFindingCandidate(ctx context.Context, candidate *models.FindingCandidate) error
	GetFindingCandidate(ctx context.Context, id string) (*models.FindingCandidate, error)
	ListFindingCandidates(ctx context.Context, filter models.CandidateFilter) ([]*models.FindingCandidate, int, error)
	UpdateCandidateState(ctx context.Context, id string, newState models.CandidateState, reason string) error

	SaveCandidateEvidence(ctx context.Context, evidence *models.CandidateEvidence) error
	ListCandidateEvidence(ctx context.Context, candidateID string) ([]*models.CandidateEvidence, error)
}

// SecurityIntelligenceRepository specifies storage operations for relationship graphs, temporal intelligence,
// state invariants, differential behavior records, and correlated investigation clusters.
type SecurityIntelligenceRepository interface {
	// Graph Operations
	SaveGraphNode(ctx context.Context, node *models.GraphNode) error
	SaveGraphEdge(ctx context.Context, edge *models.GraphEdge) error
	GetTargetGraph(ctx context.Context, targetID string) (*models.GraphData, error)

	// Temporal Intelligence ("What Changed")
	RecordTemporalChange(ctx context.Context, record *models.TemporalChangeRecord) error
	ListTemporalChanges(ctx context.Context, targetID string, limit int) ([]*models.TemporalChangeRecord, error)

	// Invariant & Differential Behavior
	RecordInvariantSignal(ctx context.Context, sig *models.InvariantSignal) error
	ListInvariantSignals(ctx context.Context, targetID string) ([]*models.InvariantSignal, error)
	RecordBehaviorDifference(ctx context.Context, diff *models.BehaviorDifference) error
	ListBehaviorDifferences(ctx context.Context, targetID string) ([]*models.BehaviorDifference, error)

	// Investigation Clusters & Priority Scoring
	SaveInvestigationCluster(ctx context.Context, cluster *models.InvestigationCluster) error
	GetInvestigationCluster(ctx context.Context, id string) (*models.InvestigationCluster, error)
	ListInvestigationClusters(ctx context.Context, targetID string) ([]*models.InvestigationCluster, error)
	UpdateClusterStatus(ctx context.Context, id string, status models.ClusterStatus) error

	// Research Memory
	GetResearchMemory(ctx context.Context, targetID string) (*models.ResearchMemory, error)

	// Controlled Validation
	RecordValidationResult(ctx context.Context, result *models.ControlledValidationResult) error
}

// EvidenceRepository specifies storage operations for Phase 6 Evidence Intelligence & Security Reasoning.
type EvidenceRepository interface {
	SaveEvidence(ctx context.Context, ev *models.Evidence) error
	GetEvidence(ctx context.Context, id string) (*models.Evidence, error)
	ListEvidenceByTarget(ctx context.Context, targetID string) ([]*models.Evidence, error)
	ListEvidenceByAsset(ctx context.Context, assetID string) ([]*models.Evidence, error)
	ListEvidenceByObservation(ctx context.Context, obsID string) ([]*models.Evidence, error)

	SaveEvidenceDiff(ctx context.Context, diff *models.EvidenceDiff) error
	GetEvidenceDiff(ctx context.Context, id string) (*models.EvidenceDiff, error)
	ListEvidenceDiffs(ctx context.Context, targetID string) ([]*models.EvidenceDiff, error)

	SaveSecurityExpectation(ctx context.Context, exp *models.SecurityExpectation) error
	ListSecurityExpectations(ctx context.Context, targetID, assetID string) ([]*models.SecurityExpectation, error)

	SaveSecurityContradiction(ctx context.Context, con *models.SecurityContradiction) error
	GetSecurityContradiction(ctx context.Context, id string) (*models.SecurityContradiction, error)
	ListSecurityContradictions(ctx context.Context, targetID, assetID string) ([]*models.SecurityContradiction, error)

	SaveSecurityOutlier(ctx context.Context, out *models.SecurityOutlier) error
	ListSecurityOutliers(ctx context.Context, targetID, assetID string) ([]*models.SecurityOutlier, error)

	RecordTimelineEvent(ctx context.Context, ev *models.EvidenceTimelineEvent) error
	ListTimelineEvents(ctx context.Context, targetID, assetID string, limit int) ([]*models.EvidenceTimelineEvent, error)
}

// ReasoningRepository specifies storage operations for Phase 7 Security Reasoning, Hypotheses, and Investigations.
type ReasoningRepository interface {
	// Signals
	SaveReasoningSignal(ctx context.Context, sig *models.ReasoningSignal) error
	GetReasoningSignal(ctx context.Context, id string) (*models.ReasoningSignal, error)
	ListReasoningSignals(ctx context.Context, targetID, assetID string) ([]*models.ReasoningSignal, error)
	UpdateSignalStatus(ctx context.Context, id string, status models.SignalStatus) error

	// Hypothesis Groups & Hypotheses
	SaveHypothesisGroup(ctx context.Context, group *models.HypothesisGroup) error
	GetHypothesisGroup(ctx context.Context, id string) (*models.HypothesisGroup, error)
	ListHypothesisGroups(ctx context.Context, targetID string) ([]*models.HypothesisGroup, error)
	SaveHypothesis(ctx context.Context, hyp *models.Hypothesis) error
	GetHypothesis(ctx context.Context, id string) (*models.Hypothesis, error)
	ListHypotheses(ctx context.Context, targetID string) ([]*models.Hypothesis, error)
	ListHypothesesByGroup(ctx context.Context, groupID string) ([]*models.Hypothesis, error)
	UpdateHypothesisStatus(ctx context.Context, id string, status models.HypothesisStatus) error

	// Falsification & Missing Evidence Requirements
	SaveFalsificationCondition(ctx context.Context, cond *models.FalsificationCondition) error
	ListFalsificationConditions(ctx context.Context, hypothesisID string) ([]*models.FalsificationCondition, error)
	SaveEvidenceRequirement(ctx context.Context, req *models.EvidenceRequirement) error
	ListEvidenceRequirements(ctx context.Context, hypothesisID string) ([]*models.EvidenceRequirement, error)
	UpdateEvidenceRequirementStatus(ctx context.Context, id string, status models.RequirementStatus, satisfiedRef string) error

	// Investigations
	SaveInvestigation(ctx context.Context, inv *models.Investigation) error
	GetInvestigation(ctx context.Context, id string) (*models.Investigation, error)
	ListInvestigations(ctx context.Context, targetID string) ([]*models.Investigation, error)
	UpdateInvestigationStatus(ctx context.Context, id string, status models.InvestigationStatus, result string) error

	// Trust Boundaries
	SaveTrustBoundary(ctx context.Context, tb *models.TrustBoundary) error
	ListTrustBoundaries(ctx context.Context, targetID, assetID string) ([]*models.TrustBoundary, error)

	// Auth Contexts
	SaveAuthContext(ctx context.Context, ac *models.AuthContext) error
	ListAuthContexts(ctx context.Context, targetID string) ([]*models.AuthContext, error)

	// Permission Matrix
	SavePermissionMatrixEntry(ctx context.Context, entry *models.PermissionMatrixEntry) error
	ListPermissionMatrix(ctx context.Context, targetID, assetID string) ([]*models.PermissionMatrixEntry, error)

	// Security Controls
	SaveSecurityControl(ctx context.Context, sc *models.SecurityControlRecord) error
	ListSecurityControls(ctx context.Context, targetID, assetID string) ([]*models.SecurityControlRecord, error)

	// Reasoning Runs
	RecordReasoningRun(ctx context.Context, run *models.ReasoningRun) error
}




