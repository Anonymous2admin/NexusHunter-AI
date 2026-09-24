package storage

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// MemoryStorage implements TargetRepository, JobRepository, EventRepository, ReconRepository, and AssetIntelligenceRepository in-memory.
type MemoryStorage struct {
	mu           sync.RWMutex
	targets      map[string]*models.Target
	jobs         map[string]*models.ScanJob
	events       []*models.Event
	assets       map[string]*models.Asset       // key: id
	assetsByHost map[string]string              // key: targetID + ":" + hostname -> assetID
	dnsRecords   map[string][]*models.DNSRecord // key: assetID
	httpServices map[string][]*models.HTTPService
	urls         map[string][]*models.URLRecord
	reconRuns    map[string]*models.ReconRun // key: jobID

	// Phase 3 Asset Intelligence
	techObs    map[string][]*models.TechnologyObservation // key: targetID
	serviceObs map[string][]*models.ServiceObservation    // key: targetID
	secObs     map[string][]*models.SecurityObservation   // key: assetID
	tags       map[string][]*models.AssetTag              // key: assetID
	changes    map[string][]*models.AssetChange           // key: targetID
	pageAssets map[string][]*models.PageAsset             // key: assetID

	// Phase 4 AI Analysis & Findings
	analysisRuns       map[string]*models.AnalysisRun       // key: id
	signals            map[string][]*models.SecuritySignal  // key: targetID
	candidates         map[string]*models.FindingCandidate  // key: id
	candidateEvidences map[string][]*models.CandidateEvidence // key: candidateID

	// Differentiated Security Intelligence & Investigation Engine
	graphNodes         map[string]*models.GraphNode             // key: id
	graphEdges         map[string]*models.GraphEdge             // key: id
	temporalChanges    map[string][]*models.TemporalChangeRecord // key: targetID
	invariants         map[string][]*models.InvariantSignal      // key: targetID
	behaviorDiffs      map[string][]*models.BehaviorDifference   // key: targetID
	clusters           map[string]*models.InvestigationCluster   // key: id
	validationResults  map[string][]*models.ControlledValidationResult // key: candidateID or clusterID

	// Phase 6 Evidence Intelligence & Security Reasoning
	evidenceRecords      map[string]*models.Evidence              // key: id
	evidenceDiffs        map[string]*models.EvidenceDiff          // key: id
	securityExpectations map[string][]*models.SecurityExpectation // key: targetID
	contradictions       map[string]*models.SecurityContradiction // key: id
	outliers             map[string][]*models.SecurityOutlier     // key: targetID
	timelineEvents       []*models.EvidenceTimelineEvent

	// Phase 7 Security Reasoning, Hypotheses & Investigations
	reasoningSignals     map[string]*models.ReasoningSignal          // key: id
	hypothesisGroups     map[string]*models.HypothesisGroup          // key: id
	hypotheses           map[string]*models.Hypothesis               // key: id
	falsifications       map[string][]*models.FalsificationCondition // key: hypothesis_id
	evidenceRequirements map[string][]*models.EvidenceRequirement    // key: hypothesis_id
	investigations       map[string]*models.Investigation            // key: id
	trustBoundaries      map[string][]*models.TrustBoundary          // key: targetID
	authContexts         map[string][]*models.AuthContext            // key: targetID
	permissionMatrix     map[string][]*models.PermissionMatrixEntry  // key: targetID
	securityControls     map[string][]*models.SecurityControlRecord  // key: targetID
	reasoningRuns        map[string]*models.ReasoningRun             // key: id

	// Phase 8 Scope, JS Intel, Cloud References, WAF & AI Hunting Planner
	scopeImports         map[string]*models.ScopeImportReview        // key: id
	jsAssets             map[string]*models.JSAsset                  // key: id
	jsReferences         map[string][]*models.JSReference            // key: targetID
	jsSecrets            map[string][]*models.JSSecretIndicator      // key: targetID
	cloudReferences      map[string][]*models.CloudReference         // key: targetID
	wafObservations      map[string]*models.WAFObservation           // key: targetID:assetID
	investigationPlans   map[string]*models.InvestigationPlan        // key: id
}

// NewMemoryStorage instantiates thread-safe in-memory stores.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		targets:              make(map[string]*models.Target),
		jobs:                 make(map[string]*models.ScanJob),
		events:               make([]*models.Event, 0),
		assets:               make(map[string]*models.Asset),
		assetsByHost:         make(map[string]string),
		dnsRecords:           make(map[string][]*models.DNSRecord),
		httpServices:         make(map[string][]*models.HTTPService),
		urls:                 make(map[string][]*models.URLRecord),
		reconRuns:            make(map[string]*models.ReconRun),
		techObs:              make(map[string][]*models.TechnologyObservation),
		serviceObs:           make(map[string][]*models.ServiceObservation),
		secObs:               make(map[string][]*models.SecurityObservation),
		tags:                 make(map[string][]*models.AssetTag),
		changes:              make(map[string][]*models.AssetChange),
		pageAssets:           make(map[string][]*models.PageAsset),
		analysisRuns:         make(map[string]*models.AnalysisRun),
		signals:              make(map[string][]*models.SecuritySignal),
		candidates:           make(map[string]*models.FindingCandidate),
		candidateEvidences:   make(map[string][]*models.CandidateEvidence),
		graphNodes:           make(map[string]*models.GraphNode),
		graphEdges:           make(map[string]*models.GraphEdge),
		temporalChanges:      make(map[string][]*models.TemporalChangeRecord),
		invariants:           make(map[string][]*models.InvariantSignal),
		behaviorDiffs:        make(map[string][]*models.BehaviorDifference),
		clusters:             make(map[string]*models.InvestigationCluster),
		validationResults:    make(map[string][]*models.ControlledValidationResult),
		evidenceRecords:      make(map[string]*models.Evidence),
		evidenceDiffs:        make(map[string]*models.EvidenceDiff),
		securityExpectations: make(map[string][]*models.SecurityExpectation),
		contradictions:       make(map[string]*models.SecurityContradiction),
		outliers:             make(map[string][]*models.SecurityOutlier),
		timelineEvents:       make([]*models.EvidenceTimelineEvent, 0),
		reasoningSignals:     make(map[string]*models.ReasoningSignal),
		hypothesisGroups:     make(map[string]*models.HypothesisGroup),
		hypotheses:           make(map[string]*models.Hypothesis),
		falsifications:       make(map[string][]*models.FalsificationCondition),
		evidenceRequirements: make(map[string][]*models.EvidenceRequirement),
		investigations:       make(map[string]*models.Investigation),
		trustBoundaries:      make(map[string][]*models.TrustBoundary),
		authContexts:         make(map[string][]*models.AuthContext),
		permissionMatrix:     make(map[string][]*models.PermissionMatrixEntry),
		securityControls:     make(map[string][]*models.SecurityControlRecord),
		reasoningRuns:        make(map[string]*models.ReasoningRun),

		scopeImports:         make(map[string]*models.ScopeImportReview),
		jsAssets:             make(map[string]*models.JSAsset),
		jsReferences:         make(map[string][]*models.JSReference),
		jsSecrets:            make(map[string][]*models.JSSecretIndicator),
		cloudReferences:      make(map[string][]*models.CloudReference),
		wafObservations:      make(map[string]*models.WAFObservation),
		investigationPlans:   make(map[string]*models.InvestigationPlan),
	}
}

// Target Operations
func (m *MemoryStorage) Create(ctx context.Context, target *models.Target) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.targets[target.ID]; exists {
		return ErrConflict
	}
	cp := *target
	m.targets[target.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetByID(ctx context.Context, id string) (*models.Target, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	t, exists := m.targets[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (m *MemoryStorage) List(ctx context.Context) ([]*models.Target, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*models.Target, 0, len(m.targets))
	for _, t := range m.targets {
		cp := *t
		result = append(result, &cp)
	}
	return result, nil
}

func (m *MemoryStorage) Update(ctx context.Context, target *models.Target) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.targets[target.ID]; !exists {
		return ErrNotFound
	}
	cp := *target
	m.targets[target.ID] = &cp
	return nil
}

func (m *MemoryStorage) Delete(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.targets[id]; !exists {
		return ErrNotFound
	}
	delete(m.targets, id)
	return nil
}

// Job Operations
func (m *MemoryStorage) CreateJob(ctx context.Context, job *models.ScanJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *job
	m.jobs[job.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetJobByID(ctx context.Context, id string) (*models.ScanJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	j, exists := m.jobs[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *j
	return &cp, nil
}

func (m *MemoryStorage) ListJobs(ctx context.Context, targetID string) ([]*models.ScanJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*models.ScanJob, 0, len(m.jobs))
	for _, j := range m.jobs {
		if targetID == "" || j.TargetID == targetID {
			cp := *j
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (m *MemoryStorage) UpdateJob(ctx context.Context, job *models.ScanJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.jobs[job.ID]; !exists {
		return ErrNotFound
	}
	cp := *job
	m.jobs[job.ID] = &cp
	return nil
}

// Event Operations
func (m *MemoryStorage) Record(ctx context.Context, event *models.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *event
	m.events = append(m.events, &cp)
	return nil
}

func (m *MemoryStorage) ListRecent(ctx context.Context, limit int) ([]*models.Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if limit <= 0 || limit > len(m.events) {
		limit = len(m.events)
	}

	result := make([]*models.Event, limit)
	start := len(m.events) - limit
	for i := 0; i < limit; i++ {
		cp := *m.events[start+i]
		result[i] = &cp
	}
	return result, nil
}

// Recon Operations
func (m *MemoryStorage) SaveAsset(ctx context.Context, asset *models.Asset) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := asset.TargetID + ":" + asset.Hostname
	if existingID, exists := m.assetsByHost[key]; exists {
		// Update last seen
		if existing, ok := m.assets[existingID]; ok {
			existing.LastSeen = asset.LastSeen
			if asset.Status != "" {
				existing.Status = asset.Status
			}
			return nil
		}
	}

	cp := *asset
	m.assets[asset.ID] = &cp
	m.assetsByHost[key] = asset.ID
	return nil
}

func (m *MemoryStorage) GetAssetByHostname(ctx context.Context, targetID, hostname string) (*models.Asset, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := targetID + ":" + hostname
	assetID, exists := m.assetsByHost[key]
	if !exists {
		return nil, ErrNotFound
	}
	asset, exists := m.assets[assetID]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *asset
	return &cp, nil
}

func (m *MemoryStorage) ListAssets(ctx context.Context, targetID string) ([]*models.Asset, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*models.Asset, 0)
	for _, a := range m.assets {
		if targetID == "" || a.TargetID == targetID {
			cp := *a
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (m *MemoryStorage) UpdateAssetStatus(ctx context.Context, id string, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	asset, exists := m.assets[id]
	if !exists {
		return ErrNotFound
	}
	asset.Status = status
	return nil
}

func (m *MemoryStorage) SaveDNSRecord(ctx context.Context, record *models.DNSRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	list := m.dnsRecords[record.AssetID]
	for _, existing := range list {
		if existing.RecordType == record.RecordType && existing.Value == record.Value {
			existing.LastSeen = record.LastSeen
			return nil
		}
	}
	cp := *record
	m.dnsRecords[record.AssetID] = append(m.dnsRecords[record.AssetID], &cp)
	return nil
}

func (m *MemoryStorage) ListDNSRecords(ctx context.Context, assetID string) ([]*models.DNSRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	list := m.dnsRecords[assetID]
	result := make([]*models.DNSRecord, len(list))
	for i, r := range list {
		cp := *r
		result[i] = &cp
	}
	return result, nil
}

func (m *MemoryStorage) SaveHTTPService(ctx context.Context, svc *models.HTTPService) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	list := m.httpServices[svc.AssetID]
	for _, existing := range list {
		if existing.URL == svc.URL {
			existing.StatusCode = svc.StatusCode
			existing.ContentType = svc.ContentType
			existing.ResponseTime = svc.ResponseTime
			existing.FinalURL = svc.FinalURL
			existing.ServerHeader = svc.ServerHeader
			existing.TLSVersion = svc.TLSVersion
			existing.LastSeen = svc.LastSeen
			return nil
		}
	}
	cp := *svc
	m.httpServices[svc.AssetID] = append(m.httpServices[svc.AssetID], &cp)
	return nil
}

func (m *MemoryStorage) ListHTTPServices(ctx context.Context, targetID string) ([]*models.HTTPService, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*models.HTTPService, 0)
	for assetID, svcs := range m.httpServices {
		if targetID != "" {
			asset, ok := m.assets[assetID]
			if !ok || asset.TargetID != targetID {
				continue
			}
		}
		for _, s := range svcs {
			cp := *s
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (m *MemoryStorage) SaveURL(ctx context.Context, u *models.URLRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	list := m.urls[u.AssetID]
	for _, existing := range list {
		if existing.URL == u.URL {
			existing.LastSeen = u.LastSeen
			return nil
		}
	}
	cp := *u
	m.urls[u.AssetID] = append(m.urls[u.AssetID], &cp)
	return nil
}

func (m *MemoryStorage) ListURLs(ctx context.Context, targetID string) ([]*models.URLRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*models.URLRecord, 0)
	for assetID, urls := range m.urls {
		if targetID != "" {
			asset, ok := m.assets[assetID]
			if !ok || asset.TargetID != targetID {
				continue
			}
		}
		for _, u := range urls {
			cp := *u
			result = append(result, &cp)
		}
	}
	return result, nil
}

func (m *MemoryStorage) SaveReconRun(ctx context.Context, run *models.ReconRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *run
	m.reconRuns[run.JobID] = &cp
	return nil
}

func (m *MemoryStorage) GetReconRunByJobID(ctx context.Context, jobID string) (*models.ReconRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	run, exists := m.reconRuns[jobID]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *run
	return &cp, nil
}

func (m *MemoryStorage) UpdateReconRun(ctx context.Context, run *models.ReconRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.reconRuns[run.JobID]; !exists {
		return ErrNotFound
	}
	cp := *run
	m.reconRuns[run.JobID] = &cp
	return nil
}

// -----------------------------------------------------------------------------
// Phase 3 Asset Intelligence Operations
// -----------------------------------------------------------------------------

func (m *MemoryStorage) SaveTechnologyObservation(ctx context.Context, obs *models.TechnologyObservation) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	list := m.techObs[obs.TargetID]
	for i, existing := range list {
		sameVer := (existing.Version == nil && obs.Version == nil) ||
			(existing.Version != nil && obs.Version != nil && *existing.Version == *obs.Version)
		if existing.AssetID == obs.AssetID && existing.TechnologyName == obs.TechnologyName && sameVer {
			// Update existing
			list[i].LastSeen = obs.LastSeen
			if obs.Confidence == models.ConfidenceHigh {
				list[i].Confidence = models.ConfidenceHigh
			}
			list[i].Evidence = obs.Evidence
			return nil
		}
	}

	cp := *obs
	if cp.FirstSeen.IsZero() {
		cp.FirstSeen = time.Now().UTC()
	}
	if cp.LastSeen.IsZero() {
		cp.LastSeen = time.Now().UTC()
	}
	m.techObs[obs.TargetID] = append(m.techObs[obs.TargetID], &cp)
	return nil
}

func (m *MemoryStorage) ListTechnologyObservations(ctx context.Context, filter models.TechnologyFilter) ([]*models.TechnologyObservation, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	raw := m.techObs[filter.TargetID]
	var matched []*models.TechnologyObservation

	for _, item := range raw {
		if filter.AssetID != "" && item.AssetID != filter.AssetID {
			continue
		}
		if filter.Category != "" && !strings.EqualFold(item.Category, filter.Category) {
			continue
		}
		if filter.Confidence != "" && item.Confidence != filter.Confidence {
			continue
		}
		if filter.Name != "" && !strings.Contains(strings.ToLower(item.TechnologyName), strings.ToLower(filter.Name)) {
			continue
		}
		cp := *item
		matched = append(matched, &cp)
	}

	total := len(matched)
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []*models.TechnologyObservation{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}

	return matched[offset:end], total, nil
}

func (m *MemoryStorage) SaveServiceObservation(ctx context.Context, obs *models.ServiceObservation) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	list := m.serviceObs[obs.TargetID]
	for i, existing := range list {
		if existing.AssetID == obs.AssetID && existing.ServiceIdentity == obs.ServiceIdentity {
			list[i].StatusCode = obs.StatusCode
			list[i].PageTitle = obs.PageTitle
			list[i].WebServer = obs.WebServer
			list[i].ContentType = obs.ContentType
			list[i].ContentLength = obs.ContentLength
			list[i].ResponseTimeMS = obs.ResponseTimeMS
			list[i].TLSVersion = obs.TLSVersion
			list[i].Headers = obs.Headers
			list[i].LastSeen = obs.LastSeen
			return nil
		}
	}

	cp := *obs
	if cp.FirstSeen.IsZero() {
		cp.FirstSeen = time.Now().UTC()
	}
	if cp.LastSeen.IsZero() {
		cp.LastSeen = time.Now().UTC()
	}
	m.serviceObs[obs.TargetID] = append(m.serviceObs[obs.TargetID], &cp)
	return nil
}

func (m *MemoryStorage) ListServiceObservations(ctx context.Context, filter models.ServiceFilter) ([]*models.ServiceObservation, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	raw := m.serviceObs[filter.TargetID]
	var matched []*models.ServiceObservation

	for _, item := range raw {
		if filter.AssetID != "" && item.AssetID != filter.AssetID {
			continue
		}
		if filter.Scheme != "" && !strings.EqualFold(item.Scheme, filter.Scheme) {
			continue
		}
		if filter.Port > 0 && item.Port != filter.Port {
			continue
		}
		if filter.StatusCode > 0 && item.StatusCode != filter.StatusCode {
			continue
		}
		cp := *item
		matched = append(matched, &cp)
	}

	total := len(matched)
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []*models.ServiceObservation{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}

	return matched[offset:end], total, nil
}

func (m *MemoryStorage) SaveSecurityObservation(ctx context.Context, obs *models.SecurityObservation) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	list := m.secObs[obs.AssetID]
	for i, existing := range list {
		if existing.PropertyName == obs.PropertyName {
			list[i].IsPresent = obs.IsPresent
			list[i].Details = obs.Details
			list[i].RawValue = obs.RawValue
			list[i].ObservedAt = obs.ObservedAt
			return nil
		}
	}

	cp := *obs
	if cp.ObservedAt.IsZero() {
		cp.ObservedAt = time.Now().UTC()
	}
	m.secObs[obs.AssetID] = append(m.secObs[obs.AssetID], &cp)
	return nil
}

func (m *MemoryStorage) ListSecurityObservations(ctx context.Context, targetID, assetID string) ([]*models.SecurityObservation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if assetID != "" {
		raw := m.secObs[assetID]
		res := make([]*models.SecurityObservation, len(raw))
		for i, item := range raw {
			cp := *item
			res[i] = &cp
		}
		return res, nil
	}

	var res []*models.SecurityObservation
	for _, obsList := range m.secObs {
		for _, item := range obsList {
			if item.TargetID == targetID {
				cp := *item
				res = append(res, &cp)
			}
		}
	}
	return res, nil
}

func (m *MemoryStorage) AddAssetTag(ctx context.Context, tag *models.AssetTag) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	list := m.tags[tag.AssetID]
	for _, existing := range list {
		if strings.EqualFold(existing.Tag, tag.Tag) {
			return nil // idempotent
		}
	}

	cp := *tag
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now().UTC()
	}
	m.tags[tag.AssetID] = append(m.tags[tag.AssetID], &cp)
	return nil
}

func (m *MemoryStorage) RemoveAssetTag(ctx context.Context, assetID, tag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	list := m.tags[assetID]
	var updated []*models.AssetTag
	found := false
	for _, existing := range list {
		if strings.EqualFold(existing.Tag, tag) {
			found = true
			continue
		}
		updated = append(updated, existing)
	}
	if !found {
		return ErrNotFound
	}
	m.tags[assetID] = updated
	return nil
}

func (m *MemoryStorage) ListAssetTags(ctx context.Context, assetID string) ([]*models.AssetTag, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	raw := m.tags[assetID]
	res := make([]*models.AssetTag, len(raw))
	for i, t := range raw {
		cp := *t
		res[i] = &cp
	}
	return res, nil
}

func (m *MemoryStorage) ListTagsForTarget(ctx context.Context, targetID string) ([]*models.AssetTag, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var res []*models.AssetTag
	for _, tagList := range m.tags {
		for _, t := range tagList {
			if t.TargetID == targetID {
				cp := *t
				res = append(res, &cp)
			}
		}
	}
	return res, nil
}

func (m *MemoryStorage) RecordAssetChange(ctx context.Context, change *models.AssetChange) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := *change
	if cp.DetectedAt.IsZero() {
		cp.DetectedAt = time.Now().UTC()
	}
	m.changes[change.TargetID] = append(m.changes[change.TargetID], &cp)
	return nil
}

func (m *MemoryStorage) ListAssetChanges(ctx context.Context, filter models.ChangeFilter) ([]*models.AssetChange, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	raw := m.changes[filter.TargetID]
	var matched []*models.AssetChange

	for _, item := range raw {
		if filter.AssetID != "" && item.AssetID != filter.AssetID {
			continue
		}
		if filter.ChangeType != "" && item.ChangeType != filter.ChangeType {
			continue
		}
		if filter.EntityType != "" && !strings.EqualFold(item.EntityType, filter.EntityType) {
			continue
		}
		cp := *item
		matched = append(matched, &cp)
	}

	// Sort most recent first
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].DetectedAt.After(matched[j].DetectedAt)
	})

	total := len(matched)
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []*models.AssetChange{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}

	return matched[offset:end], total, nil
}

func (m *MemoryStorage) SavePageAsset(ctx context.Context, pa *models.PageAsset) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	list := m.pageAssets[pa.AssetID]
	for i, existing := range list {
		if existing.URL == pa.URL {
			list[i].LastSeen = pa.LastSeen
			return nil
		}
	}

	cp := *pa
	if cp.FirstSeen.IsZero() {
		cp.FirstSeen = time.Now().UTC()
	}
	if cp.LastSeen.IsZero() {
		cp.LastSeen = time.Now().UTC()
	}
	m.pageAssets[pa.AssetID] = append(m.pageAssets[pa.AssetID], &cp)
	return nil
}

func (m *MemoryStorage) ListPageAssets(ctx context.Context, assetID string) ([]*models.PageAsset, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	raw := m.pageAssets[assetID]
	res := make([]*models.PageAsset, len(raw))
	for i, pa := range raw {
		cp := *pa
		res[i] = &cp
	}
	return res, nil
}

func (m *MemoryStorage) GetTargetIntelligence(ctx context.Context, targetID string) (*models.TargetIntelligenceSummary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	assets, _ := m.listAssetsInternal(targetID)
	totalAssets := len(assets)
	activeAssets := 0
	for _, a := range assets {
		if a.Status == "LIVE" || a.Status == "RESOLVED" {
			activeAssets++
		}
	}

	techs := m.techObs[targetID]
	services := m.serviceObs[targetID]
	changes := m.changes[targetID]

	topCats := make(map[string]int)
	topTechs := make(map[string]int)
	for _, t := range techs {
		topCats[t.Category]++
		topTechs[t.TechnologyName]++
	}

	secPosture := make(map[string]int)
	for _, a := range assets {
		for _, so := range m.secObs[a.ID] {
			if so.IsPresent {
				secPosture["present_"+so.PropertyName]++
			} else {
				secPosture["absent_"+so.PropertyName]++
			}
		}
	}

	inferredTags := make(map[string]int)
	for _, a := range assets {
		for _, tag := range m.tags[a.ID] {
			if tag.IsInferred {
				inferredTags[tag.Tag]++
			}
		}
	}

	// Recent changes up to 10
	var recentChanges []*models.AssetChange
	limit := len(changes)
	if limit > 10 {
		limit = 10
	}
	for i := len(changes) - 1; i >= 0 && len(recentChanges) < limit; i-- {
		cp := *changes[i]
		recentChanges = append(recentChanges, &cp)
	}

	urls := m.urls[targetID]

	return &models.TargetIntelligenceSummary{
		TargetID:          targetID,
		TotalAssets:       totalAssets,
		ActiveAssets:      activeAssets,
		TotalServices:     len(services),
		TotalTechnologies: len(techs),
		TotalURLs:         len(urls),
		TotalChanges:      len(changes),
		TopCategories:     topCats,
		TopTechnologies:   topTechs,
		SecurityPosture:   secPosture,
		InferredTagsCount: inferredTags,
		RecentChanges:     recentChanges,
	}, nil
}

func (m *MemoryStorage) GetAssetDetail(ctx context.Context, targetID, assetID string) (*models.AssetDetail, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	asset, exists := m.assets[assetID]
	if !exists || asset.TargetID != targetID {
		return nil, ErrNotFound
	}
	assetCp := *asset

	dns := m.dnsRecords[assetID]
	var dnsCp []*models.DNSRecord
	for _, d := range dns {
		cp := *d
		dnsCp = append(dnsCp, &cp)
	}

	var svcs []*models.ServiceObservation
	for _, s := range m.serviceObs[targetID] {
		if s.AssetID == assetID {
			cp := *s
			svcs = append(svcs, &cp)
		}
	}

	var techs []*models.TechnologyObservation
	for _, t := range m.techObs[targetID] {
		if t.AssetID == assetID {
			cp := *t
			techs = append(techs, &cp)
		}
	}

	sec := m.secObs[assetID]
	var secCp []*models.SecurityObservation
	for _, s := range sec {
		cp := *s
		secCp = append(secCp, &cp)
	}

	tags := m.tags[assetID]
	var tagsCp []*models.AssetTag
	for _, t := range tags {
		cp := *t
		tagsCp = append(tagsCp, &cp)
	}

	pageAssets := m.pageAssets[assetID]
	var pageCp []*models.PageAsset
	for _, p := range pageAssets {
		cp := *p
		pageCp = append(pageCp, &cp)
	}

	var urls []*models.URLRecord
	for _, u := range m.urls[targetID] {
		if u.AssetID == assetID {
			cp := *u
			urls = append(urls, &cp)
		}
	}

	var changes []*models.AssetChange
	for _, c := range m.changes[targetID] {
		if c.AssetID == assetID {
			cp := *c
			changes = append(changes, &cp)
		}
	}

	return &models.AssetDetail{
		Asset:                &assetCp,
		DNSRecords:           dnsCp,
		Services:             svcs,
		Technologies:         techs,
		SecurityObservations: secCp,
		Tags:                 tagsCp,
		PageAssets:           pageCp,
		URLs:                 urls,
		Changes:              changes,
	}, nil
}

func (m *MemoryStorage) ListAssetsFiltered(ctx context.Context, filter models.AssetFilter) ([]*models.Asset, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	raw, _ := m.listAssetsInternal(filter.TargetID)
	var matched []*models.Asset

	for _, a := range raw {
		if filter.Hostname != "" && !strings.Contains(strings.ToLower(a.Hostname), strings.ToLower(filter.Hostname)) {
			continue
		}
		if filter.Status != "" && !strings.EqualFold(a.Status, filter.Status) {
			continue
		}
		if filter.Tag != "" {
			hasTag := false
			for _, t := range m.tags[a.ID] {
				if strings.EqualFold(t.Tag, filter.Tag) {
					hasTag = true
					break
				}
			}
			if !hasTag {
				continue
			}
		}
		cp := *a
		matched = append(matched, &cp)
	}

	total := len(matched)
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []*models.Asset{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}

	return matched[offset:end], total, nil
}

func (m *MemoryStorage) listAssetsInternal(targetID string) ([]*models.Asset, error) {
	var result []*models.Asset
	for _, a := range m.assets {
		if a.TargetID == targetID {
			cp := *a
			result = append(result, &cp)
		}
	}
	return result, nil
}

// AIAnalysisRepository implementation

func (m *MemoryStorage) SaveAnalysisRun(ctx context.Context, run *models.AnalysisRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *run
	m.analysisRuns[run.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetAnalysisRun(ctx context.Context, id string) (*models.AnalysisRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	run, exists := m.analysisRuns[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *run
	return &cp, nil
}

func (m *MemoryStorage) ListAnalysisRuns(ctx context.Context, targetID string) ([]*models.AnalysisRun, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var results []*models.AnalysisRun
	for _, r := range m.analysisRuns {
		if targetID == "" || r.TargetID == targetID {
			cp := *r
			results = append(results, &cp)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})
	return results, nil
}

func (m *MemoryStorage) UpdateAnalysisRun(ctx context.Context, run *models.AnalysisRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.analysisRuns[run.ID]; !exists {
		return ErrNotFound
	}
	cp := *run
	m.analysisRuns[run.ID] = &cp
	return nil
}

func (m *MemoryStorage) SaveSecuritySignal(ctx context.Context, signal *models.SecuritySignal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *signal
	m.signals[signal.TargetID] = append(m.signals[signal.TargetID], &cp)
	return nil
}

func (m *MemoryStorage) ListSecuritySignals(ctx context.Context, targetID, assetID string) ([]*models.SecuritySignal, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var results []*models.SecuritySignal
	for _, sig := range m.signals[targetID] {
		if assetID == "" || sig.AssetID == assetID {
			cp := *sig
			results = append(results, &cp)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].DetectedAt.After(results[j].DetectedAt)
	})
	return results, nil
}

func (m *MemoryStorage) SaveFindingCandidate(ctx context.Context, candidate *models.FindingCandidate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *candidate
	m.candidates[candidate.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetFindingCandidate(ctx context.Context, id string) (*models.FindingCandidate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	candidate, exists := m.candidates[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *candidate
	// Attach evidence and signals
	cp.Evidence = m.candidateEvidences[id]
	return &cp, nil
}

func (m *MemoryStorage) ListFindingCandidates(ctx context.Context, filter models.CandidateFilter) ([]*models.FindingCandidate, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var matched []*models.FindingCandidate
	for _, c := range m.candidates {
		if filter.TargetID != "" && c.TargetID != filter.TargetID {
			continue
		}
		if filter.AssetID != "" && c.AssetID != filter.AssetID {
			continue
		}
		if filter.Category != "" && !strings.EqualFold(c.Category, filter.Category) {
			continue
		}
		if filter.State != "" && c.State != filter.State {
			continue
		}
		if filter.Search != "" {
			s := strings.ToLower(filter.Search)
			if !strings.Contains(strings.ToLower(c.Title), s) &&
				!strings.Contains(strings.ToLower(c.Description), s) &&
				!strings.Contains(strings.ToLower(c.Reasoning), s) {
				continue
			}
		}
		cp := *c
		cp.Evidence = m.candidateEvidences[c.ID]
		matched = append(matched, &cp)
	}

	sort.Slice(matched, func(i, j int) bool {
		if matched[i].ConfidenceScore != matched[j].ConfidenceScore {
			return matched[i].ConfidenceScore > matched[j].ConfidenceScore
		}
		return matched[i].CreatedAt.After(matched[j].CreatedAt)
	})

	total := len(matched)
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []*models.FindingCandidate{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}

	return matched[offset:end], total, nil
}

func (m *MemoryStorage) UpdateCandidateState(ctx context.Context, id string, newState models.CandidateState, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	candidate, exists := m.candidates[id]
	if !exists {
		return ErrNotFound
	}
	candidate.State = newState
	candidate.UpdatedAt = time.Now().UTC()
	if reason != "" {
		candidate.Reasoning += fmt.Sprintf("\n[State changed to %s: %s]", newState, reason)
	}
	return nil
}

func (m *MemoryStorage) SaveCandidateEvidence(ctx context.Context, evidence *models.CandidateEvidence) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *evidence
	m.candidateEvidences[evidence.CandidateID] = append(m.candidateEvidences[evidence.CandidateID], &cp)
	return nil
}

func (m *MemoryStorage) ListCandidateEvidence(ctx context.Context, candidateID string) ([]*models.CandidateEvidence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := m.candidateEvidences[candidateID]
	var results []*models.CandidateEvidence
	for _, item := range items {
		cp := *item
		results = append(results, &cp)
	}
	return results, nil
}

// SecurityIntelligenceRepository Implementations

func (m *MemoryStorage) SaveGraphNode(ctx context.Context, node *models.GraphNode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *node
	m.graphNodes[node.ID] = &cp
	return nil
}

func (m *MemoryStorage) SaveGraphEdge(ctx context.Context, edge *models.GraphEdge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *edge
	m.graphEdges[edge.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetTargetGraph(ctx context.Context, targetID string) (*models.GraphData, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var nodes []*models.GraphNode
	for _, n := range m.graphNodes {
		if n.TargetID == targetID {
			cp := *n
			nodes = append(nodes, &cp)
		}
	}

	var edges []*models.GraphEdge
	for _, e := range m.graphEdges {
		if e.TargetID == targetID {
			cp := *e
			edges = append(edges, &cp)
		}
	}

	metrics := make(map[string]int)
	for _, n := range nodes {
		metrics[string(n.Type)]++
	}

	return &models.GraphData{
		TargetID:   targetID,
		Nodes:      nodes,
		Edges:      edges,
		TotalNodes: len(nodes),
		TotalEdges: len(edges),
		Metrics:    metrics,
	}, nil
}

func (m *MemoryStorage) RecordTemporalChange(ctx context.Context, record *models.TemporalChangeRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *record
	m.temporalChanges[record.TargetID] = append([]*models.TemporalChangeRecord{&cp}, m.temporalChanges[record.TargetID]...)
	return nil
}

func (m *MemoryStorage) ListTemporalChanges(ctx context.Context, targetID string, limit int) ([]*models.TemporalChangeRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := m.temporalChanges[targetID]
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	var results []*models.TemporalChangeRecord
	for _, item := range items {
		cp := *item
		results = append(results, &cp)
	}
	return results, nil
}

func (m *MemoryStorage) RecordInvariantSignal(ctx context.Context, sig *models.InvariantSignal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *sig
	m.invariants[sig.TargetID] = append([]*models.InvariantSignal{&cp}, m.invariants[sig.TargetID]...)
	return nil
}

func (m *MemoryStorage) ListInvariantSignals(ctx context.Context, targetID string) ([]*models.InvariantSignal, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := m.invariants[targetID]
	var results []*models.InvariantSignal
	for _, item := range items {
		cp := *item
		results = append(results, &cp)
	}
	return results, nil
}

func (m *MemoryStorage) RecordBehaviorDifference(ctx context.Context, diff *models.BehaviorDifference) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *diff
	m.behaviorDiffs[diff.TargetID] = append([]*models.BehaviorDifference{&cp}, m.behaviorDiffs[diff.TargetID]...)
	return nil
}

func (m *MemoryStorage) ListBehaviorDifferences(ctx context.Context, targetID string) ([]*models.BehaviorDifference, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := m.behaviorDiffs[targetID]
	var results []*models.BehaviorDifference
	for _, item := range items {
		cp := *item
		results = append(results, &cp)
	}
	return results, nil
}

func (m *MemoryStorage) SaveInvestigationCluster(ctx context.Context, cluster *models.InvestigationCluster) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *cluster
	m.clusters[cluster.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetInvestigationCluster(ctx context.Context, id string) (*models.InvestigationCluster, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, exists := m.clusters[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (m *MemoryStorage) ListInvestigationClusters(ctx context.Context, targetID string) ([]*models.InvestigationCluster, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var results []*models.InvestigationCluster
	for _, c := range m.clusters {
		if c.TargetID == targetID {
			cp := *c
			results = append(results, &cp)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].PriorityScore > results[j].PriorityScore
	})
	return results, nil
}

func (m *MemoryStorage) UpdateClusterStatus(ctx context.Context, id string, status models.ClusterStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, exists := m.clusters[id]
	if !exists {
		return ErrNotFound
	}
	c.Status = status
	c.UpdatedAt = time.Now().UTC()
	return nil
}

func (m *MemoryStorage) GetResearchMemory(ctx context.Context, targetID string) (*models.ResearchMemory, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var assetCount int
	for _, a := range m.assets {
		if a.TargetID == targetID {
			assetCount++
		}
	}

	var endpointCount int
	if urls, ok := m.urls[targetID]; ok {
		endpointCount = len(urls)
	}

	techs := m.techObs[targetID]
	changes := m.temporalChanges[targetID]

	var activeClusters []*models.InvestigationCluster
	for _, c := range m.clusters {
		if c.TargetID == targetID && (c.Status == models.ClusterStatusActive || c.Status == models.ClusterStatusInvestigating) {
			cp := *c
			activeClusters = append(activeClusters, &cp)
		}
	}

	var validatedCount, rejectedCount int
	for _, cand := range m.candidates {
		if cand.TargetID == targetID {
			if cand.State == models.CandidateStateReported || cand.State == models.CandidateStateResolved || cand.State == models.CandidateStateValidated {
				validatedCount++
			} else if cand.State == models.CandidateStateDismissed || cand.State == models.CandidateStateRejected {
				rejectedCount++
			}
		}
	}

	recent := changes
	if len(recent) > 10 {
		recent = recent[:10]
	}

	return &models.ResearchMemory{
		TargetID:                  targetID,
		KnownAssetsCount:          assetCount,
		KnownEndpointsCount:       endpointCount,
		KnownTechnologiesCount:   len(techs),
		TotalHistoricalChanges:   len(changes),
		ActiveInvestigationsCount: len(activeClusters),
		ValidatedFindingsCount:   validatedCount,
		RejectedCandidatesCount:  rejectedCount,
		RecentWhatChanged:        recent,
		DeservesReinvestigation:  activeClusters,
		LastScanAt:               time.Now().UTC(),
	}, nil
}

func (m *MemoryStorage) RecordValidationResult(ctx context.Context, result *models.ControlledValidationResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *result
	key := result.CandidateID
	if key == "" {
		key = result.ClusterID
	}
	m.validationResults[key] = append(m.validationResults[key], &cp)
	return nil
}

// --- Phase 6 Evidence Intelligence & Security Reasoning Operations ---

func (m *MemoryStorage) SaveEvidence(ctx context.Context, ev *models.Evidence) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *ev
	m.evidenceRecords[ev.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetEvidence(ctx context.Context, id string) (*models.Evidence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ev, ok := m.evidenceRecords[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *ev
	return &cp, nil
}

func (m *MemoryStorage) ListEvidenceByTarget(ctx context.Context, targetID string) ([]*models.Evidence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.Evidence
	for _, ev := range m.evidenceRecords {
		if ev.TargetID == targetID {
			cp := *ev
			res = append(res, &cp)
		}
	}
	return res, nil
}

func (m *MemoryStorage) ListEvidenceByAsset(ctx context.Context, assetID string) ([]*models.Evidence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.Evidence
	for _, ev := range m.evidenceRecords {
		if ev.AssetID == assetID {
			cp := *ev
			res = append(res, &cp)
		}
	}
	return res, nil
}

func (m *MemoryStorage) ListEvidenceByObservation(ctx context.Context, obsID string) ([]*models.Evidence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.Evidence
	for _, ev := range m.evidenceRecords {
		if ev.ObservationID == obsID {
			cp := *ev
			res = append(res, &cp)
		}
	}
	return res, nil
}

func (m *MemoryStorage) SaveEvidenceDiff(ctx context.Context, diff *models.EvidenceDiff) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *diff
	m.evidenceDiffs[diff.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetEvidenceDiff(ctx context.Context, id string) (*models.EvidenceDiff, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	diff, ok := m.evidenceDiffs[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *diff
	return &cp, nil
}

func (m *MemoryStorage) ListEvidenceDiffs(ctx context.Context, targetID string) ([]*models.EvidenceDiff, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.EvidenceDiff
	for _, diff := range m.evidenceDiffs {
		if diff.TargetID == targetID {
			cp := *diff
			res = append(res, &cp)
		}
	}
	return res, nil
}

func (m *MemoryStorage) SaveSecurityExpectation(ctx context.Context, exp *models.SecurityExpectation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *exp
	m.securityExpectations[exp.TargetID] = append(m.securityExpectations[exp.TargetID], &cp)
	return nil
}

func (m *MemoryStorage) ListSecurityExpectations(ctx context.Context, targetID, assetID string) ([]*models.SecurityExpectation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.SecurityExpectation
	for _, exp := range m.securityExpectations[targetID] {
		if assetID == "" || exp.AssetID == assetID {
			cp := *exp
			res = append(res, &cp)
		}
	}
	return res, nil
}

func (m *MemoryStorage) SaveSecurityContradiction(ctx context.Context, con *models.SecurityContradiction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *con
	m.contradictions[con.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetSecurityContradiction(ctx context.Context, id string) (*models.SecurityContradiction, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	con, ok := m.contradictions[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *con
	return &cp, nil
}

func (m *MemoryStorage) ListSecurityContradictions(ctx context.Context, targetID, assetID string) ([]*models.SecurityContradiction, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.SecurityContradiction
	for _, con := range m.contradictions {
		if con.TargetID == targetID {
			if assetID == "" || con.AssetID == assetID {
				cp := *con
				res = append(res, &cp)
			}
		}
	}
	return res, nil
}

func (m *MemoryStorage) SaveSecurityOutlier(ctx context.Context, out *models.SecurityOutlier) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *out
	m.outliers[out.TargetID] = append(m.outliers[out.TargetID], &cp)
	return nil
}

func (m *MemoryStorage) ListSecurityOutliers(ctx context.Context, targetID, assetID string) ([]*models.SecurityOutlier, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.SecurityOutlier
	for _, out := range m.outliers[targetID] {
		if assetID == "" || out.AssetID == assetID {
			cp := *out
			res = append(res, &cp)
		}
	}
	return res, nil
}

func (m *MemoryStorage) RecordTimelineEvent(ctx context.Context, ev *models.EvidenceTimelineEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *ev
	m.timelineEvents = append(m.timelineEvents, &cp)
	return nil
}

func (m *MemoryStorage) ListTimelineEvents(ctx context.Context, targetID, assetID string, limit int) ([]*models.EvidenceTimelineEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit <= 0 {
		limit = 50
	}
	var res []*models.EvidenceTimelineEvent
	for i := len(m.timelineEvents) - 1; i >= 0; i-- {
		item := m.timelineEvents[i]
		if targetID != "" && item.TargetID != targetID {
			continue
		}
		if assetID != "" && item.AssetID != assetID {
			continue
		}
		cp := *item
		res = append(res, &cp)
		if len(res) >= limit {
			break
		}
	}
	return res, nil
}

// Phase 7 ReasoningRepository Implementation

func (m *MemoryStorage) SaveReasoningSignal(ctx context.Context, sig *models.ReasoningSignal) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *sig
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	cp.UpdatedAt = time.Now()
	m.reasoningSignals[cp.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetReasoningSignal(ctx context.Context, id string) (*models.ReasoningSignal, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sig, exists := m.reasoningSignals[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *sig
	return &cp, nil
}

func (m *MemoryStorage) ListReasoningSignals(ctx context.Context, targetID, assetID string) ([]*models.ReasoningSignal, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.ReasoningSignal
	for _, sig := range m.reasoningSignals {
		if targetID != "" && sig.TargetID != targetID {
			continue
		}
		if assetID != "" && sig.AssetID != assetID {
			continue
		}
		cp := *sig
		res = append(res, &cp)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].CreatedAt.After(res[j].CreatedAt)
	})
	return res, nil
}

func (m *MemoryStorage) UpdateSignalStatus(ctx context.Context, id string, status models.SignalStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sig, exists := m.reasoningSignals[id]
	if !exists {
		return ErrNotFound
	}
	sig.Status = status
	sig.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStorage) SaveHypothesisGroup(ctx context.Context, group *models.HypothesisGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *group
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	cp.UpdatedAt = time.Now()
	m.hypothesisGroups[cp.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetHypothesisGroup(ctx context.Context, id string) (*models.HypothesisGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	grp, exists := m.hypothesisGroups[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *grp
	// Populate hypotheses inside group
	for _, hyp := range m.hypotheses {
		if hyp.GroupID == cp.ID {
			hcp := *hyp
			hcp.FalsificationConditions = m.copyFalsifications(hyp.ID)
			hcp.MissingEvidence = m.copyRequirements(hyp.ID)
			cp.Hypotheses = append(cp.Hypotheses, hcp)
		}
	}
	return &cp, nil
}

func (m *MemoryStorage) ListHypothesisGroups(ctx context.Context, targetID string) ([]*models.HypothesisGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.HypothesisGroup
	for _, grp := range m.hypothesisGroups {
		if targetID != "" && grp.TargetID != targetID {
			continue
		}
		cp := *grp
		for _, hyp := range m.hypotheses {
			if hyp.GroupID == cp.ID {
				hcp := *hyp
				hcp.FalsificationConditions = m.copyFalsifications(hyp.ID)
				hcp.MissingEvidence = m.copyRequirements(hyp.ID)
				cp.Hypotheses = append(cp.Hypotheses, hcp)
			}
		}
		res = append(res, &cp)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].CreatedAt.After(res[j].CreatedAt)
	})
	return res, nil
}

func (m *MemoryStorage) SaveHypothesis(ctx context.Context, hyp *models.Hypothesis) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *hyp
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	cp.UpdatedAt = time.Now()
	m.hypotheses[cp.ID] = &cp

	// Save sub-objects if provided
	if len(hyp.FalsificationConditions) > 0 {
		for _, f := range hyp.FalsificationConditions {
			fcp := f
			m.falsifications[hyp.ID] = append(m.falsifications[hyp.ID], &fcp)
		}
	}
	if len(hyp.MissingEvidence) > 0 {
		for _, req := range hyp.MissingEvidence {
			rcp := req
			m.evidenceRequirements[hyp.ID] = append(m.evidenceRequirements[hyp.ID], &rcp)
		}
	}
	return nil
}

func (m *MemoryStorage) GetHypothesis(ctx context.Context, id string) (*models.Hypothesis, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	hyp, exists := m.hypotheses[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *hyp
	cp.FalsificationConditions = m.copyFalsifications(id)
	cp.MissingEvidence = m.copyRequirements(id)
	return &cp, nil
}

func (m *MemoryStorage) ListHypotheses(ctx context.Context, targetID string) ([]*models.Hypothesis, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.Hypothesis
	for _, hyp := range m.hypotheses {
		if targetID != "" && hyp.TargetID != targetID {
			continue
		}
		cp := *hyp
		cp.FalsificationConditions = m.copyFalsifications(hyp.ID)
		cp.MissingEvidence = m.copyRequirements(hyp.ID)
		res = append(res, &cp)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].InvestigationPriority > res[j].InvestigationPriority
	})
	return res, nil
}

func (m *MemoryStorage) ListHypothesesByGroup(ctx context.Context, groupID string) ([]*models.Hypothesis, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.Hypothesis
	for _, hyp := range m.hypotheses {
		if hyp.GroupID != groupID {
			continue
		}
		cp := *hyp
		cp.FalsificationConditions = m.copyFalsifications(hyp.ID)
		cp.MissingEvidence = m.copyRequirements(hyp.ID)
		res = append(res, &cp)
	}
	return res, nil
}

func (m *MemoryStorage) UpdateHypothesisStatus(ctx context.Context, id string, status models.HypothesisStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	hyp, exists := m.hypotheses[id]
	if !exists {
		return ErrNotFound
	}
	hyp.Status = status
	hyp.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStorage) SaveFalsificationCondition(ctx context.Context, cond *models.FalsificationCondition) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *cond
	m.falsifications[cond.HypothesisID] = append(m.falsifications[cond.HypothesisID], &cp)
	return nil
}

func (m *MemoryStorage) ListFalsificationConditions(ctx context.Context, hypothesisID string) ([]*models.FalsificationCondition, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.FalsificationCondition
	for _, item := range m.falsifications[hypothesisID] {
		cp := *item
		res = append(res, &cp)
	}
	return res, nil
}

func (m *MemoryStorage) SaveEvidenceRequirement(ctx context.Context, req *models.EvidenceRequirement) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *req
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	m.evidenceRequirements[req.HypothesisID] = append(m.evidenceRequirements[req.HypothesisID], &cp)
	return nil
}

func (m *MemoryStorage) ListEvidenceRequirements(ctx context.Context, hypothesisID string) ([]*models.EvidenceRequirement, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.EvidenceRequirement
	for _, item := range m.evidenceRequirements[hypothesisID] {
		cp := *item
		res = append(res, &cp)
	}
	return res, nil
}

func (m *MemoryStorage) UpdateEvidenceRequirementStatus(ctx context.Context, id string, status models.RequirementStatus, satisfiedRef string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, list := range m.evidenceRequirements {
		for _, req := range list {
			if req.ID == id {
				req.Status = status
				if satisfiedRef != "" {
					req.SatisfiedByRef = satisfiedRef
				}
				return nil
			}
		}
	}
	return ErrNotFound
}

func (m *MemoryStorage) SaveInvestigation(ctx context.Context, inv *models.Investigation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *inv
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	m.investigations[cp.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetInvestigation(ctx context.Context, id string) (*models.Investigation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	inv, exists := m.investigations[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *inv
	return &cp, nil
}

func (m *MemoryStorage) ListInvestigations(ctx context.Context, targetID string) ([]*models.Investigation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.Investigation
	for _, inv := range m.investigations {
		if targetID != "" && inv.TargetID != targetID {
			continue
		}
		cp := *inv
		res = append(res, &cp)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].CreatedAt.After(res[j].CreatedAt)
	})
	return res, nil
}

func (m *MemoryStorage) UpdateInvestigationStatus(ctx context.Context, id string, status models.InvestigationStatus, result string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, exists := m.investigations[id]
	if !exists {
		return ErrNotFound
	}
	inv.Status = status
	if result != "" {
		inv.ResultSummary = result
	}
	if status == models.InvStatusCompleted || status == models.InvStatusCancelled || status == models.InvStatusFailed {
		now := time.Now()
		inv.CompletedAt = &now
	}
	return nil
}

func (m *MemoryStorage) SaveTrustBoundary(ctx context.Context, tb *models.TrustBoundary) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *tb
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	m.trustBoundaries[cp.TargetID] = append(m.trustBoundaries[cp.TargetID], &cp)
	return nil
}

func (m *MemoryStorage) ListTrustBoundaries(ctx context.Context, targetID, assetID string) ([]*models.TrustBoundary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.TrustBoundary
	for _, tb := range m.trustBoundaries[targetID] {
		if assetID != "" && tb.AssetID != assetID {
			continue
		}
		cp := *tb
		res = append(res, &cp)
	}
	return res, nil
}

func (m *MemoryStorage) SaveAuthContext(ctx context.Context, ac *models.AuthContext) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *ac
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	m.authContexts[cp.TargetID] = append(m.authContexts[cp.TargetID], &cp)
	return nil
}

func (m *MemoryStorage) ListAuthContexts(ctx context.Context, targetID string) ([]*models.AuthContext, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.AuthContext
	for _, ac := range m.authContexts[targetID] {
		cp := *ac
		res = append(res, &cp)
	}
	return res, nil
}

func (m *MemoryStorage) SavePermissionMatrixEntry(ctx context.Context, entry *models.PermissionMatrixEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *entry
	if cp.ObservedAt.IsZero() {
		cp.ObservedAt = time.Now()
	}
	m.permissionMatrix[cp.TargetID] = append(m.permissionMatrix[cp.TargetID], &cp)
	return nil
}

func (m *MemoryStorage) ListPermissionMatrix(ctx context.Context, targetID, assetID string) ([]*models.PermissionMatrixEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.PermissionMatrixEntry
	for _, entry := range m.permissionMatrix[targetID] {
		if assetID != "" && entry.AssetID != assetID {
			continue
		}
		cp := *entry
		res = append(res, &cp)
	}
	return res, nil
}

func (m *MemoryStorage) SaveSecurityControl(ctx context.Context, sc *models.SecurityControlRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *sc
	if cp.EvaluatedAt.IsZero() {
		cp.EvaluatedAt = time.Now()
	}
	m.securityControls[cp.TargetID] = append(m.securityControls[cp.TargetID], &cp)
	return nil
}

func (m *MemoryStorage) ListSecurityControls(ctx context.Context, targetID, assetID string) ([]*models.SecurityControlRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.SecurityControlRecord
	for _, sc := range m.securityControls[targetID] {
		if assetID != "" && sc.AssetID != assetID {
			continue
		}
		cp := *sc
		res = append(res, &cp)
	}
	return res, nil
}

func (m *MemoryStorage) RecordReasoningRun(ctx context.Context, run *models.ReasoningRun) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *run
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	m.reasoningRuns[cp.ID] = &cp
	return nil
}

func (m *MemoryStorage) copyFalsifications(hypoID string) []models.FalsificationCondition {
	var res []models.FalsificationCondition
	for _, item := range m.falsifications[hypoID] {
		res = append(res, *item)
	}
	return res
}

func (m *MemoryStorage) copyRequirements(hypoID string) []models.EvidenceRequirement {
	var res []models.EvidenceRequirement
	for _, item := range m.evidenceRequirements[hypoID] {
		res = append(res, *item)
	}
	return res
}

// ==========================================
// Phase 8: Scope Import Repository
// ==========================================

func (m *MemoryStorage) SaveImportReview(ctx context.Context, review *models.ScopeImportReview) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *review
	m.scopeImports[review.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetImportReview(ctx context.Context, id string) (*models.ScopeImportReview, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rev, exists := m.scopeImports[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *rev
	return &cp, nil
}

func (m *MemoryStorage) ListImportReviews(ctx context.Context) ([]*models.ScopeImportReview, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.ScopeImportReview
	for _, rev := range m.scopeImports {
		cp := *rev
		res = append(res, &cp)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].CreatedAt.After(res[j].CreatedAt)
	})
	return res, nil
}

func (m *MemoryStorage) ConfirmImportReview(ctx context.Context, id string, selectedRootDomain string, targetID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rev, exists := m.scopeImports[id]
	if !exists {
		return ErrNotFound
	}
	if rev.Status == "CONFIRMED" {
		return ErrInvalidState
	}
	now := time.Now().UTC()
	rev.Status = "CONFIRMED"
	rev.SelectedRootDomain = selectedRootDomain
	rev.TargetID = targetID
	rev.ConfirmedAt = &now
	return nil
}

// ==========================================
// Phase 8: JavaScript Intelligence Repository
// ==========================================

func (m *MemoryStorage) SaveJSAsset(ctx context.Context, asset *models.JSAsset) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *asset
	m.jsAssets[asset.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetJSAsset(ctx context.Context, id string) (*models.JSAsset, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	asset, exists := m.jsAssets[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *asset
	return &cp, nil
}

func (m *MemoryStorage) ListJSAssets(ctx context.Context, targetID, assetID string) ([]*models.JSAsset, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.JSAsset
	for _, a := range m.jsAssets {
		if a.TargetID == targetID {
			if assetID == "" || a.AssetID == assetID {
				cp := *a
				res = append(res, &cp)
			}
		}
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].DiscoveredAt.After(res[j].DiscoveredAt)
	})
	return res, nil
}

func (m *MemoryStorage) SaveJSReference(ctx context.Context, ref *models.JSReference) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *ref
	m.jsReferences[ref.TargetID] = append(m.jsReferences[ref.TargetID], &cp)
	return nil
}

func (m *MemoryStorage) ListJSReferences(ctx context.Context, targetID, jsAssetID string) ([]*models.JSReference, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.JSReference
	for _, ref := range m.jsReferences[targetID] {
		if jsAssetID == "" || ref.JSAssetID == jsAssetID {
			cp := *ref
			res = append(res, &cp)
		}
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].CreatedAt.After(res[j].CreatedAt)
	})
	return res, nil
}

func (m *MemoryStorage) SaveSecretIndicator(ctx context.Context, sec *models.JSSecretIndicator) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *sec
	m.jsSecrets[sec.TargetID] = append(m.jsSecrets[sec.TargetID], &cp)
	return nil
}

func (m *MemoryStorage) ListSecretIndicators(ctx context.Context, targetID, assetID string) ([]*models.JSSecretIndicator, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.JSSecretIndicator
	for _, sec := range m.jsSecrets[targetID] {
		if assetID == "" || sec.AssetID == assetID {
			cp := *sec
			res = append(res, &cp)
		}
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].CreatedAt.After(res[j].CreatedAt)
	})
	return res, nil
}

// ==========================================
// Phase 8: Cloud Reference Intelligence Repository
// ==========================================

func (m *MemoryStorage) SaveCloudReference(ctx context.Context, ref *models.CloudReference) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *ref
	m.cloudReferences[ref.TargetID] = append(m.cloudReferences[ref.TargetID], &cp)
	return nil
}

func (m *MemoryStorage) GetCloudReference(ctx context.Context, id string) (*models.CloudReference, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, refs := range m.cloudReferences {
		for _, r := range refs {
			if r.ID == id {
				cp := *r
				return &cp, nil
			}
		}
	}
	return nil, ErrNotFound
}

func (m *MemoryStorage) ListCloudReferences(ctx context.Context, targetID, assetID string) ([]*models.CloudReference, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.CloudReference
	for _, ref := range m.cloudReferences[targetID] {
		if assetID == "" || ref.AssetID == assetID {
			cp := *ref
			res = append(res, &cp)
		}
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].CreatedAt.After(res[j].CreatedAt)
	})
	return res, nil
}

func (m *MemoryStorage) UpdateCloudValidation(ctx context.Context, id string, status string, statusCode int, publicAccessible bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, refs := range m.cloudReferences {
		for _, r := range refs {
			if r.ID == id {
				r.ValidationStatus = status
				r.StatusCode = statusCode
				r.PublicAccessible = publicAccessible
				return nil
			}
		}
	}
	return ErrNotFound
}

// ==========================================
// Phase 8: WAF Intelligence Repository
// ==========================================

func (m *MemoryStorage) SaveWAFObservation(ctx context.Context, obs *models.WAFObservation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%s:%s", obs.TargetID, obs.AssetID)
	cp := *obs
	m.wafObservations[key] = &cp
	return nil
}

func (m *MemoryStorage) GetWAFObservation(ctx context.Context, targetID, assetID string) (*models.WAFObservation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := fmt.Sprintf("%s:%s", targetID, assetID)
	obs, exists := m.wafObservations[key]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *obs
	return &cp, nil
}

func (m *MemoryStorage) ListWAFObservations(ctx context.Context, targetID string) ([]*models.WAFObservation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.WAFObservation
	for _, obs := range m.wafObservations {
		if obs.TargetID == targetID {
			cp := *obs
			res = append(res, &cp)
		}
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].CreatedAt.After(res[j].CreatedAt)
	})
	return res, nil
}

// ==========================================
// Phase 8: Hunting Planner Repository
// ==========================================

func (m *MemoryStorage) SaveInvestigationPlan(ctx context.Context, plan *models.InvestigationPlan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *plan
	m.investigationPlans[plan.ID] = &cp
	return nil
}

func (m *MemoryStorage) GetInvestigationPlan(ctx context.Context, id string) (*models.InvestigationPlan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, exists := m.investigationPlans[id]
	if !exists {
		return nil, ErrNotFound
	}
	cp := *p
	return &cp, nil
}

func (m *MemoryStorage) ListInvestigationPlans(ctx context.Context, targetID, assetID string) ([]*models.InvestigationPlan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.InvestigationPlan
	for _, p := range m.investigationPlans {
		if p.TargetID == targetID {
			if assetID == "" || p.AssetID == assetID {
				cp := *p
				res = append(res, &cp)
			}
		}
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].CreatedAt.After(res[j].CreatedAt)
	})
	return res, nil
}

func (m *MemoryStorage) ApprovePlanStep(ctx context.Context, planID string, stepNumber int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	plan, exists := m.investigationPlans[planID]
	if !exists {
		return ErrNotFound
	}
	for i := range plan.Steps {
		if plan.Steps[i].StepNumber == stepNumber {
			now := time.Now().UTC()
			plan.Steps[i].ApprovedByHuman = true
			plan.Steps[i].ApprovedAt = &now
			plan.Steps[i].Status = "APPROVED"
			plan.Status = "APPROVED"
			plan.UpdatedAt = now
			return nil
		}
	}
	return ErrNotFound
}

func (m *MemoryStorage) UpdatePlanStatus(ctx context.Context, planID string, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	plan, exists := m.investigationPlans[planID]
	if !exists {
		return ErrNotFound
	}
	plan.Status = status
	plan.UpdatedAt = time.Now().UTC()
	return nil
}
