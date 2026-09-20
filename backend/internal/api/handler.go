package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/ai"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/config"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/intel"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/jobs"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/reasoning"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/recon"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/storage"
)

// Handler houses all HTTP endpoints for the NexusHunter-AI API.
type Handler struct {
	cfg          *config.Config
	storage      storage.TargetRepository
	scopeSvc     scope.ScopeService
	jobSvc       jobs.JobService
	eventBus     events.EventBus
	reconEngine  recon.ReconEngine
	reconRepo    storage.ReconRepository
	intelRepo    storage.AssetIntelligenceRepository
	analysisRepo storage.AIAnalysisRepository
	aiService    ai.Service
	secRepo      storage.SecurityIntelligenceRepository
	secEngine    *intel.SecurityIntelligenceEngine
	evidenceRepo storage.EvidenceRepository
	evidenceEng  interface {
		RecordEvidence(ctx context.Context, raw *models.Evidence) (*models.Evidence, error)
		CompareEvidence(ctx context.Context, evidenceAID, evidenceBID string, filterNoise bool) (*models.EvidenceDiff, error)
		EvaluateContradiction(ctx context.Context, targetID, assetID, endpoint string, expected *models.SecurityExpectation, observedState models.EpistemicObservationState, evidenceRefs []string) (*models.SecurityContradiction, error)
		SynthesizeAssetInterest(ctx context.Context, targetID, assetID, hostname string) (*models.AssetInterestSummary, error)
		VerifyEvidenceIntegrity(ctx context.Context, evidenceID string) (*models.EvidenceIntegrityResult, error)
	}
	reasoningRepo storage.ReasoningRepository
	reasoningEng  *reasoning.Engine
}

// NewHandler initializes API handlers with required dependencies.
func NewHandler(
	cfg *config.Config,
	targetStorage storage.TargetRepository,
	scopeSvc scope.ScopeService,
	jobSvc jobs.JobService,
	eventBus events.EventBus,
	reconEngine recon.ReconEngine,
	reconRepo storage.ReconRepository,
	intelRepo storage.AssetIntelligenceRepository,
	analysisRepo storage.AIAnalysisRepository,
	aiService ai.Service,
) *Handler {
	return &Handler{
		cfg:          cfg,
		storage:      targetStorage,
		scopeSvc:     scopeSvc,
		jobSvc:       jobSvc,
		eventBus:     eventBus,
		reconEngine:  reconEngine,
		reconRepo:    reconRepo,
		intelRepo:    intelRepo,
		analysisRepo: analysisRepo,
		aiService:    aiService,
	}
}

// SetSecurityIntelligence binds the security intelligence repository and validation engine.
func (h *Handler) SetSecurityIntelligence(secRepo storage.SecurityIntelligenceRepository, secEngine *intel.SecurityIntelligenceEngine) {
	h.secRepo = secRepo
	h.secEngine = secEngine
}

// SetEvidenceIntelligence binds the evidence intelligence repository and engine.
func (h *Handler) SetEvidenceIntelligence(evidenceRepo storage.EvidenceRepository, evidenceEng interface {
	RecordEvidence(ctx context.Context, raw *models.Evidence) (*models.Evidence, error)
	CompareEvidence(ctx context.Context, evidenceAID, evidenceBID string, filterNoise bool) (*models.EvidenceDiff, error)
	EvaluateContradiction(ctx context.Context, targetID, assetID, endpoint string, expected *models.SecurityExpectation, observedState models.EpistemicObservationState, evidenceRefs []string) (*models.SecurityContradiction, error)
	SynthesizeAssetInterest(ctx context.Context, targetID, assetID, hostname string) (*models.AssetInterestSummary, error)
	VerifyEvidenceIntegrity(ctx context.Context, evidenceID string) (*models.EvidenceIntegrityResult, error)
}) {
	h.evidenceRepo = evidenceRepo
	h.evidenceEng = evidenceEng
}

// SetReasoningIntelligence binds the reasoning repository and engine.
func (h *Handler) SetReasoningIntelligence(reasoningRepo storage.ReasoningRepository, reasoningEng *reasoning.Engine) {
	h.reasoningRepo = reasoningRepo
	h.reasoningEng = reasoningEng
}

// HealthCheck handles GET /api/health
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	JSON(w, http.StatusOK, map[string]interface{}{
		"status":  "ok",
		"service": h.cfg.ServiceName,
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

// Version handles GET /api/version
func (h *Handler) Version(w http.ResponseWriter, r *http.Request) {
	JSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"service":     h.cfg.ServiceName,
		"version":     h.cfg.Version,
		"environment": h.cfg.AppEnv,
	})
}

// CreateTargetRequest represents the payload to register a new target.
type CreateTargetRequest struct {
	Name               string   `json:"name"`
	RootDomain         string   `json:"root_domain"`
	AllowedDomains     []string `json:"allowed_domains"`
	AllowedURLPatterns []string `json:"allowed_url_patterns"`
	ExcludedPatterns   []string `json:"excluded_patterns"`
}

// CreateTarget handles POST /api/targets
func (h *Handler) CreateTarget(w http.ResponseWriter, r *http.Request) {
	var req CreateTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "INVALID_PAYLOAD", "failed to parse JSON body", err.Error())
		return
	}

	target := &models.Target{
		ID:                 events.GenerateID("tgt"),
		Name:               strings.TrimSpace(req.Name),
		RootDomain:         strings.ToLower(strings.TrimSpace(req.RootDomain)),
		AllowedDomains:     cleanStringSlice(req.AllowedDomains),
		AllowedURLPatterns: cleanStringSlice(req.AllowedURLPatterns),
		ExcludedPatterns:   cleanStringSlice(req.ExcludedPatterns),
		Status:             models.TargetStatusActive,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
	}

	// Strict Fail-Closed Validation
	if err := h.scopeSvc.ValidateTarget(target); err != nil {
		Error(w, http.StatusUnprocessableEntity, "VALIDATION_FAILED", "target definition failed strict authorization validation", err.Error())
		return
	}

	if err := h.storage.Create(r.Context(), target); err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to store target", err.Error())
		return
	}

	Success(w, http.StatusCreated, target)
}

// ListTargets handles GET /api/targets
func (h *Handler) ListTargets(w http.ResponseWriter, r *http.Request) {
	list, err := h.storage.List(r.Context())
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to retrieve targets", err.Error())
		return
	}
	Success(w, http.StatusOK, list)
}

// GetTarget handles GET /api/targets/{id}
func (h *Handler) GetTarget(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		// Fallback for custom routing
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}

	target, err := h.storage.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			Error(w, http.StatusNotFound, "TARGET_NOT_FOUND", "target with specified id does not exist", id)
			return
		}
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to retrieve target", err.Error())
		return
	}

	Success(w, http.StatusOK, target)
}

// DeleteTarget handles DELETE /api/targets/{id}
func (h *Handler) DeleteTarget(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}

	if err := h.storage.Delete(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			Error(w, http.StatusNotFound, "TARGET_NOT_FOUND", "target with specified id does not exist", id)
			return
		}
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to delete target", err.Error())
		return
	}

	Success(w, http.StatusOK, map[string]string{
		"message": "target deleted successfully",
		"id":      id,
	})
}

// VerifyScopeRequest represents an interactive scope query.
type VerifyScopeRequest struct {
	TargetID string `json:"target_id"`
	Hostname string `json:"hostname"`
	URL      string `json:"url"`
}

// VerifyScope handles POST /api/scope/verify
func (h *Handler) VerifyScope(w http.ResponseWriter, r *http.Request) {
	var req VerifyScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "INVALID_PAYLOAD", "failed to parse JSON body", err.Error())
		return
	}

	if req.TargetID == "" {
		Error(w, http.StatusBadRequest, "MISSING_TARGET_ID", "target_id is required", "")
		return
	}

	target, err := h.storage.GetByID(r.Context(), req.TargetID)
	if err != nil {
		Error(w, http.StatusNotFound, "TARGET_NOT_FOUND", "target not found", req.TargetID)
		return
	}

	decision := h.scopeSvc.Evaluate(target, req.Hostname, req.URL)
	Success(w, http.StatusOK, decision)
}

// CreateJobRequest represents a payload to enqueue a scan job.
type CreateJobRequest struct {
	TargetID string                 `json:"target_id"`
	Type     string                 `json:"type"`
	Metadata map[string]interface{} `json:"metadata"`
}

// CreateJob handles POST /api/jobs
func (h *Handler) CreateJob(w http.ResponseWriter, r *http.Request) {
	var req CreateJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "INVALID_PAYLOAD", "failed to parse JSON body", err.Error())
		return
	}

	// Validate target exists and is active before creating a job
	target, err := h.storage.GetByID(r.Context(), req.TargetID)
	if err != nil {
		Error(w, http.StatusNotFound, "TARGET_NOT_FOUND", "target not found", req.TargetID)
		return
	}
	if target.Status != models.TargetStatusActive {
		Error(w, http.StatusForbidden, "TARGET_INACTIVE", "cannot enqueue scan job on inactive target", string(target.Status))
		return
	}

	job, err := h.jobSvc.CreateJob(r.Context(), req.TargetID, req.Type, req.Metadata)
	if err != nil {
		Error(w, http.StatusBadRequest, "JOB_CREATION_FAILED", err.Error(), "")
		return
	}

	Success(w, http.StatusCreated, job)
}

// ListJobs handles GET /api/jobs
func (h *Handler) ListJobs(w http.ResponseWriter, r *http.Request) {
	targetID := r.URL.Query().Get("target_id")
	jobsList, err := h.jobSvc.ListJobs(r.Context(), targetID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list jobs", err.Error())
		return
	}
	Success(w, http.StatusOK, jobsList)
}

// GetJob handles GET /api/jobs/{id}
func (h *Handler) GetJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}

	job, err := h.jobSvc.GetJob(r.Context(), id)
	if err != nil {
		Error(w, http.StatusNotFound, "JOB_NOT_FOUND", "scan job not found", id)
		return
	}
	Success(w, http.StatusOK, job)
}

// ListEvents handles GET /api/events
func (h *Handler) ListEvents(w http.ResponseWriter, r *http.Request) {
	recent := h.eventBus.GetRecentEvents(50)
	Success(w, http.StatusOK, recent)
}

// StartReconRequest defines the body for POST /api/recon
type StartReconRequest struct {
	TargetID string             `json:"target_id"`
	Options  recon.ReconOptions `json:"options"`
}

// StartRecon handles POST /api/recon
func (h *Handler) StartRecon(w http.ResponseWriter, r *http.Request) {
	if h.reconEngine == nil {
		Error(w, http.StatusNotImplemented, "ENGINE_UNAVAILABLE", "recon engine is not configured", "")
		return
	}

	var req StartReconRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "INVALID_PAYLOAD", "failed to parse JSON body", err.Error())
		return
	}

	if req.TargetID == "" {
		Error(w, http.StatusBadRequest, "MISSING_TARGET_ID", "target_id is required", "")
		return
	}

	// Default to enabled stages if none specified
	if !req.Options.SubdomainDiscovery && !req.Options.DNSResolution && !req.Options.HTTPProbe && !req.Options.Crawl {
		req.Options = recon.DefaultOptions()
	}

	job, err := h.reconEngine.StartRecon(r.Context(), req.TargetID, req.Options)
	if err != nil {
		if errors.Is(err, recon.ErrTargetNotFound) {
			Error(w, http.StatusNotFound, "TARGET_NOT_FOUND", "target not found", req.TargetID)
			return
		}
		if errors.Is(err, jobs.ErrTargetNotActive) {
			Error(w, http.StatusForbidden, "TARGET_INACTIVE", "cannot enqueue recon job on inactive target", "")
			return
		}
		Error(w, http.StatusUnprocessableEntity, "SCOPE_VIOLATION", err.Error(), "")
		return
	}

	Success(w, http.StatusAccepted, job)
}

// GetReconRun handles GET /api/recon/{id}
func (h *Handler) GetReconRun(w http.ResponseWriter, r *http.Request) {
	if h.reconEngine == nil {
		Error(w, http.StatusNotImplemented, "ENGINE_UNAVAILABLE", "recon engine is not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}

	run, err := h.reconEngine.GetRun(r.Context(), id)
	if err != nil {
		if errors.Is(err, recon.ErrReconRunNotFound) {
			Error(w, http.StatusNotFound, "RUN_NOT_FOUND", "recon execution run not found", id)
			return
		}
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to retrieve recon run", err.Error())
		return
	}

	Success(w, http.StatusOK, run)
}

// CancelRecon handles POST /api/recon/{id}/cancel
func (h *Handler) CancelRecon(w http.ResponseWriter, r *http.Request) {
	if h.reconEngine == nil {
		Error(w, http.StatusNotImplemented, "ENGINE_UNAVAILABLE", "recon engine is not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}

	if err := h.reconEngine.CancelRecon(r.Context(), id); err != nil {
		if errors.Is(err, jobs.ErrJobNotFound) {
			Error(w, http.StatusNotFound, "JOB_NOT_FOUND", "scan job not found", id)
			return
		}
		Error(w, http.StatusBadRequest, "CANCELLATION_FAILED", err.Error(), "")
		return
	}

	Success(w, http.StatusOK, map[string]interface{}{
		"job_id": id,
		"status": "cancelled",
	})
}

// ListTargetAssets handles GET /api/targets/{id}/assets
func (h *Handler) ListTargetAssets(w http.ResponseWriter, r *http.Request) {
	if h.reconRepo == nil {
		Error(w, http.StatusNotImplemented, "STORAGE_UNAVAILABLE", "recon repository is not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}

	assets, err := h.reconRepo.ListAssets(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list assets", err.Error())
		return
	}

	type AssetWithRecords struct {
		*models.Asset
		DNSRecords []*models.DNSRecord `json:"dns_records"`
		Tags       []string            `json:"tags"`
		TechCount  int                 `json:"tech_count"`
		SvcCount   int                 `json:"svc_count"`
	}

	enhanced := make([]AssetWithRecords, len(assets))
	for i, a := range assets {
		records, _ := h.reconRepo.ListDNSRecords(r.Context(), a.ID)
		if records == nil {
			records = []*models.DNSRecord{}
		}
		var tagNames []string
		techCount := 0
		svcCount := 0
		if h.intelRepo != nil {
			tags, _ := h.intelRepo.ListAssetTags(r.Context(), a.ID)
			for _, t := range tags {
				tagNames = append(tagNames, t.Tag)
			}
			techs, _, _ := h.intelRepo.ListTechnologyObservations(r.Context(), models.TechnologyFilter{AssetID: a.ID, Limit: 100})
			techCount = len(techs)
			svcs, _, _ := h.intelRepo.ListServiceObservations(r.Context(), models.ServiceFilter{AssetID: a.ID, Limit: 100})
			svcCount = len(svcs)
		}
		if tagNames == nil {
			tagNames = []string{}
		}

		enhanced[i] = AssetWithRecords{
			Asset:      a,
			DNSRecords: records,
			Tags:       tagNames,
			TechCount:  techCount,
			SvcCount:   svcCount,
		}
	}

	Success(w, http.StatusOK, enhanced)
}

// GetTargetIntelligence handles GET /api/targets/{id}/intelligence
func (h *Handler) GetTargetIntelligence(w http.ResponseWriter, r *http.Request) {
	if h.intelRepo == nil {
		Error(w, http.StatusNotImplemented, "STORAGE_UNAVAILABLE", "asset intelligence repository is not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}

	techs, totalTechs, _ := h.intelRepo.ListTechnologyObservations(r.Context(), models.TechnologyFilter{TargetID: id, Limit: 1000})
	svcs, totalSvcs, _ := h.intelRepo.ListServiceObservations(r.Context(), models.ServiceFilter{TargetID: id, Limit: 1000})
	changes, totalChanges, _ := h.intelRepo.ListAssetChanges(r.Context(), models.ChangeFilter{TargetID: id, Limit: 20})
	assets, _ := h.reconRepo.ListAssets(r.Context(), id)

	categoryCounts := make(map[string]int)
	confidenceCounts := make(map[string]int)
	for _, t := range techs {
		categoryCounts[t.Category]++
		confidenceCounts[string(t.Confidence)]++
	}

	webServerCounts := make(map[string]int)
	portCounts := make(map[int]int)
	tlsCounts := make(map[string]int)
	for _, s := range svcs {
		if s.WebServer != "" {
			webServerCounts[s.WebServer]++
		}
		if s.TLSVersion != "" {
			tlsCounts[s.TLSVersion]++
		}
		portCounts[s.Port]++
	}

	// Calculate security posture summary (passive observations only)
	secObs, _ := h.intelRepo.ListSecurityObservations(r.Context(), "", id)
	secSummary := make(map[string]map[string]int)
	for _, so := range secObs {
		if secSummary[so.PropertyName] == nil {
			secSummary[so.PropertyName] = make(map[string]int)
		}
		if so.IsPresent {
			secSummary[so.PropertyName]["present"]++
		} else {
			secSummary[so.PropertyName]["absent"]++
		}
	}

	Success(w, http.StatusOK, map[string]interface{}{
		"target_id":          id,
		"total_assets":       len(assets),
		"total_services":     totalSvcs,
		"total_technologies": totalTechs,
		"total_changes":      totalChanges,
		"categories":         categoryCounts,
		"confidence":         confidenceCounts,
		"web_servers":        webServerCounts,
		"ports":              portCounts,
		"tls_versions":       tlsCounts,
		"security_summary":   secSummary,
		"recent_changes":     changes,
	})
}

// ListTargetTechnologies handles GET /api/targets/{id}/technologies
func (h *Handler) ListTargetTechnologies(w http.ResponseWriter, r *http.Request) {
	if h.intelRepo == nil {
		Error(w, http.StatusNotImplemented, "STORAGE_UNAVAILABLE", "asset intelligence repository is not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}

	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	filter := models.TechnologyFilter{
		TargetID:       id,
		AssetID:        q.Get("asset_id"),
		Category:       q.Get("category"),
		TechnologyName: q.Get("technology_name"),
		Confidence:     models.ConfidenceLevel(q.Get("confidence")),
		MinConfidence:  models.ConfidenceLevel(q.Get("min_confidence")),
		Search:         q.Get("search"),
		Limit:          limit,
		Offset:         offset,
	}

	items, total, err := h.intelRepo.ListTechnologyObservations(r.Context(), filter)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list technologies", err.Error())
		return
	}

	Success(w, http.StatusOK, map[string]interface{}{
		"items":  items,
		"total":  total,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

// ListTargetServices handles GET /api/targets/{id}/services
func (h *Handler) ListTargetServices(w http.ResponseWriter, r *http.Request) {
	if h.intelRepo == nil {
		Error(w, http.StatusNotImplemented, "STORAGE_UNAVAILABLE", "asset intelligence repository is not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}

	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	port, _ := strconv.Atoi(q.Get("port"))
	status, _ := strconv.Atoi(q.Get("status_code"))

	filter := models.ServiceFilter{
		TargetID:   id,
		AssetID:    q.Get("asset_id"),
		Scheme:     q.Get("scheme"),
		Port:       port,
		StatusCode: status,
		WebServer:  q.Get("web_server"),
		Search:     q.Get("search"),
		Limit:      limit,
		Offset:     offset,
	}

	items, total, err := h.intelRepo.ListServiceObservations(r.Context(), filter)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list services", err.Error())
		return
	}

	Success(w, http.StatusOK, map[string]interface{}{
		"items":  items,
		"total":  total,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

// ListTargetChanges handles GET /api/targets/{id}/changes
func (h *Handler) ListTargetChanges(w http.ResponseWriter, r *http.Request) {
	if h.intelRepo == nil {
		Error(w, http.StatusNotImplemented, "STORAGE_UNAVAILABLE", "asset intelligence repository is not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}

	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	filter := models.ChangeFilter{
		TargetID:   id,
		AssetID:    q.Get("asset_id"),
		ChangeType: models.ChangeType(q.Get("change_type")),
		EntityType: q.Get("entity_type"),
		Limit:      limit,
		Offset:     offset,
	}

	items, total, err := h.intelRepo.ListAssetChanges(r.Context(), filter)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list changes", err.Error())
		return
	}

	Success(w, http.StatusOK, map[string]interface{}{
		"items":  items,
		"total":  total,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

// GetAssetDetail handles GET /api/targets/{id}/assets/{assetId}
func (h *Handler) GetAssetDetail(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	assetID := r.PathValue("assetId")
	if targetID == "" || assetID == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 5 {
			targetID = parts[2]
			assetID = parts[4]
		}
	}

	assets, err := h.reconRepo.ListAssets(r.Context(), targetID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to query assets", err.Error())
		return
	}

	var matchedAsset *models.Asset
	for _, a := range assets {
		if a.ID == assetID || a.Hostname == assetID {
			matchedAsset = a
			break
		}
	}

	if matchedAsset == nil {
		Error(w, http.StatusNotFound, "ASSET_NOT_FOUND", "asset not found in specified target", assetID)
		return
	}

	records, _ := h.reconRepo.ListDNSRecords(r.Context(), matchedAsset.ID)
	if records == nil {
		records = []*models.DNSRecord{}
	}

	var (
		svcs      []*models.ServiceObservation
		techs     []*models.TechnologyObservation
		secObs    []*models.SecurityObservation
		tags      []*models.AssetTag
		assets2   []*models.PageAsset
		changes   []*models.AssetChange
	)

	if h.intelRepo != nil {
		svcs, _, _ = h.intelRepo.ListServiceObservations(r.Context(), models.ServiceFilter{TargetID: targetID, AssetID: matchedAsset.ID, Limit: 100})
		techs, _, _ = h.intelRepo.ListTechnologyObservations(r.Context(), models.TechnologyFilter{TargetID: targetID, AssetID: matchedAsset.ID, Limit: 100})
		secObs, _ = h.intelRepo.ListSecurityObservations(r.Context(), matchedAsset.ID, targetID)
		tags, _ = h.intelRepo.ListAssetTags(r.Context(), matchedAsset.ID)
		assets2, _ = h.intelRepo.ListPageAssets(r.Context(), matchedAsset.ID)
		changes, _, _ = h.intelRepo.ListAssetChanges(r.Context(), models.ChangeFilter{TargetID: targetID, AssetID: matchedAsset.ID, Limit: 50})
	}

	Success(w, http.StatusOK, map[string]interface{}{
		"asset":                 matchedAsset,
		"dns_records":           records,
		"services":              svcs,
		"technologies":          techs,
		"security_observations": secObs,
		"tags":                  tags,
		"page_assets":           assets2,
		"changes":               changes,
	})
}

// AddAssetTag handles POST /api/assets/{id}/tags
func (h *Handler) AddAssetTag(w http.ResponseWriter, r *http.Request) {
	if h.intelRepo == nil {
		Error(w, http.StatusNotImplemented, "STORAGE_UNAVAILABLE", "asset intelligence repository is not configured", "")
		return
	}

	assetID := r.PathValue("id")
	if assetID == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			assetID = parts[2]
		}
	}

	var req struct {
		Tag      string `json:"tag"`
		TargetID string `json:"target_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "INVALID_PAYLOAD", "invalid request payload", err.Error())
		return
	}

	cleanTag := strings.ToLower(strings.TrimSpace(req.Tag))
	if cleanTag == "" {
		Error(w, http.StatusBadRequest, "INVALID_TAG", "tag name cannot be empty", "")
		return
	}

	assetTag := &models.AssetTag{
		ID:         events.GenerateID("tag"),
		AssetID:    assetID,
		TargetID:   req.TargetID,
		Tag:        cleanTag,
		IsInferred: false,
		CreatedAt:  time.Now().UTC(),
		CreatedBy:  "user:manual",
	}

	if err := h.intelRepo.AddAssetTag(r.Context(), assetTag); err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to add tag", err.Error())
		return
	}

	Success(w, http.StatusCreated, assetTag)
}

// DeleteAssetTag handles DELETE /api/assets/{id}/tags/{tag}
func (h *Handler) DeleteAssetTag(w http.ResponseWriter, r *http.Request) {
	if h.intelRepo == nil {
		Error(w, http.StatusNotImplemented, "STORAGE_UNAVAILABLE", "asset intelligence repository is not configured", "")
		return
	}

	assetID := r.PathValue("id")
	tag := r.PathValue("tag")
	if assetID == "" || tag == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 5 {
			assetID = parts[2]
			tag = parts[4]
		}
	}

	if err := h.intelRepo.RemoveAssetTag(r.Context(), assetID, tag); err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to remove tag", err.Error())
		return
	}

	Success(w, http.StatusOK, map[string]interface{}{
		"status":   "removed",
		"asset_id": assetID,
		"tag":      tag,
	})
}

// ListTargetURLs handles GET /api/targets/{id}/urls
func (h *Handler) ListTargetURLs(w http.ResponseWriter, r *http.Request) {
	if h.reconRepo == nil {
		Error(w, http.StatusNotImplemented, "STORAGE_UNAVAILABLE", "recon repository is not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}

	urls, err := h.reconRepo.ListURLs(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list urls", err.Error())
		return
	}

	Success(w, http.StatusOK, urls)
}

func cleanStringSlice(in []string) []string {
	if in == nil {
		return []string{}
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// Phase 4: AI Analysis & Finding Candidates Endpoints

// TriggerAnalysis handles POST /api/analysis/run
func (h *Handler) TriggerAnalysis(w http.ResponseWriter, r *http.Request) {
	if h.aiService == nil {
		Error(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI analysis service not configured", "")
		return
	}

	var req models.TriggerAnalysisRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "INVALID_JSON", "request body is not valid JSON", err.Error())
		return
	}
	if req.TargetID == "" {
		Error(w, http.StatusBadRequest, "VALIDATION_FAILED", "target_id is required", "")
		return
	}

	// Verify target exists
	if _, err := h.storage.GetByID(r.Context(), req.TargetID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			Error(w, http.StatusNotFound, "NOT_FOUND", "target not found", "")
			return
		}
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check target", err.Error())
		return
	}

	if req.AssetID != "" {
		run, candidates, err := h.aiService.AnalyzeAsset(r.Context(), req.TargetID, req.AssetID)
		if err != nil {
			Error(w, http.StatusInternalServerError, "ANALYSIS_FAILED", "asset analysis failed", err.Error())
			return
		}
		Success(w, http.StatusOK, map[string]any{
			"run":        run,
			"candidates": candidates,
		})
		return
	}

	// Target-wide analysis
	runs, err := h.aiService.AnalyzeTarget(r.Context(), req.TargetID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "ANALYSIS_FAILED", "target analysis failed", err.Error())
		return
	}
	Success(w, http.StatusOK, map[string]any{
		"runs":       runs,
		"runs_count": len(runs),
	})
}

// TriggerTargetAnalysis handles POST /api/targets/{id}/analyze
func (h *Handler) TriggerTargetAnalysis(w http.ResponseWriter, r *http.Request) {
	if h.aiService == nil {
		Error(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI analysis service not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}

	if _, err := h.storage.GetByID(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			Error(w, http.StatusNotFound, "NOT_FOUND", "target not found", "")
			return
		}
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to check target", err.Error())
		return
	}

	runs, err := h.aiService.AnalyzeTarget(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "ANALYSIS_FAILED", "target analysis failed", err.Error())
		return
	}
	Success(w, http.StatusOK, map[string]any{
		"target_id":  id,
		"runs":       runs,
		"runs_count": len(runs),
	})
}

// TriggerAssetAnalysis handles POST /api/targets/{id}/assets/{assetId}/analyze
func (h *Handler) TriggerAssetAnalysis(w http.ResponseWriter, r *http.Request) {
	if h.aiService == nil {
		Error(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI analysis service not configured", "")
		return
	}

	targetID := r.PathValue("id")
	assetID := r.PathValue("assetId")
	if targetID == "" || assetID == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 5 {
			targetID = parts[2]
			assetID = parts[4]
		}
	}

	run, candidates, err := h.aiService.AnalyzeAsset(r.Context(), targetID, assetID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "ANALYSIS_FAILED", "asset analysis failed", err.Error())
		return
	}
	Success(w, http.StatusOK, map[string]any{
		"run":        run,
		"candidates": candidates,
	})
}

// ListTargetAnalysisRuns handles GET /api/targets/{id}/analysis-runs
func (h *Handler) ListTargetAnalysisRuns(w http.ResponseWriter, r *http.Request) {
	if h.aiService == nil {
		Error(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI analysis service not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}

	runs, err := h.aiService.ListAnalysisRuns(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list analysis runs", err.Error())
		return
	}
	Success(w, http.StatusOK, runs)
}

// GetAnalysisRun handles GET /api/analysis-runs/{id}
func (h *Handler) GetAnalysisRun(w http.ResponseWriter, r *http.Request) {
	if h.aiService == nil {
		Error(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI analysis service not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}

	run, err := h.aiService.GetAnalysisRun(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			Error(w, http.StatusNotFound, "NOT_FOUND", "analysis run not found", "")
			return
		}
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get analysis run", err.Error())
		return
	}
	Success(w, http.StatusOK, run)
}

// ListFindingCandidates handles GET /api/findings/candidates
func (h *Handler) ListFindingCandidates(w http.ResponseWriter, r *http.Request) {
	if h.aiService == nil {
		Error(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI analysis service not configured", "")
		return
	}

	q := r.URL.Query()
	limit := 50
	if l := q.Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 && val <= 200 {
			limit = val
		}
	}
	offset := 0
	if o := q.Get("offset"); o != "" {
		if val, err := strconv.Atoi(o); err == nil && val >= 0 {
			offset = val
		}
	}

	filter := models.CandidateFilter{
		TargetID: q.Get("target_id"),
		AssetID:  q.Get("asset_id"),
		Category: q.Get("category"),
		State:    models.CandidateState(q.Get("state")),
		Search:   q.Get("search"),
		Limit:    limit,
		Offset:   offset,
	}

	candidates, total, err := h.aiService.ListCandidates(r.Context(), filter)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list candidates", err.Error())
		return
	}

	Success(w, http.StatusOK, map[string]any{
		"candidates": candidates,
		"total":      total,
		"limit":      limit,
		"offset":     offset,
	})
}

// GetFindingCandidate handles GET /api/findings/candidates/{id}
func (h *Handler) GetFindingCandidate(w http.ResponseWriter, r *http.Request) {
	if h.aiService == nil {
		Error(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI analysis service not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 4 {
			id = parts[3]
		}
	}

	candidate, err := h.aiService.GetCandidate(r.Context(), id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			Error(w, http.StatusNotFound, "NOT_FOUND", "candidate not found", "")
			return
		}
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get candidate", err.Error())
		return
	}
	Success(w, http.StatusOK, candidate)
}

// UpdateCandidateState handles PATCH /api/findings/candidates/{id}/state
func (h *Handler) UpdateCandidateState(w http.ResponseWriter, r *http.Request) {
	if h.aiService == nil {
		Error(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI analysis service not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 4 {
			id = parts[3]
		}
	}

	var req models.UpdateCandidateStateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "INVALID_JSON", "request body is not valid JSON", err.Error())
		return
	}

	validStates := map[models.CandidateState]bool{
		models.CandidateStateCandidate:       true,
		models.CandidateStateNeedsValidation: true,
		models.CandidateStateValidated:       true,
		models.CandidateStateRejected:        true,
		models.CandidateStateDismissed:       true,
		models.CandidateStateDuplicate:       true,
		models.CandidateStateReadyForReview:  true,
		models.CandidateStateValidating:      true,
		models.CandidateStateReported:        true,
		models.CandidateStateResolved:        true,
	}
	if !validStates[req.State] {
		Error(w, http.StatusBadRequest, "INVALID_STATE", "invalid candidate state requested", string(req.State))
		return
	}

	updated, err := h.aiService.UpdateCandidateState(r.Context(), id, req)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			Error(w, http.StatusNotFound, "NOT_FOUND", "candidate not found", "")
			return
		}
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update candidate state", err.Error())
		return
	}
	Success(w, http.StatusOK, updated)
}

// ListTargetSignals handles GET /api/targets/{id}/signals
func (h *Handler) ListTargetSignals(w http.ResponseWriter, r *http.Request) {
	if h.aiService == nil {
		Error(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI analysis service not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}
	assetID := r.URL.Query().Get("asset_id")

	signals, err := h.aiService.ListSignals(r.Context(), id, assetID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list security signals", err.Error())
		return
	}
	Success(w, http.StatusOK, signals)
}

// GetAIHealth handles GET /api/ai/health
func (h *Handler) GetAIHealth(w http.ResponseWriter, r *http.Request) {
	if h.aiService == nil {
		Error(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI analysis service not configured", "")
		return
	}

	health, err := h.aiService.Health(r.Context())
	if err != nil {
		Error(w, http.StatusServiceUnavailable, "AI_UNREACHABLE", "failed to connect to AI engine", err.Error())
		return
	}
	Success(w, http.StatusOK, health)
}

// ListTargetCandidates handles GET /api/targets/{id}/candidates
func (h *Handler) ListTargetCandidates(w http.ResponseWriter, r *http.Request) {
	if h.aiService == nil {
		Error(w, http.StatusServiceUnavailable, "AI_UNAVAILABLE", "AI analysis service not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}
	state := r.URL.Query().Get("state")
	candidates, _, err := h.aiService.ListCandidates(r.Context(), models.CandidateFilter{
		TargetID: id,
		State:    models.CandidateState(state),
		Limit:    100,
	})
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list target candidates", err.Error())
		return
	}
	if candidates == nil {
		candidates = []*models.FindingCandidate{}
	}
	Success(w, http.StatusOK, candidates)
}

// GetTargetGraph handles GET /api/targets/{id}/graph
func (h *Handler) GetTargetGraph(w http.ResponseWriter, r *http.Request) {
	if h.secRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "security intelligence repository not configured", "")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}
	graph, err := h.secRepo.GetTargetGraph(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to fetch target graph", err.Error())
		return
	}
	if graph == nil {
		graph = &models.GraphData{
			TargetID: id,
			Nodes:    []*models.GraphNode{},
			Edges:    []*models.GraphEdge{},
			Metrics:  map[string]int{},
		}
	}
	Success(w, http.StatusOK, graph)
}

// ListTargetTemporalChanges handles GET /api/targets/{id}/temporal-changes
func (h *Handler) ListTargetTemporalChanges(w http.ResponseWriter, r *http.Request) {
	if h.secRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "security intelligence repository not configured", "")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 {
			limit = val
		}
	}
	changes, err := h.secRepo.ListTemporalChanges(r.Context(), id, limit)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list temporal changes", err.Error())
		return
	}
	if changes == nil {
		changes = []*models.TemporalChangeRecord{}
	}
	Success(w, http.StatusOK, changes)
}

// ListTargetInvariants handles GET /api/targets/{id}/invariants
func (h *Handler) ListTargetInvariants(w http.ResponseWriter, r *http.Request) {
	if h.secRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "security intelligence repository not configured", "")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}
	signals, err := h.secRepo.ListInvariantSignals(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list invariant signals", err.Error())
		return
	}
	if signals == nil {
		signals = []*models.InvariantSignal{}
	}
	Success(w, http.StatusOK, signals)
}

// ListTargetBehaviorDiffs handles GET /api/targets/{id}/behavior-diffs
func (h *Handler) ListTargetBehaviorDiffs(w http.ResponseWriter, r *http.Request) {
	if h.secRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "security intelligence repository not configured", "")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}
	diffs, err := h.secRepo.ListBehaviorDifferences(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list behavior diffs", err.Error())
		return
	}
	if diffs == nil {
		diffs = []*models.BehaviorDifference{}
	}
	Success(w, http.StatusOK, diffs)
}

// ListInvestigationClusters handles GET /api/targets/{id}/investigation-clusters
func (h *Handler) ListInvestigationClusters(w http.ResponseWriter, r *http.Request) {
	if h.secRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "security intelligence repository not configured", "")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}
	clusters, err := h.secRepo.ListInvestigationClusters(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to list investigation clusters", err.Error())
		return
	}
	if clusters == nil {
		clusters = []*models.InvestigationCluster{}
	}
	Success(w, http.StatusOK, clusters)
}

// UpdateClusterStatus handles PATCH /api/investigation-clusters/{id}/status
func (h *Handler) UpdateClusterStatus(w http.ResponseWriter, r *http.Request) {
	if h.secRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "security intelligence repository not configured", "")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		for i, p := range parts {
			if p == "investigation-clusters" && i+1 < len(parts) {
				id = parts[i+1]
				break
			}
		}
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Error(w, http.StatusBadRequest, "INVALID_REQUEST", "malformed status body", err.Error())
		return
	}
	if err := h.secRepo.UpdateClusterStatus(r.Context(), id, models.ClusterStatus(body.Status)); err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to update cluster status", err.Error())
		return
	}
	cluster, _ := h.secRepo.GetInvestigationCluster(r.Context(), id)
	Success(w, http.StatusOK, cluster)
}

// GetResearchMemory handles GET /api/targets/{id}/research-memory
func (h *Handler) GetResearchMemory(w http.ResponseWriter, r *http.Request) {
	if h.secRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "security intelligence repository not configured", "")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 {
			id = parts[2]
		}
	}
	mem, err := h.secRepo.GetResearchMemory(r.Context(), id)
	if err != nil {
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to get research memory", err.Error())
		return
	}
	Success(w, http.StatusOK, mem)
}

// ExecuteControlledValidation handles POST /api/validation/execute
func (h *Handler) ExecuteControlledValidation(w http.ResponseWriter, r *http.Request) {
	if h.secEngine == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "validation engine not configured", "")
		return
	}
	var req models.ControlledValidationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "INVALID_REQUEST", "malformed validation request body", err.Error())
		return
	}
	result, err := h.secEngine.ExecuteControlledValidation(r.Context(), &req)
	if err != nil {
		if strings.Contains(err.Error(), "SCOPE_VIOLATION") {
			Error(w, http.StatusForbidden, "SCOPE_VIOLATION", err.Error(), "")
			return
		}
		Error(w, http.StatusInternalServerError, "VALIDATION_FAILED", "validation execution failed", err.Error())
		return
	}
	Success(w, http.StatusOK, result)
}


