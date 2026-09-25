package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/cloudintel"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/jsintel"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/planner"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/storage"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/waf"
)

// Phase8Dependencies wraps services and repositories for Phase 8.
type Phase8Dependencies struct {
	ScopeImportRepo storage.ScopeImportRepository
	ScopeSanitizer  scope.ImportSanitizer
	JSRepo          storage.JSIntelligenceRepository
	JSIntel         jsintel.Service
	CloudRepo       storage.CloudIntelligenceRepository
	CloudIntel      cloudintel.Service
	WAFRepo         storage.WAFIntelligenceRepository
	WAFDetector     waf.Detector
	PlannerRepo     storage.HuntingPlannerRepository
	PlannerSvc      planner.Service
}

// SetPhase8Intelligence registers Phase 8 dependencies into the main API Handler.
func (h *Handler) SetPhase8Intelligence(deps Phase8Dependencies) {
	h.p8ScopeImportRepo = deps.ScopeImportRepo
	h.p8ScopeSanitizer = deps.ScopeSanitizer
	h.p8JSRepo = deps.JSRepo
	h.p8JSIntel = deps.JSIntel
	h.p8CloudRepo = deps.CloudRepo
	h.p8CloudIntel = deps.CloudIntel
	h.p8WAFRepo = deps.WAFRepo
	h.p8WAFDetector = deps.WAFDetector
	h.p8PlannerRepo = deps.PlannerRepo
	h.p8PlannerSvc = deps.PlannerSvc
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	JSON(w, status, data)
}

// ----------------------------------------------------
// Scope Intelligence Handlers
// ----------------------------------------------------

func (h *Handler) ImportScope(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read scope content"})
		return
	}

	fileName := r.URL.Query().Get("file_name")
	if fileName == "" {
		fileName = "scope_import.json"
	}

	sanitizer := h.p8ScopeSanitizer
	if sanitizer == nil {
		sanitizer = scope.NewSanitizer()
	}

	review, err := sanitizer.SanitizeScopeFile(body, fileName)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":  "scope sanitization failed",
			"detail": err.Error(),
		})
		return
	}

	if h.p8ScopeImportRepo != nil {
		_ = h.p8ScopeImportRepo.SaveImportReview(ctx, review)
	}

	writeJSON(w, http.StatusCreated, review)
}


func (h *Handler) ListScopeImports(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if h.p8ScopeImportRepo == nil {
		writeJSON(w, http.StatusOK, []*models.ScopeImportReview{})
		return
	}

	reviews, err := h.p8ScopeImportRepo.ListImportReviews(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, reviews)
}

func (h *Handler) GetScopeImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if h.p8ScopeImportRepo == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scope review not found"})
		return
	}

	rev, err := h.p8ScopeImportRepo.GetImportReview(ctx, id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scope review not found"})
		return
	}
	writeJSON(w, http.StatusOK, rev)
}

type ConfirmScopeImportReq struct {
	SelectedRootDomain string `json:"selected_root_domain"`
	SelectionReason    string `json:"selection_reason,omitempty"`
	TargetName         string `json:"target_name"`
	ConfirmedBy        string `json:"confirmed_by,omitempty"`
}

func (h *Handler) ConfirmScopeImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	var req ConfirmScopeImportReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if h.p8ScopeImportRepo == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "scope import repository unavailable"})
		return
	}

	rev, err := h.p8ScopeImportRepo.GetImportReview(ctx, id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scope review not found"})
		return
	}

	// Invariant: Cannot re-confirm an already confirmed import
	if rev.Status == "CONFIRMED" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "scope import has already been confirmed"})
		return
	}
	if rev.Status == "REJECTED" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot create target from rejected scope import"})
		return
	}

	selectedRoot := req.SelectedRootDomain
	// Phase 8.2R-FINAL.3 Item 5: Zero automatic primary-root selection.
	// Even for a single root domain, explicit confirmation from the caller is mandatory.
	if selectedRoot == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "explicit selected_root_domain is strictly required; automatic primary-root selection is disabled",
		})
		return
	}

	// Verify selectedRoot is among discovered candidates
	validCandidate := false
	for _, rd := range rev.RootDomains {
		if rd.NormalizedDomain == selectedRoot {
			validCandidate = true
			break
		}
	}
	if !validCandidate {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "selected_root_domain is not among discovered root domain candidates",
		})
		return
	}

	targetName := req.TargetName
	if targetName == "" {
		targetName = selectedRoot
	}

	now := time.Now().UTC()

	// Section 10 Target Creation Invariant:
	// A target created from an imported scope must contain:
	// target_id, scope_import_id, canonical_scope_hash, primary_root_domain, root_domains, include/exclude rules, confirmation_timestamp
	target := &models.Target{
		ID:                    "target-" + strconv.FormatInt(time.Now().UnixNano(), 36),
		Name:                  targetName,
		RootDomain:            selectedRoot,
		ScopeImportID:         rev.ID,
		CanonicalScopeHash:    rev.CanonicalScopeSHA256,
		ConfirmationTimestamp: &now,
		ScopeConfig: &models.AdvancedScopeConfig{
			AdvancedMode: true,
		},
		Status:    models.TargetStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if rev.CanonicalScope != nil {
		target.AllowedDomains = rev.CanonicalScope.RootDomains
		target.ScopeConfig.Include = append(target.ScopeConfig.Include, rev.CanonicalScope.IncludeHosts...)
		target.ScopeConfig.Exclude = append(target.ScopeConfig.Exclude, rev.CanonicalScope.ExcludeHosts...)
	}

	confirmedBy := req.ConfirmedBy
	if confirmedBy == "" {
		confirmedBy = "lead-researcher"
	}

	if err := h.p8ScopeImportRepo.ConfirmImportReviewProvenance(ctx, id, selectedRoot, target.ID, confirmedBy); err != nil {
		if errors.Is(err, storage.ErrInvalidState) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "scope import has already been confirmed"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to record scope confirmation: " + err.Error()})
		return
	}

	if err := h.storage.Create(ctx, target); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create target: " + err.Error()})
		return
	}
	rev.Status = "CONFIRMED"
	rev.TargetID = target.ID
	rev.SelectedRootDomain = selectedRoot
	rev.ConfirmedBy = confirmedBy
	rev.ConfirmedAt = &now
	rev.SelectionReason = req.SelectionReason

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":                 "CONFIRMED",
		"target_id":              target.ID,
		"selected_root":          selectedRoot,
		"confirmed_by":           confirmedBy,
		"source_import_id":       rev.ID,
		"canonical_scope_sha256": rev.CanonicalScopeSHA256,
		"scope_review":           rev,
	})
}

// ----------------------------------------------------
// JS Intelligence Handlers
// ----------------------------------------------------

func (h *Handler) ListTargetJSAssets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	targetID := r.PathValue("id")
	assetID := r.URL.Query().Get("asset_id")

	if h.p8JSRepo == nil {
		writeJSON(w, http.StatusOK, []*models.JSAsset{})
		return
	}

	assets, err := h.p8JSRepo.ListJSAssets(ctx, targetID, assetID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, assets)
}

func (h *Handler) ListTargetJSReferences(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	targetID := r.PathValue("id")
	jsAssetID := r.URL.Query().Get("js_asset_id")

	if h.p8JSRepo == nil {
		writeJSON(w, http.StatusOK, []*models.JSReference{})
		return
	}

	refs, err := h.p8JSRepo.ListJSReferences(ctx, targetID, jsAssetID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, refs)
}

func (h *Handler) ListTargetJSSecrets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	targetID := r.PathValue("id")
	assetID := r.URL.Query().Get("asset_id")

	if h.p8JSRepo == nil {
		writeJSON(w, http.StatusOK, []*models.JSSecretIndicator{})
		return
	}

	secrets, err := h.p8JSRepo.ListSecretIndicators(ctx, targetID, assetID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, secrets)
}

type AnalyzeJSReq struct {
	AssetID   string `json:"asset_id"`
	ScriptURL string `json:"script_url"`
	Content   string `json:"content"`
}

func (h *Handler) TriggerJSAnalysis(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	targetID := r.PathValue("id")

	target, err := h.storage.GetByID(ctx, targetID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "target not found"})
		return
	}

	var req AnalyzeJSReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if h.p8JSIntel == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "JS Intelligence service unavailable"})
		return
	}

	jsAsset := &models.JSAsset{
		ID:          "js-" + strconv.FormatInt(time.Now().UnixNano(), 36),
		TargetID:    target.ID,
		AssetID:     req.AssetID,
		URL:         req.ScriptURL,
		FetchStatus: "FETCHED",
		CreatedAt:   time.Now().UTC(),
	}

	var refs []*models.JSReference
	var secrets []*models.JSSecretIndicator
	if req.Content != "" {
		refs, secrets, err = h.p8JSIntel.AnalyzeContent(ctx, target, jsAsset, req.Content)
	} else if req.ScriptURL != "" {
		refs, secrets, err = h.p8JSIntel.FetchAndAnalyze(ctx, target, jsAsset)
	} else {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "either script_url or content must be provided"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if h.p8JSRepo != nil {
		_ = h.p8JSRepo.SaveJSAsset(ctx, jsAsset)
		for _, ref := range refs {
			_ = h.p8JSRepo.SaveJSReference(ctx, ref)
		}
		for _, sec := range secrets {
			_ = h.p8JSRepo.SaveSecretIndicator(ctx, sec)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"asset":      jsAsset,
		"references": refs,
		"secrets":    secrets,
	})
}

// ----------------------------------------------------
// Cloud Reference Intelligence Handlers
// ----------------------------------------------------

func (h *Handler) ListTargetCloudReferences(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	targetID := r.PathValue("id")
	assetID := r.URL.Query().Get("asset_id")

	if h.p8CloudRepo == nil {
		writeJSON(w, http.StatusOK, []*models.CloudReference{})
		return
	}

	refs, err := h.p8CloudRepo.ListCloudReferences(ctx, targetID, assetID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, refs)
}

type ValidateCloudRefReq struct {
	CloudReferenceID string `json:"cloud_reference_id"`
}

func (h *Handler) ValidateCloudReference(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req ValidateCloudRefReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if h.p8CloudIntel == nil || h.p8CloudRepo == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cloud intelligence service or repository unavailable"})
		return
	}

	ref, err := h.p8CloudRepo.GetCloudReference(ctx, req.CloudReferenceID)
	if err != nil || ref == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "cloud reference not found"})
		return
	}

	target, err := h.storage.GetByID(ctx, ref.TargetID)
	if err != nil || target == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "target not found"})
		return
	}

	if err := h.p8CloudIntel.ProbeSafePublicStatus(ctx, target, ref); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	_ = h.p8CloudRepo.UpdateCloudValidation(ctx, ref.ID, ref.ValidationStatus, ref.StatusCode, ref.PublicAccessible)
	writeJSON(w, http.StatusOK, ref)
}


// ----------------------------------------------------
// WAF Intelligence Handlers
// ----------------------------------------------------

func (h *Handler) ListTargetWAFObservations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	targetID := r.PathValue("id")

	if h.p8WAFRepo == nil {
		writeJSON(w, http.StatusOK, []*models.WAFObservation{})
		return
	}

	obs, err := h.p8WAFRepo.ListWAFObservations(ctx, targetID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, obs)
}

// ----------------------------------------------------
// AI Hunting Planner & Human Validation Checklist Handlers
// ----------------------------------------------------

type GeneratePlanReq struct {
	AssetID         string   `json:"asset_id"`
	HypothesisID    string   `json:"hypothesis_id"`
	HypothesisTitle string   `json:"hypothesis_title"`
	EvidenceIDs     []string `json:"evidence_ids"`
}

func (h *Handler) GenerateHuntingPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	targetID := r.PathValue("id")

	target, err := h.storage.GetByID(ctx, targetID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "target not found"})
		return
	}

	var req GeneratePlanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if h.p8PlannerSvc == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "hunting planner service unavailable"})
		return
	}

	pCtx := planner.PlannerContext{
		HypothesisID:      req.HypothesisID,
		HypothesisTitle:   req.HypothesisTitle,
		SourceEvidenceIDs: req.EvidenceIDs,
	}

	if req.AssetID != "" && h.intelRepo != nil {
		if detail, err := h.intelRepo.GetAssetDetail(ctx, targetID, req.AssetID); err == nil && detail != nil {
			pCtx.Asset = detail.Asset
		}
	}
	if h.reconRepo != nil {
		if svcs, err := h.reconRepo.ListHTTPServices(ctx, targetID); err == nil {
			pCtx.Services = svcs
		}
	}

	if h.p8JSRepo != nil {
		if refs, err := h.p8JSRepo.ListJSReferences(ctx, targetID, ""); err == nil {
			pCtx.JSReferences = refs
		}
	}
	if h.p8CloudRepo != nil {
		if cloudRefs, err := h.p8CloudRepo.ListCloudReferences(ctx, targetID, req.AssetID); err == nil {
			pCtx.CloudReferences = cloudRefs
		}
	}
	if h.p8WAFRepo != nil {
		if wafObs, err := h.p8WAFRepo.GetWAFObservation(ctx, targetID, req.AssetID); err == nil {
			pCtx.WAFObservation = wafObs
		}
	}

	plan, err := h.p8PlannerSvc.GenerateInvestigationPlan(ctx, target, req.AssetID, pCtx)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if h.p8PlannerRepo != nil {
		_ = h.p8PlannerRepo.SaveInvestigationPlan(ctx, plan)
	}

	writeJSON(w, http.StatusCreated, plan)
}

func (h *Handler) ListInvestigationPlans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	targetID := r.PathValue("id")
	assetID := r.URL.Query().Get("asset_id")

	if h.p8PlannerRepo == nil {
		writeJSON(w, http.StatusOK, []*models.InvestigationPlan{})
		return
	}

	plans, err := h.p8PlannerRepo.ListInvestigationPlans(ctx, targetID, assetID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, plans)
}

func (h *Handler) GetInvestigationPlan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	if h.p8PlannerRepo == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "plan not found"})
		return
	}

	plan, err := h.p8PlannerRepo.GetInvestigationPlan(ctx, id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "plan not found"})
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

type ApproveStepReq struct {
	StepNumber int `json:"step_number"`
}

func (h *Handler) ApproveInvestigationStep(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	var req ApproveStepReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if h.p8PlannerSvc == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "planner service unavailable"})
		return
	}

	updatedPlan, err := h.p8PlannerSvc.ApproveStep(ctx, id, req.StepNumber)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if h.p8PlannerRepo != nil {
		_ = h.p8PlannerRepo.ApprovePlanStep(ctx, id, req.StepNumber)
	}

	writeJSON(w, http.StatusOK, updatedPlan)
}
