package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// RecordEvidence handles POST /api/evidence
func (h *Handler) RecordEvidence(w http.ResponseWriter, r *http.Request) {
	if h.evidenceEng == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence engine is not configured", "")
		return
	}

	var req models.Evidence
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "INVALID_REQUEST", "malformed JSON body", err.Error())
		return
	}

	if req.TargetID == "" {
		Error(w, http.StatusBadRequest, "INVALID_REQUEST", "target_id is required", "")
		return
	}

	// 1. Server-side validation: TargetID must exist
	var target *models.Target
	if h.storage != nil {
		var err error
		target, err = h.storage.GetByID(r.Context(), req.TargetID)
		if err != nil || target == nil {
			Error(w, http.StatusNotFound, "TARGET_NOT_FOUND", "specified target does not exist", "")
			return
		}
	}

	// 2. Server-side validation: AssetID must belong to TargetID
	if req.AssetID != "" && h.intelRepo != nil {
		detail, err := h.intelRepo.GetAssetDetail(r.Context(), req.TargetID, req.AssetID)
		if err != nil || detail == nil || detail.Asset == nil || detail.Asset.TargetID != req.TargetID {
			Error(w, http.StatusConflict, "SECURITY_CONTEXT_MISMATCH", "asset does not belong to target", "")
			return
		}
	}


	// 3. Server-side validation: SSRF and scope validation
	if req.Request != nil && req.Request.URL != "" && h.scopeSvc != nil && target != nil {
		u, err := url.Parse(req.Request.URL)
		if err != nil {
			Error(w, http.StatusBadRequest, "MALFORMED_URL", "malformed request URL", err.Error())
			return
		}
		inScope, err := h.scopeSvc.IsInScope(target, u.Hostname(), req.Request.URL)
		if err != nil || !inScope {
			Error(w, http.StatusForbidden, "SCOPE_VIOLATION", "evidence request URL violates target scope or SSRF restrictions", "")
			return
		}
	}


	recorded, err := h.evidenceEng.RecordEvidence(r.Context(), &req)
	if err != nil {
		Error(w, http.StatusInternalServerError, "PROCESSING_ERROR", "failed to record evidence", err.Error())
		return
	}

	JSON(w, http.StatusCreated, map[string]interface{}{
		"status":   "recorded",
		"evidence": recorded,
	})
}

// GetEvidence handles GET /api/evidence/{id}
func (h *Handler) GetEvidence(w http.ResponseWriter, r *http.Request) {
	if h.evidenceRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence repository is not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "INVALID_REQUEST", "evidence id is required", "")
		return
	}

	ev, err := h.evidenceRepo.GetEvidence(r.Context(), id)
	if err != nil {
		Error(w, http.StatusNotFound, "NOT_FOUND", "evidence record not found", err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"evidence": ev,
	})
}

// ListTargetEvidence handles GET /api/targets/{id}/evidence
func (h *Handler) ListTargetEvidence(w http.ResponseWriter, r *http.Request) {
	if h.evidenceRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence repository is not configured", "")
		return
	}

	targetID := r.PathValue("id")
	list, err := h.evidenceRepo.ListEvidenceByTarget(r.Context(), targetID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "STORAGE_ERROR", "failed to list target evidence", err.Error())
		return
	}
	if list == nil {
		list = []*models.Evidence{}
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"target_id": targetID,
		"evidence":  list,
		"count":     len(list),
	})
}

// ListAssetEvidence handles GET /api/assets/{id}/evidence
func (h *Handler) ListAssetEvidence(w http.ResponseWriter, r *http.Request) {
	if h.evidenceRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence repository is not configured", "")
		return
	}

	assetID := r.PathValue("id")
	list, err := h.evidenceRepo.ListEvidenceByAsset(r.Context(), assetID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "STORAGE_ERROR", "failed to list asset evidence", err.Error())
		return
	}
	if list == nil {
		list = []*models.Evidence{}
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"asset_id": assetID,
		"evidence": list,
		"count":    len(list),
	})
}

// ComputeEvidenceDiff handles POST /api/evidence/diff
func (h *Handler) ComputeEvidenceDiff(w http.ResponseWriter, r *http.Request) {
	if h.evidenceEng == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence engine is not configured", "")
		return
	}

	var req models.DifferentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "INVALID_REQUEST", "malformed differential request", err.Error())
		return
	}

	if req.EvidenceAID == "" || req.EvidenceBID == "" {
		Error(w, http.StatusBadRequest, "INVALID_REQUEST", "both evidence_a_id and evidence_b_id are required", "")
		return
	}

	diff, err := h.evidenceEng.CompareEvidence(r.Context(), req.EvidenceAID, req.EvidenceBID, req.FilterNoise)
	if err != nil {
		if strings.Contains(err.Error(), "TARGET_MISMATCH_PROHIBITED") {
			Error(w, http.StatusConflict, "TARGET_MISMATCH_PROHIBITED", err.Error(), "")
			return
		}
		if strings.Contains(err.Error(), "not found") {
			Error(w, http.StatusNotFound, "NOT_FOUND", err.Error(), "")
			return
		}
		Error(w, http.StatusInternalServerError, "PROCESSING_ERROR", "differential computation failed", err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"diff": diff,
	})
}

// VerifyEvidenceIntegrity handles GET /api/evidence/{id}/integrity
func (h *Handler) VerifyEvidenceIntegrity(w http.ResponseWriter, r *http.Request) {
	if h.evidenceEng == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence engine is not configured", "")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		Error(w, http.StatusBadRequest, "INVALID_PARAM", "missing evidence id", "")
		return
	}

	result, err := h.evidenceEng.VerifyEvidenceIntegrity(r.Context(), id)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			Error(w, http.StatusNotFound, "NOT_FOUND", "evidence record not found", err.Error())
			return
		}
		Error(w, http.StatusInternalServerError, "INTEGRITY_CHECK_FAILED", "failed to verify evidence integrity", err.Error())
		return
	}

	JSON(w, http.StatusOK, result)
}

// GetEvidenceDiff handles GET /api/evidence/diffs/{id}
func (h *Handler) GetEvidenceDiff(w http.ResponseWriter, r *http.Request) {
	if h.evidenceRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence repository is not configured", "")
		return
	}

	id := r.PathValue("id")
	diff, err := h.evidenceRepo.GetEvidenceDiff(r.Context(), id)
	if err != nil {
		Error(w, http.StatusNotFound, "NOT_FOUND", "evidence diff not found", err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"diff": diff,
	})
}

// ListTargetDiffs handles GET /api/targets/{id}/diffs
func (h *Handler) ListTargetDiffs(w http.ResponseWriter, r *http.Request) {
	if h.evidenceRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence repository is not configured", "")
		return
	}

	targetID := r.PathValue("id")
	list, err := h.evidenceRepo.ListEvidenceDiffs(r.Context(), targetID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "STORAGE_ERROR", "failed to list diffs", err.Error())
		return
	}
	if list == nil {
		list = []*models.EvidenceDiff{}
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"target_id": targetID,
		"diffs":     list,
		"count":     len(list),
	})
}

// CreateSecurityExpectation handles POST /api/expectations
func (h *Handler) CreateSecurityExpectation(w http.ResponseWriter, r *http.Request) {
	if h.evidenceRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence repository is not configured", "")
		return
	}

	var req models.SecurityExpectation
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "INVALID_REQUEST", "malformed expectation request", err.Error())
		return
	}

	if req.TargetID == "" || req.ControlName == "" || req.ExpectedState == "" {
		Error(w, http.StatusBadRequest, "INVALID_REQUEST", "target_id, control_name, and expected_state are required", "")
		return
	}

	if req.ID == "" {
		req.ID = "exp-" + uuid.New().String()[:12]
	}
	if req.CreatedAt.IsZero() {
		req.CreatedAt = time.Now().UTC()
	}

	if err := h.evidenceRepo.SaveSecurityExpectation(r.Context(), &req); err != nil {
		Error(w, http.StatusInternalServerError, "STORAGE_ERROR", "failed to save expectation", err.Error())
		return
	}

	JSON(w, http.StatusCreated, map[string]interface{}{
		"status":      "created",
		"expectation": req,
	})
}

// ListTargetExpectations handles GET /api/targets/{id}/expectations
func (h *Handler) ListTargetExpectations(w http.ResponseWriter, r *http.Request) {
	if h.evidenceRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence repository is not configured", "")
		return
	}

	targetID := r.PathValue("id")
	assetID := r.URL.Query().Get("asset_id")

	list, err := h.evidenceRepo.ListSecurityExpectations(r.Context(), targetID, assetID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "STORAGE_ERROR", "failed to list expectations", err.Error())
		return
	}
	if list == nil {
		list = []*models.SecurityExpectation{}
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"target_id":    targetID,
		"expectations": list,
		"count":        len(list),
	})
}

// EvaluateContradictionRequest payload
type EvaluateContradictionRequest struct {
	TargetID      string                           `json:"target_id"`
	AssetID       string                           `json:"asset_id"`
	Endpoint      string                           `json:"endpoint"`
	Expectation   models.SecurityExpectation       `json:"expectation"`
	ObservedState models.EpistemicObservationState `json:"observed_state"`
	EvidenceRefs  []string                         `json:"evidence_refs"`
}

// EvaluateContradiction handles POST /api/contradictions/evaluate
func (h *Handler) EvaluateContradiction(w http.ResponseWriter, r *http.Request) {
	if h.evidenceEng == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence engine is not configured", "")
		return
	}

	var req EvaluateContradictionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "INVALID_REQUEST", "malformed request", err.Error())
		return
	}

	con, err := h.evidenceEng.EvaluateContradiction(
		r.Context(), req.TargetID, req.AssetID, req.Endpoint,
		&req.Expectation, req.ObservedState, req.EvidenceRefs,
	)
	if err != nil {
		Error(w, http.StatusInternalServerError, "PROCESSING_ERROR", "evaluation failed", err.Error())
		return
	}

	if con == nil {
		JSON(w, http.StatusOK, map[string]interface{}{
			"contradiction_found": false,
			"message":             "Observed state aligns with expected security model",
		})
		return
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"contradiction_found": true,
		"contradiction":       con,
	})
}

// ListTargetContradictions handles GET /api/targets/{id}/contradictions
func (h *Handler) ListTargetContradictions(w http.ResponseWriter, r *http.Request) {
	if h.evidenceRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence repository is not configured", "")
		return
	}

	targetID := r.PathValue("id")
	assetID := r.URL.Query().Get("asset_id")

	list, err := h.evidenceRepo.ListSecurityContradictions(r.Context(), targetID, assetID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "STORAGE_ERROR", "failed to list contradictions", err.Error())
		return
	}
	if list == nil {
		list = []*models.SecurityContradiction{}
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"target_id":      targetID,
		"contradictions": list,
		"count":          len(list),
	})
}

// UpdateContradictionStatus handles PATCH /api/contradictions/{id}/status
func (h *Handler) UpdateContradictionStatus(w http.ResponseWriter, r *http.Request) {
	if h.evidenceRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence repository is not configured", "")
		return
	}

	id := r.PathValue("id")
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Error(w, http.StatusBadRequest, "INVALID_REQUEST", "malformed request", err.Error())
		return
	}

	con, err := h.evidenceRepo.GetSecurityContradiction(r.Context(), id)
	if err != nil {
		Error(w, http.StatusNotFound, "NOT_FOUND", "contradiction not found", err.Error())
		return
	}

	con.Status = models.ContradictionStatus(req.Status)
	con.UpdatedAt = time.Now().UTC()

	if err := h.evidenceRepo.SaveSecurityContradiction(r.Context(), con); err != nil {
		Error(w, http.StatusInternalServerError, "STORAGE_ERROR", "failed to update contradiction", err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"status":        "updated",
		"contradiction": con,
	})
}

// ListTargetOutliers handles GET /api/targets/{id}/outliers
func (h *Handler) ListTargetOutliers(w http.ResponseWriter, r *http.Request) {
	if h.evidenceRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence repository is not configured", "")
		return
	}

	targetID := r.PathValue("id")
	assetID := r.URL.Query().Get("asset_id")

	list, err := h.evidenceRepo.ListSecurityOutliers(r.Context(), targetID, assetID)
	if err != nil {
		Error(w, http.StatusInternalServerError, "STORAGE_ERROR", "failed to list outliers", err.Error())
		return
	}
	if list == nil {
		list = []*models.SecurityOutlier{}
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"target_id": targetID,
		"outliers":  list,
		"count":     len(list),
	})
}

// GetAssetInterest handles GET /api/targets/{id}/assets/{assetId}/interest
func (h *Handler) GetAssetInterest(w http.ResponseWriter, r *http.Request) {
	if h.evidenceEng == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence engine is not configured", "")
		return
	}

	targetID := r.PathValue("id")
	assetID := r.PathValue("assetId")
	hostname := r.URL.Query().Get("hostname")

	summary, err := h.evidenceEng.SynthesizeAssetInterest(r.Context(), targetID, assetID, hostname)
	if err != nil {
		Error(w, http.StatusInternalServerError, "PROCESSING_ERROR", "interest synthesis failed", err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"interest_summary": summary,
	})
}

// ListEvidenceTimeline handles GET /api/targets/{id}/evidence-timeline
func (h *Handler) ListEvidenceTimeline(w http.ResponseWriter, r *http.Request) {
	if h.evidenceRepo == nil {
		Error(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "evidence repository is not configured", "")
		return
	}

	targetID := r.PathValue("id")
	assetID := r.URL.Query().Get("asset_id")
	limitStr := r.URL.Query().Get("limit")
	limit := 50
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}

	events, err := h.evidenceRepo.ListTimelineEvents(r.Context(), targetID, assetID, limit)
	if err != nil {
		Error(w, http.StatusInternalServerError, "STORAGE_ERROR", "failed to list timeline events", err.Error())
		return
	}
	if events == nil {
		events = []*models.EvidenceTimelineEvent{}
	}

	JSON(w, http.StatusOK, map[string]interface{}{
		"target_id": targetID,
		"events":    events,
		"count":     len(events),
	})
}
