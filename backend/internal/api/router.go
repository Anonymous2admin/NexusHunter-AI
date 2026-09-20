package api

import (
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// NewRouter registers all API routes and middleware.
func NewRouter(h *Handler, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	// Health & Version Endpoints
	mux.HandleFunc("GET /api/health", h.HealthCheck)
	mux.HandleFunc("GET /api/version", h.Version)

	// Target Scope System
	mux.HandleFunc("POST /api/targets", h.CreateTarget)
	mux.HandleFunc("GET /api/targets", h.ListTargets)
	mux.HandleFunc("GET /api/targets/{id}", h.GetTarget)
	mux.HandleFunc("DELETE /api/targets/{id}", h.DeleteTarget)
	mux.HandleFunc("GET /api/targets/{id}/assets", h.ListTargetAssets)
	mux.HandleFunc("GET /api/targets/{id}/urls", h.ListTargetURLs)

	// Asset Intelligence & Fingerprinting
	mux.HandleFunc("GET /api/targets/{id}/intelligence", h.GetTargetIntelligence)
	mux.HandleFunc("GET /api/targets/{id}/technologies", h.ListTargetTechnologies)
	mux.HandleFunc("GET /api/targets/{id}/services", h.ListTargetServices)
	mux.HandleFunc("GET /api/targets/{id}/changes", h.ListTargetChanges)
	mux.HandleFunc("GET /api/targets/{id}/assets/{assetId}", h.GetAssetDetail)
	mux.HandleFunc("POST /api/assets/{id}/tags", h.AddAssetTag)
	mux.HandleFunc("DELETE /api/assets/{id}/tags/{tag}", h.DeleteAssetTag)

	// Scope Validation Service
	mux.HandleFunc("POST /api/scope/verify", h.VerifyScope)

	// Job System Endpoints
	mux.HandleFunc("POST /api/jobs", h.CreateJob)
	mux.HandleFunc("GET /api/jobs", h.ListJobs)
	mux.HandleFunc("GET /api/jobs/{id}", h.GetJob)

	// High-Speed Recon Engine Endpoints
	mux.HandleFunc("POST /api/recon", h.StartRecon)
	mux.HandleFunc("GET /api/recon/{id}", h.GetReconRun)
	mux.HandleFunc("POST /api/recon/{id}/cancel", h.CancelRecon)

	// Phase 4: AI Analysis & Finding Candidates Endpoints
	mux.HandleFunc("POST /api/analysis/run", h.TriggerAnalysis)
	mux.HandleFunc("POST /api/ai/analyze", h.TriggerAnalysis)
	mux.HandleFunc("POST /api/targets/{id}/analyze", h.TriggerTargetAnalysis)
	mux.HandleFunc("POST /api/targets/{id}/assets/{assetId}/analyze", h.TriggerAssetAnalysis)
	mux.HandleFunc("GET /api/targets/{id}/analysis-runs", h.ListTargetAnalysisRuns)
	mux.HandleFunc("GET /api/analysis-runs/{id}", h.GetAnalysisRun)
	mux.HandleFunc("GET /api/findings/candidates", h.ListFindingCandidates)
	mux.HandleFunc("GET /api/findings/candidates/{id}", h.GetFindingCandidate)
	mux.HandleFunc("PATCH /api/findings/candidates/{id}/state", h.UpdateCandidateState)
	mux.HandleFunc("GET /api/targets/{id}/candidates", h.ListTargetCandidates)
	mux.HandleFunc("GET /api/candidates/{id}", h.GetFindingCandidate)
	mux.HandleFunc("PATCH /api/candidates/{id}/state", h.UpdateCandidateState)
	mux.HandleFunc("GET /api/targets/{id}/signals", h.ListTargetSignals)
	mux.HandleFunc("GET /api/ai/health", h.GetAIHealth)

	// Phase 5: Security Intelligence & Investigation Engine Endpoints
	mux.HandleFunc("GET /api/targets/{id}/graph", h.GetTargetGraph)
	mux.HandleFunc("GET /api/targets/{id}/temporal-changes", h.ListTargetTemporalChanges)
	mux.HandleFunc("GET /api/targets/{id}/invariants", h.ListTargetInvariants)
	mux.HandleFunc("GET /api/targets/{id}/behavior-diffs", h.ListTargetBehaviorDiffs)
	mux.HandleFunc("GET /api/targets/{id}/investigation-clusters", h.ListInvestigationClusters)
	mux.HandleFunc("PATCH /api/investigation-clusters/{id}/status", h.UpdateClusterStatus)
	mux.HandleFunc("GET /api/targets/{id}/research-memory", h.GetResearchMemory)
	mux.HandleFunc("POST /api/validation/execute", h.ExecuteControlledValidation)

	// Phase 6: Evidence Intelligence & Security Reasoning Endpoints
	mux.HandleFunc("POST /api/evidence", h.RecordEvidence)
	mux.HandleFunc("GET /api/evidence/{id}", h.GetEvidence)
	mux.HandleFunc("GET /api/evidence/{id}/integrity", h.VerifyEvidenceIntegrity)
	mux.HandleFunc("GET /api/targets/{id}/evidence", h.ListTargetEvidence)
	mux.HandleFunc("GET /api/assets/{id}/evidence", h.ListAssetEvidence)
	mux.HandleFunc("POST /api/evidence/diff", h.ComputeEvidenceDiff)
	mux.HandleFunc("GET /api/evidence/diffs/{id}", h.GetEvidenceDiff)
	mux.HandleFunc("GET /api/targets/{id}/diffs", h.ListTargetDiffs)
	mux.HandleFunc("POST /api/expectations", h.CreateSecurityExpectation)
	mux.HandleFunc("GET /api/targets/{id}/expectations", h.ListTargetExpectations)
	mux.HandleFunc("POST /api/contradictions/evaluate", h.EvaluateContradiction)
	mux.HandleFunc("GET /api/targets/{id}/contradictions", h.ListTargetContradictions)
	mux.HandleFunc("PATCH /api/contradictions/{id}/status", h.UpdateContradictionStatus)
	mux.HandleFunc("GET /api/targets/{id}/outliers", h.ListTargetOutliers)
	mux.HandleFunc("GET /api/targets/{id}/assets/{assetId}/interest", h.GetAssetInterest)
	mux.HandleFunc("GET /api/targets/{id}/evidence-timeline", h.ListEvidenceTimeline)

	// Phase 7: Security Reasoning, Hypothesis & Investigation Intelligence Engine Endpoints
	mux.HandleFunc("GET /api/signals", h.ListSignals)
	mux.HandleFunc("GET /api/signals/{id}", h.GetSignal)
	mux.HandleFunc("PATCH /api/signals/{id}/status", h.UpdateSignalStatus)

	mux.HandleFunc("GET /api/hypotheses", h.ListHypotheses)
	mux.HandleFunc("POST /api/hypotheses", h.CreateHypothesis)
	mux.HandleFunc("GET /api/hypotheses/{id}", h.GetHypothesis)
	mux.HandleFunc("POST /api/hypotheses/{id}/status", h.UpdateHypothesisStatus)
	mux.HandleFunc("GET /api/hypotheses/{id}/evidence", h.GetHypothesisEvidence)
	mux.HandleFunc("GET /api/hypotheses/{id}/alternatives", h.GetHypothesisAlternatives)

	mux.HandleFunc("GET /api/hypothesis-groups", h.ListHypothesisGroups)
	mux.HandleFunc("GET /api/hypothesis-groups/{id}", h.GetHypothesisGroup)

	mux.HandleFunc("GET /api/investigations", h.ListInvestigations)
	mux.HandleFunc("POST /api/investigations", h.PlanInvestigation)
	mux.HandleFunc("GET /api/investigations/{id}", h.GetInvestigation)
	mux.HandleFunc("POST /api/investigations/{id}/cancel", h.CancelInvestigation)
	mux.HandleFunc("POST /api/investigations/{id}/execute", h.ExecuteInvestigationStep)
	mux.HandleFunc("GET /api/investigations/{id}/steps", h.GetInvestigationSteps)

	mux.HandleFunc("GET /api/assets/{id}/signals", h.ListAssetSignals)
	mux.HandleFunc("GET /api/assets/{id}/hypotheses", h.ListAssetHypotheses)
	mux.HandleFunc("GET /api/assets/{id}/investigations", h.ListAssetInvestigations)
	mux.HandleFunc("GET /api/assets/{id}/trust-boundaries", h.ListAssetTrustBoundaries)
	mux.HandleFunc("GET /api/assets/{id}/permission-matrix", h.ListAssetPermissionMatrix)
	mux.HandleFunc("POST /api/assets/{id}/permission-matrix", h.RecordPermissionMatrixEntry)
	mux.HandleFunc("GET /api/assets/{id}/security-controls", h.ListAssetSecurityControls)

	mux.HandleFunc("GET /api/auth-contexts", h.ListAuthContexts)
	mux.HandleFunc("POST /api/auth-contexts", h.CreateAuthContext)

	mux.HandleFunc("POST /api/reasoning/analyze", h.TriggerReasoningCycle)
	mux.HandleFunc("POST /api/reasoning/ai-assist", h.AIAssistedReasoning)

	// Event Telemetry
	mux.HandleFunc("GET /api/events", h.ListEvents)

	// Apply Middlewares
	var handler http.Handler = mux
	handler = corsMiddleware(handler)
	handler = loggingMiddleware(handler, logger)
	handler = recoveryMiddleware(handler, logger)

	return handler
}

func corsMiddleware(next http.Handler) http.Handler {
	allowedOriginsMap := map[string]bool{
		"http://localhost:3000":  true,
		"http://127.0.0.1:3000":  true,
		"http://localhost:5173":  true,
		"http://127.0.0.1:5173":  true,
		"http://localhost:8080":  true,
		"http://127.0.0.1:8080":  true,
		"http://localhost:8081":  true,
		"http://127.0.0.1:8081":  true,
	}

	envOrigins := os.Getenv("CORS_ALLOWED_ORIGINS")
	if envOrigins != "" {
		for _, o := range strings.Split(envOrigins, ",") {
			trimmed := strings.TrimSpace(o)
			if trimmed != "" {
				allowedOriginsMap[trimmed] = true
			}
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		isAllowed := false

		if origin != "" {
			if allowedOriginsMap[origin] {
				isAllowed = true
			} else {
				u, err := url.Parse(origin)
				if err == nil && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || strings.HasSuffix(u.Hostname(), ".preview.app.github.dev") || strings.HasSuffix(u.Hostname(), ".run.app")) {
					isAllowed = true
				}
			}
		}

		if isAllowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-Nexus-Mode")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.Header().Set("Vary", "Origin")
		}

		if r.Method == http.MethodOptions {
			if origin != "" && !isAllowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriterInterceptor{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)
		duration := time.Since(start)

		logger.Info("HTTP request handled",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rw.statusCode),
			slog.Duration("duration", duration),
			slog.String("remote_addr", r.RemoteAddr),
		)
	})
}

func recoveryMiddleware(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("panic recovered in HTTP handler", slog.Any("panic", rec))
				Error(w, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "an unexpected panic occurred", "")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type responseWriterInterceptor struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriterInterceptor) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
