package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/storage"
)

func TestClient_Health(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(HealthPayload{
			Status:       "ok",
			Service:      "nexushunter-ai-analysis",
			Provider:     "mock",
			Model:        "gpt-4o-mini",
			RateLimitRPM: 60,
			BaseURL:      "http://localhost:8001",
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	health, err := client.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if health.Status != "ok" || health.Provider != "mock" {
		t.Errorf("unexpected health response: %+v", health)
	}
}

func TestClient_Analyze(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/analyze" {
			http.NotFound(w, r)
			return
		}
		var req AnalyzePayload
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		resp := AnalysisResultPayload{
			RunID:    req.RunID,
			TargetID: req.TargetID,
			AssetID:  req.AssetID,
			SignalsParsed: []SignalPayload{
				{
					ID:           "sig_1",
					TargetID:     req.TargetID,
					AssetID:      req.AssetID,
					SignalType:   "reflected_parameter",
					SeverityHint: "MEDIUM",
					Evidence:     "Reflected search param",
					Source:       "deterministic_detector",
				},
			},
			Candidates: []CandidatePayload{
				{
					ID:                      "cand_1",
					TargetID:                req.TargetID,
					AssetID:                 req.AssetID,
					Category:                "xss",
					Title:                   "Candidate XSS via Search Parameter",
					Description:             "Observed raw parameter reflection in HTML body",
					State:                   "CANDIDATE",
					ConfidenceScore:         0.75,
					Reasoning:               "Reflection observed without encoding",
					MissingEvidence:         "Need to verify execution in script context",
					ValidationSteps:         []string{"Submit harmless probe", "Check context escaping"},
					EvidenceReferences:      []string{"sig_1"},
					RecommendedVerification: "Manual DOM verification",
					IsMock:                  true,
				},
			},
			Summary:         "1 candidate identified",
			ConfidenceNotes: "Medium confidence",
			Status:          "COMPLETED",
			Provider:        "mock",
			Model:           "mock-provider",
			ExecutionTimeMS: 25,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	req := &AnalyzePayload{
		TargetID: "target_123",
		AssetID:  "asset_456",
		RunID:    "run_789",
		Evidence: StructuredEvidencePayload{
			TargetID: "target_123",
			AssetID:  "asset_456",
		},
	}

	res, err := client.Analyze(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected analyze error: %v", err)
	}
	if len(res.Candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(res.Candidates))
	}
	if res.Candidates[0].Category != "xss" {
		t.Errorf("expected category 'xss', got %s", res.Candidates[0].Category)
	}
}

func TestService_EndToEnd(t *testing.T) {
	memStore := storage.NewMemoryStorage()
	eventBus := events.NewMemoryEventBus(100)

	// Seed Asset Intelligence Data
	targetID := "tgt_test_1"
	assetID := "ast_test_1"

	err := memStore.SaveAsset(context.Background(), &models.Asset{
		ID:        assetID,
		TargetID:  targetID,
		Hostname:  "api.example.com",
		AssetType: "SUBDOMAIN",
		Status:    "LIVE",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("failed to save asset: %v", err)
	}

	err = memStore.SaveServiceObservation(context.Background(), &models.ServiceObservation{
		ID:              "svc_1",
		AssetID:         assetID,
		TargetID:        targetID,
		ServiceIdentity: "https://api.example.com:443",
		Scheme:          "https",
		Port:            443,
		StatusCode:      200,
		PageTitle:       "Test API Portal",
		WebServer:       "nginx/1.24",
		Headers:         map[string]string{"Server": "nginx/1.24"},
	})
	if err != nil {
		t.Fatalf("failed to save service obs: %v", err)
	}

	err = memStore.SaveTechnologyObservation(context.Background(), &models.TechnologyObservation{
		ID:              "tech_1",
		AssetID:         assetID,
		TargetID:        targetID,
		TechnologyName:  "Express",
		Category:        "Web Framework",
		Confidence:      models.ConfidenceHigh,
		DetectionSource: "header",
		Evidence:        "X-Powered-By: Express",
	})
	if err != nil {
		t.Fatalf("failed to save tech obs: %v", err)
	}

	// Mock HTTP Server simulating the Python FastAPI service
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req AnalyzePayload
		_ = json.NewDecoder(r.Body).Decode(&req)

		resp := AnalysisResultPayload{
			RunID:    req.RunID,
			TargetID: req.TargetID,
			AssetID:  req.AssetID,
			SignalsParsed: []SignalPayload{
				{
					ID:           "sig_test_1",
					TargetID:     req.TargetID,
					AssetID:      req.AssetID,
					SignalType:   "info_disclosure",
					SeverityHint: "LOW",
					Evidence:     "Server banner disclosure: nginx/1.24",
					Source:       "deterministic_detector",
				},
			},
			Candidates: []CandidatePayload{
				{
					ID:                      "cand_test_1",
					TargetID:                req.TargetID,
					AssetID:                 req.AssetID,
					Category:                "information_disclosure",
					Title:                   "Candidate Server Version Banner Disclosure",
					Description:             "Web server header exposes specific version information",
					State:                   "CANDIDATE",
					ConfidenceScore:         0.90,
					Reasoning:               "nginx/1.24 clearly reported in HTTP headers",
					MissingEvidence:         "No vulnerability confirmed without CVE check",
					ValidationSteps:         []string{"Verify banner presence across endpoints"},
					EvidenceReferences:      []string{"sig_test_1"},
					RecommendedVerification: "Audit response headers",
					IsMock:                  true,
				},
			},
			Summary:         "1 candidate signal identified",
			ConfidenceNotes: "High confidence in header presence",
			Status:          "COMPLETED",
			Provider:        "mock",
			Model:           "mock-provider",
			ExecutionTimeMS: 15,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	service := NewService(client, memStore, memStore, eventBus, nil)

	// 1. Run Asset Analysis
	run, candidates, err := service.AnalyzeAsset(context.Background(), targetID, assetID)
	if err != nil {
		t.Fatalf("AnalyzeAsset failed: %v", err)
	}

	if run.Status != models.AnalysisRunStatusCompleted {
		t.Errorf("expected status COMPLETED, got %s", run.Status)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}

	cand := candidates[0]
	if cand.State != models.CandidateStateCandidate {
		t.Errorf("expected state CANDIDATE, got %s", cand.State)
	}

	// 2. Query candidates via service
	cands, total, err := service.ListCandidates(context.Background(), models.CandidateFilter{
		TargetID: targetID,
	})
	if err != nil {
		t.Fatalf("ListCandidates failed: %v", err)
	}
	if total != 1 || len(cands) != 1 {
		t.Fatalf("expected 1 candidate returned, got total=%d, len=%d", total, len(cands))
	}

	// 3. Update candidate lifecycle state
	updated, err := service.UpdateCandidateState(context.Background(), cand.ID, models.UpdateCandidateStateRequest{
		State:  models.CandidateStateNeedsValidation,
		Reason: "Requires active safe validation payload",
	})
	if err != nil {
		t.Fatalf("UpdateCandidateState failed: %v", err)
	}
	if updated.State != models.CandidateStateNeedsValidation {
		t.Errorf("expected state %s, got %s", models.CandidateStateNeedsValidation, updated.State)
	}

	// 4. Query signals
	signals, err := service.ListSignals(context.Background(), targetID, assetID)
	if err != nil {
		t.Fatalf("ListSignals failed: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(signals))
	}

	// 5. Verify events published
	eventsList := eventBus.GetRecentEvents(50)
	if len(eventsList) < 3 {
		t.Errorf("expected at least 3 events published, got %d", len(eventsList))
	}
}
