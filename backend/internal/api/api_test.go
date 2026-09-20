package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/ai"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/config"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/intel"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/jobs"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/recon"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/storage"
)

func setupTestServer() (http.Handler, *Handler, *storage.MemoryStorage) {
	cfg := &config.Config{
		AppEnv:      "test",
		HTTPPort:    8080,
		ServiceName: "nexushunter-api",
		Version:     "0.1.0-alpha",
	}
	memStore := storage.NewMemoryStorage()
	scopeValidator := scope.NewValidator()
	eventBus := events.NewMemoryEventBus(100)
	jobMgr := jobs.NewManager(eventBus)

	engineCfg := recon.DefaultEngineConfig()
	pipeline := recon.NewPipeline(
		engineCfg,
		scopeValidator,
		eventBus,
		memStore,
		memStore,
		nil,
		nil,
		nil,
	)
	reconEngine := recon.NewEngine(
		pipeline,
		jobMgr,
		memStore,
		memStore,
		scopeValidator,
		eventBus,
	)

	aiClient := ai.NewClient("http://127.0.0.1:8001", time.Second)
	aiService := ai.NewService(aiClient, memStore, memStore, eventBus, nil)

	h := NewHandler(cfg, memStore, scopeValidator, jobMgr, eventBus, reconEngine, memStore, memStore, memStore, aiService)
	secEngine := intel.NewSecurityIntelligenceEngine(memStore, memStore, memStore, memStore, memStore, scopeValidator, eventBus)
	h.SetSecurityIntelligence(memStore, secEngine)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	router := NewRouter(h, logger)

	return router, h, memStore
}

func TestAPI_HealthCheck(t *testing.T) {
	router, _, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body["status"] != "ok" || body["service"] != "nexushunter-api" {
		t.Errorf("unexpected health response payload: %v", body)
	}
}

func TestAPI_Version(t *testing.T) {
	router, _, _ := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var body map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)

	if body["version"] != "0.1.0-alpha" {
		t.Errorf("expected version 0.1.0-alpha, got %v", body["version"])
	}
}

func TestAPI_TargetCRUD_AndValidation(t *testing.T) {
	router, _, _ := setupTestServer()

	// 1. Create Target with valid scope
	payload := CreateTargetRequest{
		Name:               "HackerOne Test Target",
		RootDomain:         "target.com",
		AllowedDomains:     []string{"target.com", "*.target.com"},
		AllowedURLPatterns: []string{"/api/*"},
		ExcludedPatterns:   []string{"admin.target.com"},
	}
	buf, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/targets", bytes.NewReader(buf))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var createdResp StandardResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &createdResp)
	if !createdResp.Success {
		t.Fatalf("expected success=true in created response")
	}

	targetData, _ := json.Marshal(createdResp.Data)
	var createdTarget models.Target
	_ = json.Unmarshal(targetData, &createdTarget)

	if createdTarget.ID == "" || createdTarget.RootDomain != "target.com" {
		t.Fatalf("target was not properly created: %+v", createdTarget)
	}

	// 2. Fetch list of targets
	listReq := httptest.NewRequest(http.MethodGet, "/api/targets", nil)
	listRec := httptest.NewRecorder()
	router.ServeHTTP(listRec, listReq)

	if listRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from GET /api/targets, got %d", listRec.Code)
	}

	// 3. Verify Scope dynamically via /api/scope/verify
	verifyPayload := VerifyScopeRequest{
		TargetID: createdTarget.ID,
		Hostname: "api.target.com",
		URL:      "https://api.target.com/api/v1/users",
	}
	vBuf, _ := json.Marshal(verifyPayload)
	vReq := httptest.NewRequest(http.MethodPost, "/api/scope/verify", bytes.NewReader(vBuf))
	vRec := httptest.NewRecorder()
	router.ServeHTTP(vRec, vReq)

	var vResp StandardResponse
	_ = json.Unmarshal(vRec.Body.Bytes(), &vResp)
	vMap := vResp.Data.(map[string]interface{})
	if vMap["in_scope"] != true {
		t.Fatalf("expected api.target.com to be in scope, got %v", vMap)
	}

	// 4. Test Excluded host via /api/scope/verify
	verifyExPayload := VerifyScopeRequest{
		TargetID: createdTarget.ID,
		Hostname: "admin.target.com",
		URL:      "https://admin.target.com/api/v1/test",
	}
	vexBuf, _ := json.Marshal(verifyExPayload)
	vexReq := httptest.NewRequest(http.MethodPost, "/api/scope/verify", bytes.NewReader(vexBuf))
	vexRec := httptest.NewRecorder()
	router.ServeHTTP(vexRec, vexReq)

	var vexResp StandardResponse
	_ = json.Unmarshal(vexRec.Body.Bytes(), &vexResp)
	vexMap := vexResp.Data.(map[string]interface{})
	if vexMap["in_scope"] == true {
		t.Fatalf("expected admin.target.com to be OUT of scope, got in_scope=true")
	}

	// 5. Delete Target
	delReq := httptest.NewRequest(http.MethodDelete, "/api/targets/"+createdTarget.ID, nil)
	delRec := httptest.NewRecorder()
	router.ServeHTTP(delRec, delReq)

	if delRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on target deletion, got %d", delRec.Code)
	}
}

func TestAPI_FailClosedMalformedTarget(t *testing.T) {
	router, _, _ := setupTestServer()

	// Malformed target: broad wildcard '*'
	badPayload := CreateTargetRequest{
		Name:           "Invalid Target",
		RootDomain:     "example.com",
		AllowedDomains: []string{"*"},
	}
	buf, _ := json.Marshal(badPayload)

	req := httptest.NewRequest(http.MethodPost, "/api/targets", bytes.NewReader(buf))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 Unprocessable Entity on malformed target, got %d", rec.Code)
	}
}

func TestAPI_ReconLifecycle_AndScopeEnforcement(t *testing.T) {
	router, _, memStore := setupTestServer()

	// 1. Create a valid target
	target := &models.Target{
		ID:             "target-recon-1",
		Name:           "Authorized Recon Target",
		RootDomain:     "example.com",
		AllowedDomains: []string{"example.com", "*.example.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_ = memStore.Create(context.Background(), target)

	// 2. Trigger recon job via POST /api/recon
	reconPayload := StartReconRequest{
		TargetID: target.ID,
		Options: recon.ReconOptions{
			SubdomainDiscovery: true,
			DNSResolution:      false, // test with passive discovery for mock speed
			HTTPProbe:          false,
			Crawl:              false,
		},
	}
	buf, _ := json.Marshal(reconPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/recon", bytes.NewReader(buf))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202 Accepted for POST /api/recon, got %d: %s", rec.Code, rec.Body.String())
	}

	var startResp StandardResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &startResp)
	jobMap := startResp.Data.(map[string]interface{})
	jobID := jobMap["id"].(string)
	if jobID == "" {
		t.Fatalf("expected job_id in response")
	}

	// 3. Query run via GET /api/recon/{id}
	// Allow slight time for async run initialization
	time.Sleep(50 * time.Millisecond)

	getReq := httptest.NewRequest(http.MethodGet, "/api/recon/"+jobID, nil)
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)

	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET /api/recon/%s, got %d", jobID, getRec.Code)
	}

	// 4. Cancel run via POST /api/recon/{id}/cancel
	cancelReq := httptest.NewRequest(http.MethodPost, "/api/recon/"+jobID+"/cancel", nil)
	cancelRec := httptest.NewRecorder()
	router.ServeHTTP(cancelRec, cancelReq)

	if cancelRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for cancel, got %d", cancelRec.Code)
	}

	// 5. Test Fail Closed: POST /api/recon with nonexistent target
	badTargetReq := StartReconRequest{TargetID: "nonexistent-target"}
	badBuf, _ := json.Marshal(badTargetReq)
	bReq := httptest.NewRequest(http.MethodPost, "/api/recon", bytes.NewReader(badBuf))
	bRec := httptest.NewRecorder()
	router.ServeHTTP(bRec, bReq)

	if bRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent target, got %d", bRec.Code)
	}

	// 6. Test Assets and URLs endpoints for target
	assetsReq := httptest.NewRequest(http.MethodGet, "/api/targets/"+target.ID+"/assets", nil)
	assetsRec := httptest.NewRecorder()
	router.ServeHTTP(assetsRec, assetsReq)
	if assetsRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET /api/targets/{id}/assets, got %d", assetsRec.Code)
	}

	urlsReq := httptest.NewRequest(http.MethodGet, "/api/targets/"+target.ID+"/urls", nil)
	urlsRec := httptest.NewRecorder()
	router.ServeHTTP(urlsRec, urlsReq)
	if urlsRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET /api/targets/{id}/urls, got %d", urlsRec.Code)
	}
}

func TestAPI_AIEndpoints(t *testing.T) {
	// Spin up a mock AI service HTTP server
	aiMockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/health" {
			_ = json.NewEncoder(w).Encode(ai.HealthPayload{
				Status:       "ok",
				Service:      "nexushunter-ai-analysis",
				Provider:     "mock",
				Model:        "mock-model",
				RateLimitRPM: 60,
			})
			return
		}
		if r.URL.Path == "/api/v1/analyze" {
			var req ai.AnalyzePayload
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(ai.AnalysisResultPayload{
				RunID:    req.RunID,
				TargetID: req.TargetID,
				AssetID:  req.AssetID,
				SignalsParsed: []ai.SignalPayload{
					{
						ID:           "sig_api_1",
						TargetID:     req.TargetID,
						AssetID:      req.AssetID,
						SignalType:   "test_signal",
						SeverityHint: "LOW",
						Evidence:     "Test signal evidence",
						Source:       "detector",
					},
				},
				Candidates: []ai.CandidatePayload{
					{
						ID:              "cand_api_1",
						TargetID:        req.TargetID,
						AssetID:         req.AssetID,
						Category:        "misconfiguration",
						Title:           "Candidate Test Finding",
						Description:     "Test finding candidate description",
						State:           "CANDIDATE",
						ConfidenceScore: 0.85,
						Reasoning:       "Deterministic signal detected",
						ValidationSteps: []string{"Step 1"},
					},
				},
				Summary:         "1 candidate generated",
				Status:          "COMPLETED",
				Provider:        "mock",
				Model:           "mock-model",
				ExecutionTimeMS: 10,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer aiMockServer.Close()

	cfg := &config.Config{
		AppEnv:      "test",
		HTTPPort:    8080,
		ServiceName: "nexushunter-api",
		Version:     "0.1.0-alpha",
	}
	memStore := storage.NewMemoryStorage()
	scopeValidator := scope.NewValidator()
	eventBus := events.NewMemoryEventBus(100)
	jobMgr := jobs.NewManager(eventBus)

	engineCfg := recon.DefaultEngineConfig()
	pipeline := recon.NewPipeline(engineCfg, scopeValidator, eventBus, memStore, memStore, nil, nil, nil)
	reconEngine := recon.NewEngine(pipeline, jobMgr, memStore, memStore, scopeValidator, eventBus)

	aiClient := ai.NewClient(aiMockServer.URL, 5*time.Second)
	aiService := ai.NewService(aiClient, memStore, memStore, eventBus, nil)
	handler := NewHandler(cfg, memStore, scopeValidator, jobMgr, eventBus, reconEngine, memStore, memStore, memStore, aiService)
	router := NewRouter(handler, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// 1. Test AI Health endpoint
	healthReq := httptest.NewRequest(http.MethodGet, "/api/ai/health", nil)
	healthRec := httptest.NewRecorder()
	router.ServeHTTP(healthRec, healthReq)
	if healthRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET /api/ai/health, got %d", healthRec.Code)
	}

	// 2. Create Target & Asset
	target := &models.Target{
		ID:             "tgt_ai_test",
		Name:           "AI Scope Test",
		RootDomain:     "example.com",
		AllowedDomains: []string{"example.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_ = memStore.Create(context.Background(), target)

	asset := &models.Asset{
		ID:        "ast_ai_test",
		TargetID:  target.ID,
		Hostname:  "api.example.com",
		AssetType: "SUBDOMAIN",
		Status:    "LIVE",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
	}
	_ = memStore.SaveAsset(context.Background(), asset)

	// 3. Trigger Asset Analysis
	runPayload, _ := json.Marshal(models.TriggerAnalysisRequest{
		TargetID: target.ID,
		AssetID:  asset.ID,
	})
	runReq := httptest.NewRequest(http.MethodPost, "/api/analysis/run", bytes.NewReader(runPayload))
	runReq.Header.Set("Content-Type", "application/json")
	runRec := httptest.NewRecorder()
	router.ServeHTTP(runRec, runReq)

	if runRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for POST /api/analysis/run, got %d, body: %s", runRec.Code, runRec.Body.String())
	}

	// 4. List Finding Candidates
	candsReq := httptest.NewRequest(http.MethodGet, "/api/findings/candidates?target_id="+target.ID, nil)
	candsRec := httptest.NewRecorder()
	router.ServeHTTP(candsRec, candsReq)

	if candsRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET /api/findings/candidates, got %d", candsRec.Code)
	}

	var candsResp struct {
		Success bool `json:"success"`
		Data    struct {
			Candidates []*models.FindingCandidate `json:"candidates"`
			Total      int                        `json:"total"`
		} `json:"data"`
	}
	if err := json.NewDecoder(candsRec.Body).Decode(&candsResp); err != nil {
		t.Fatalf("failed to decode candidates resp: %v", err)
	}
	if candsResp.Data.Total != 1 || len(candsResp.Data.Candidates) != 1 {
		t.Fatalf("expected 1 candidate, got total=%d", candsResp.Data.Total)
	}

	candID := candsResp.Data.Candidates[0].ID

	// 5. Get Candidate by ID
	candReq := httptest.NewRequest(http.MethodGet, "/api/findings/candidates/"+candID, nil)
	candRec := httptest.NewRecorder()
	router.ServeHTTP(candRec, candReq)
	if candRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET /api/findings/candidates/{id}, got %d", candRec.Code)
	}

	// 6. Update Candidate State to NEEDS_VALIDATION
	statePayload, _ := json.Marshal(models.UpdateCandidateStateRequest{
		State:  models.CandidateStateNeedsValidation,
		Reason: "Requires active proof",
	})
	patchReq := httptest.NewRequest(http.MethodPatch, "/api/findings/candidates/"+candID+"/state", bytes.NewReader(statePayload))
	patchReq.Header.Set("Content-Type", "application/json")
	patchRec := httptest.NewRecorder()
	router.ServeHTTP(patchRec, patchReq)
	if patchRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for PATCH /api/findings/candidates/{id}/state, got %d", patchRec.Code)
	}

	// 7. List Signals for Target
	signalsReq := httptest.NewRequest(http.MethodGet, "/api/targets/"+target.ID+"/signals", nil)
	signalsRec := httptest.NewRecorder()
	router.ServeHTTP(signalsRec, signalsReq)
	if signalsRec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for GET /api/targets/{id}/signals, got %d", signalsRec.Code)
	}
}

func TestAPI_SecurityIntelligence_And_Validation(t *testing.T) {
	router, _, memStore := setupTestServer()
	ctx := context.Background()

	// 1. Create Target
	target := &models.Target{
		ID:             "tgt-sec-01",
		Name:           "Security Target",
		RootDomain:     "example.com",
		AllowedDomains: []string{"example.com", "app.example.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	if err := memStore.Create(ctx, target); err != nil {
		t.Fatalf("failed to create target: %v", err)
	}

	// 2. Populate Intelligence Data
	now := time.Now().UTC()
	_ = memStore.SaveGraphNode(ctx, &models.GraphNode{
		ID:       "node-01",
		TargetID: target.ID,
		Type:     models.GraphNodeDomain,
		Label:    "app.example.com",
	})
	_ = memStore.RecordTemporalChange(ctx, &models.TemporalChangeRecord{
		ID:           "tc-01",
		TargetID:     target.ID,
		ChangeType:   models.TemporalChangeNewEndpoint,
		Summary:      "Discovered /api/v1/auth",
		CurrentValue: "/api/v1/auth",
		DetectedAt:   now,
	})
	_ = memStore.RecordInvariantSignal(ctx, &models.InvariantSignal{
		ID:                 "inv-01",
		TargetID:           target.ID,
		Endpoint:           "https://app.example.com/api/v1/auth",
		ObservedCondition:  "Wildcard CORS Access Control detected",
		InvariantViolation: "Unauthenticated CORS Reflection",
		Confidence:         0.95,
		DetectedAt:         now,
	})
	cluster := &models.InvestigationCluster{
		ID:                  "cl-01",
		TargetID:            target.ID,
		Title:               "Authentication Boundary Exposure",
		Category:            "AUTH_BOUNDARY",
		PriorityScore:       85,
		PriorityExplanation: "CORS anomaly on active auth route",
		RelatedEndpoints:    []string{"https://app.example.com/api/v1/auth"},
		Confidence:          0.90,
		Status:              models.ClusterStatusActive,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	_ = memStore.SaveInvestigationCluster(ctx, cluster)

	// 3. Test GET Graph
	req := httptest.NewRequest(http.MethodGet, "/api/targets/"+target.ID+"/graph", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET graph, got %d", rec.Code)
	}

	// 4. Test GET Temporal Changes
	req = httptest.NewRequest(http.MethodGet, "/api/targets/"+target.ID+"/temporal-changes", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET temporal-changes, got %d", rec.Code)
	}

	// 5. Test GET Invariants
	req = httptest.NewRequest(http.MethodGet, "/api/targets/"+target.ID+"/invariants", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET invariants, got %d", rec.Code)
	}

	// 6. Test GET Clusters
	req = httptest.NewRequest(http.MethodGet, "/api/targets/"+target.ID+"/investigation-clusters", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET investigation-clusters, got %d", rec.Code)
	}

	// 7. Test PATCH Cluster Status
	statusBody, _ := json.Marshal(map[string]string{"status": "INVESTIGATING"})
	req = httptest.NewRequest(http.MethodPatch, "/api/investigation-clusters/cl-01/status", bytes.NewReader(statusBody))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for PATCH cluster status, got %d", rec.Code)
	}

	// 8. Test GET Research Memory
	req = httptest.NewRequest(http.MethodGet, "/api/targets/"+target.ID+"/research-memory", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET research-memory, got %d", rec.Code)
	}

	// 9. Test Controlled Validation - Scope Violation (Out of scope)
	// Try with candidate that has out-of-scope URL
	badCand := &models.FindingCandidate{
		ID:              "cand-bad-01",
		TargetID:        target.ID,
		ValidationSteps: []string{"https://evil.attacker.com/malicious"},
		State:           models.CandidateStateNeedsValidation,
	}
	_ = memStore.SaveFindingCandidate(ctx, badCand)

	badValReq, _ := json.Marshal(models.ControlledValidationRequest{
		TargetID:    target.ID,
		CandidateID: badCand.ID,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/validation/execute", bytes.NewReader(badValReq))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for out-of-scope validation, got %d", rec.Code)
	}
}


