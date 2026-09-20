package intel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/recon"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/storage"
)

func TestSecurityIntelligenceEngine_IngestAndCluster(t *testing.T) {
	memStore := storage.NewMemoryStorage()
	scopeSvc := scope.NewValidator()
	eventBus := events.NewMemoryEventBus(100)

	engine := NewSecurityIntelligenceEngine(
		memStore,
		memStore,
		memStore,
		memStore,
		memStore,
		scopeSvc,
		eventBus,
	)

	ctx := context.Background()

	target := &models.Target{
		ID:             "tgt-test-intel",
		Name:           "secure.example.com",
		AllowedDomains: []string{"secure.example.com"},
		Status:         models.TargetStatusActive,
	}
	_ = memStore.Create(ctx, target)

	probe := &recon.HTTPProbeResult{
		Hostname:      "secure.example.com",
		URL:           "https://secure.example.com/api/v1/auth",
		StatusCode:    200,
		ServerHeader:  "nginx/1.24",
		ContentType:   "application/json",
		ContentLength: 128,
		ResponseTime:  45 * time.Millisecond,
		Headers: map[string]string{
			"Access-Control-Allow-Origin": "*",
		},
		Timestamp: time.Now().UTC(),
	}

	dnsRecords := []*models.DNSRecord{
		{
			ID:         "dns-1",
			AssetID:    "asset-1",
			RecordType: "A",
			Value:      "93.184.216.34",
			FirstSeen:  time.Now().UTC(),
			LastSeen:   time.Now().UTC(),
		},
	}

	err := engine.IngestProbeResult(ctx, target.ID, "asset-1", "secure.example.com", probe, dnsRecords, nil)
	if err != nil {
		t.Fatalf("IngestProbeResult returned unexpected error: %v", err)
	}

	// 1. Verify Topology Graph Nodes and Edges
	graph, err := memStore.GetTargetGraph(ctx, target.ID)
	if err != nil {
		t.Fatalf("failed to retrieve target graph: %v", err)
	}
	if len(graph.Nodes) == 0 {
		t.Errorf("expected graph nodes generated, got 0")
	}
	if len(graph.Edges) == 0 {
		t.Errorf("expected graph edges generated, got 0")
	}

	// 2. Verify Investigation Clusters
	clusters, err := memStore.ListInvestigationClusters(ctx, target.ID)
	if err != nil || len(clusters) == 0 {
		t.Fatalf("expected investigation clusters synthesized, got %d", len(clusters))
	}

	cluster := clusters[0]
	if cluster.PriorityScore <= 0 {
		t.Errorf("expected positive priority score, got %d", cluster.PriorityScore)
	}
	if len(cluster.PriorityFactors) != 4 {
		t.Errorf("expected 4 priority factors, got %d", len(cluster.PriorityFactors))
	}

	// 3. Ingest an updated probe causing temporal drift
	updatedProbe := &recon.HTTPProbeResult{
		Hostname:      "secure.example.com",
		URL:           "https://secure.example.com/api/v1/auth",
		StatusCode:    403,
		ServerHeader:  "Cloudflare",
		ContentType:   "text/html",
		ContentLength: 512,
		ResponseTime:  120 * time.Millisecond,
		Timestamp:     time.Now().UTC(),
	}

	_ = engine.IngestProbeResult(ctx, target.ID, "asset-1", "secure.example.com", updatedProbe, dnsRecords, nil)

	// Verify Behavior Differences were detected
	diffs, err := memStore.ListBehaviorDifferences(ctx, target.ID)
	if err != nil || len(diffs) == 0 {
		t.Fatalf("expected behavior differences detected after status change, got %d", len(diffs))
	}

	// Verify State Invariants were triggered
	invariants, err := memStore.ListInvariantSignals(ctx, target.ID)
	if err != nil || len(invariants) == 0 {
		t.Fatalf("expected invariant signals triggered, got %d", len(invariants))
	}
}

func TestSecurityIntelligenceEngine_ControlledValidation_ScopeAndSSRF(t *testing.T) {
	memStore := storage.NewMemoryStorage()
	scopeSvc := scope.NewValidator()
	eventBus := events.NewMemoryEventBus(100)

	engine := NewSecurityIntelligenceEngine(
		memStore,
		memStore,
		memStore,
		memStore,
		memStore,
		scopeSvc,
		eventBus,
	)

	ctx := context.Background()

	target := &models.Target{
		ID:             "tgt-val-test",
		Name:           "audit.example.com",
		AllowedDomains: []string{"audit.example.com"},
		Status:         models.TargetStatusActive,
	}
	_ = memStore.Create(ctx, target)

	// Case 1: Out-of-scope domain is rejected
	badCand := &models.FindingCandidate{
		ID:              "cand-bad-scope",
		TargetID:        target.ID,
		ValidationSteps: []string{"https://evil-unauthorized.org/exploit"},
		State:           models.CandidateStateNeedsValidation,
	}
	_ = memStore.SaveFindingCandidate(ctx, badCand)

	reqOutOfScope := &models.ControlledValidationRequest{
		TargetID:    target.ID,
		CandidateID: badCand.ID,
	}
	_, err := engine.ExecuteControlledValidation(ctx, reqOutOfScope)
	if err == nil {
		t.Fatal("expected out-of-scope validation to fail, got nil error")
	}
	if !strings.Contains(err.Error(), "SCOPE_VIOLATION") {
		t.Errorf("expected SCOPE_VIOLATION error, got: %v", err)
	}

	// Case 2: In-scope but SSRF loopback is rejected
	targetWithLoopback := &models.Target{
		ID:             "tgt-val-loopback",
		Name:           "localhost",
		AllowedDomains: []string{"127.0.0.1", "localhost", "169.254.169.254"},
		Status:         models.TargetStatusActive,
	}
	_ = memStore.Create(ctx, targetWithLoopback)

	loopbackCand := &models.FindingCandidate{
		ID:              "cand-loopback",
		TargetID:        targetWithLoopback.ID,
		ValidationSteps: []string{"http://127.0.0.1:8080/internal/keys"},
		State:           models.CandidateStateNeedsValidation,
	}
	_ = memStore.SaveFindingCandidate(ctx, loopbackCand)

	reqLoopback := &models.ControlledValidationRequest{
		TargetID:    targetWithLoopback.ID,
		CandidateID: loopbackCand.ID,
	}
	_, err = engine.ExecuteControlledValidation(ctx, reqLoopback)
	if err == nil {
		t.Fatal("expected SSRF loopback validation to be blocked, got nil error")
	}
	if !strings.Contains(err.Error(), "SSRF_VIOLATION") {
		t.Errorf("expected SSRF_VIOLATION error, got: %v", err)
	}

	// Case 3: Cloud metadata 169.254.169.254 is rejected
	metadataCand := &models.FindingCandidate{
		ID:              "cand-metadata",
		TargetID:        targetWithLoopback.ID,
		ValidationSteps: []string{"http://169.254.169.254/latest/meta-data/"},
		State:           models.CandidateStateNeedsValidation,
	}
	_ = memStore.SaveFindingCandidate(ctx, metadataCand)

	reqMetadata := &models.ControlledValidationRequest{
		TargetID:    targetWithLoopback.ID,
		CandidateID: metadataCand.ID,
	}
	_, err = engine.ExecuteControlledValidation(ctx, reqMetadata)
	if err == nil {
		t.Fatal("expected cloud metadata validation to be blocked, got nil error")
	}
	if !strings.Contains(err.Error(), "SSRF_VIOLATION") {
		t.Errorf("expected SSRF_VIOLATION error, got: %v", err)
	}
}
