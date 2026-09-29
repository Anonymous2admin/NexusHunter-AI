package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// TestMultiProcessJobStateCAS tests multi-process optimistic state transition guards (Requirement 1)
func TestMultiProcessJobStateCAS(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStorage()

	job := &models.ScanJob{
		ID:        "job-cas-001",
		TargetID:  "target-cas",
		Type:      "PORT_SCAN",
		Status:    models.JobStatusQueued,
		CreatedAt: time.Now().UTC(),
		Metadata:  map[string]interface{}{"depth": 1},
	}

	if err := repo.CreateJob(ctx, job); err != nil {
		t.Fatalf("failed to create job: %v", err)
	}

	// 1. Valid Transition: QUEUED -> RUNNING
	now := time.Now().UTC()
	job.Status = models.JobStatusRunning
	job.StartedAt = &now
	evt1 := &models.Event{
		EventID:       "evt-run-1",
		EventType:     models.EventJobStarted,
		JobID:         job.ID,
		TargetID:      job.TargetID,
		Timestamp:     now,
		PreviousState: string(models.JobStatusQueued),
		NewState:      string(models.JobStatusRunning),
	}
	err := repo.TransitionJobWithAuditEvent(ctx, job, []models.JobStatus{models.JobStatusQueued}, evt1)
	if err != nil {
		t.Fatalf("expected successful transition QUEUED -> RUNNING, got %v", err)
	}

	// 2. Simulated Concurrent Conflict: another worker attempts QUEUED -> RUNNING on already RUNNING job
	staleJob := *job
	staleJob.Status = models.JobStatusRunning
	errStale := repo.TransitionJobWithAuditEvent(ctx, &staleJob, []models.JobStatus{models.JobStatusQueued}, evt1)
	if errStale == nil {
		t.Fatalf("expected conflict on stale transition guard, got nil")
	}
	if !errors.Is(errStale, ErrJobStateConflict) {
		t.Fatalf("expected ErrJobStateConflict, got %v", errStale)
	}

	// 3. Concurrent Race: Worker A and Worker B both try to complete the job
	compTime := time.Now().UTC()
	jobCompleteA := *job
	jobCompleteA.Status = models.JobStatusCompleted
	jobCompleteA.CompletedAt = &compTime

	jobCompleteB := *job
	jobCompleteB.Status = models.JobStatusCompleted
	jobCompleteB.CompletedAt = &compTime

	var wg sync.WaitGroup
	var successCount int
	var conflictCount int
	var mu sync.Mutex

	for i := 0; i < 2; i++ {
		wg.Add(1)
		candidate := &jobCompleteA
		if i == 1 {
			candidate = &jobCompleteB
		}
		go func(j *models.ScanJob, idx int) {
			defer wg.Done()
			evt := &models.Event{
				EventID:       fmt.Sprintf("evt-comp-%d", idx),
				EventType:     models.EventJobCompleted,
				JobID:         j.ID,
				TargetID:      j.TargetID,
				Timestamp:     compTime,
				PreviousState: string(models.JobStatusRunning),
				NewState:      string(models.JobStatusCompleted),
			}
			tErr := repo.TransitionJobWithAuditEvent(ctx, j, []models.JobStatus{models.JobStatusRunning}, evt)
			mu.Lock()
			defer mu.Unlock()
			if tErr == nil {
				successCount++
			} else if errors.Is(tErr, ErrJobStateConflict) {
				conflictCount++
			}
		}(candidate, i)
	}
	wg.Wait()

	if successCount != 1 || conflictCount != 1 {
		t.Fatalf("expected exactly 1 success and 1 conflict in concurrent transition, got success=%d, conflict=%d", successCount, conflictCount)
	}

	// Verify final persisted status
	finalJob, err := repo.GetJobByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("failed to fetch final job: %v", err)
	}
	if finalJob.Status != models.JobStatusCompleted {
		t.Fatalf("expected final status COMPLETED, got %s", finalJob.Status)
	}
}

// TestMemoryJobRepositoryParityOrdering verifies deterministic sorting: created_at DESC, tie-breaker ID DESC (Requirement 3)
func TestMemoryJobRepositoryParityOrdering(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStorage()

	baseTime := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	targetID := "target-order-test"

	j1 := &models.ScanJob{ID: "job-001", TargetID: targetID, CreatedAt: baseTime.Add(1 * time.Minute)}
	j2 := &models.ScanJob{ID: "job-002", TargetID: targetID, CreatedAt: baseTime.Add(2 * time.Minute)}
	// Identical timestamp to test tie-breaker ID DESC
	j3 := &models.ScanJob{ID: "job-003", TargetID: targetID, CreatedAt: baseTime.Add(3 * time.Minute)}
	j4 := &models.ScanJob{ID: "job-004", TargetID: targetID, CreatedAt: baseTime.Add(3 * time.Minute)}

	_ = repo.CreateJob(ctx, j1)
	_ = repo.CreateJob(ctx, j2)
	_ = repo.CreateJob(ctx, j3)
	_ = repo.CreateJob(ctx, j4)

	list, err := repo.ListJobs(ctx, targetID)
	if err != nil {
		t.Fatalf("failed to list jobs: %v", err)
	}

	if len(list) != 4 {
		t.Fatalf("expected 4 jobs, got %d", len(list))
	}

	expectedOrder := []string{"job-004", "job-003", "job-002", "job-001"}
	for i, exp := range expectedOrder {
		if list[i].ID != exp {
			t.Errorf("ordering mismatch at index %d: expected %s, got %s", i, exp, list[i].ID)
		}
	}
}

// TestMemoryDeepCopyIsolation tests that repository copies metadata to prevent mutation leaks (Requirement 4)
func TestMemoryDeepCopyIsolation(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryStorage()

	callerMeta := map[string]interface{}{
		"tags":  []interface{}{"v1", "scan"},
		"flags": map[string]interface{}{"aggressive": true, "max_depth": 3},
	}

	job := &models.ScanJob{
		ID:        "job-deep-copy",
		TargetID:  "target-dc",
		Type:      "PORT_SCAN",
		Status:    models.JobStatusQueued,
		CreatedAt: time.Now().UTC(),
		Metadata:  callerMeta,
	}

	if err := repo.CreateJob(ctx, job); err != nil {
		t.Fatalf("failed to create job: %v", err)
	}

	// Mutate caller's original map
	callerMeta["tampered"] = true
	callerMeta["tags"].([]interface{})[0] = "corrupted"
	callerMeta["flags"].(map[string]interface{})["max_depth"] = 999

	// Fetch from repo
	fetched, err := repo.GetJobByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("failed to get job: %v", err)
	}

	if _, exists := fetched.Metadata["tampered"]; exists {
		t.Fatalf("deep-copy violation: 'tampered' key found in repository metadata")
	}
	if fetched.Metadata["tags"].([]interface{})[0] != "v1" {
		t.Fatalf("deep-copy violation: slice tag mutated in repository")
	}
	if fetched.Metadata["flags"].(map[string]interface{})["max_depth"] != 3 {
		t.Fatalf("deep-copy violation: nested map field mutated in repository")
	}

	// Mutate fetched object
	fetched.Metadata["external_mutation"] = true
	fetchedAgain, _ := repo.GetJobByID(ctx, job.ID)
	if _, exists := fetchedAgain.Metadata["external_mutation"]; exists {
		t.Fatalf("deep-copy violation: GetJobByID returned mutable reference")
	}
}

// TestScopeConfirmationTransactionInvariant tests one-to-one scope confirmation invariant (Requirements 7 & 8)
func TestScopeConfirmationTransactionInvariant(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStorage()

	// Setup scope import review
	review := &models.ScopeImportReview{
		ID:                   "import-invariant-01",
		Status:               "READY_FOR_REVIEW",
		CanonicalScopeSHA256: "canon-sha256-abcdef0123456789",
		OriginalFileSHA256:   "orig-sha256-abcdef0123456789",
		RootDomains: []models.RootDomainCandidate{
			{NormalizedDomain: "example.com", Confidence: "HIGH"},
			{NormalizedDomain: "example.org", Confidence: "MEDIUM"},
		},
		CanonicalScope: &models.CanonicalScope{
			IncludeHosts: []models.AdvancedScopeRule{{Enabled: true, Host: `^.*\.example\.com$`}},
		},
		SelectedRootDomain: "", // Must be empty before confirmation!
	}
	store.SaveImportReview(ctx, review)

	// Target definition to create
	target := &models.Target{
		ID:             "target-confirmed-01",
		Name:           "Example Target",
		AllowedDomains: []string{"example.com"},
		Status:         models.TargetStatusActive,
	}

	// 1. Attempt confirmation with root NOT in candidates (must fail)
	_, _, errInvalidRoot := store.ConfirmScopeAndCreateTarget(ctx, review.ID, "unauthorized.net", target, "operator@nexus.ai", "human review")
	if errInvalidRoot == nil {
		t.Fatalf("expected error confirming root not in candidates, got nil")
	}

	// 2. Authoritative confirmation
	confirmedTarget, confirmedReview, err := store.ConfirmScopeAndCreateTarget(ctx, review.ID, "example.com", target, "operator@nexus.ai", "human verified")
	if err != nil {
		t.Fatalf("failed to confirm scope and create target: %v", err)
	}

	// Verify Target Provenance (Requirement 7)
	if confirmedTarget.ScopeImportID != review.ID {
		t.Errorf("expected ScopeImportID '%s', got '%s'", review.ID, confirmedTarget.ScopeImportID)
	}
	if confirmedTarget.CanonicalScopeSHA256 != review.CanonicalScopeSHA256 {
		t.Errorf("expected CanonicalScopeSHA256 '%s', got '%s'", review.CanonicalScopeSHA256, confirmedTarget.CanonicalScopeSHA256)
	}
	if confirmedTarget.AuthorizationSnapshotSHA256 == "" {
		t.Errorf("expected non-empty AuthorizationSnapshotSHA256")
	}
	if confirmedTarget.PrimaryRootDomain != "example.com" {
		t.Errorf("expected PrimaryRootDomain 'example.com', got '%s'", confirmedTarget.PrimaryRootDomain)
	}
	if confirmedTarget.ConfirmedBy != "operator@nexus.ai" {
		t.Errorf("expected ConfirmedBy 'operator@nexus.ai', got '%s'", confirmedTarget.ConfirmedBy)
	}
	if confirmedTarget.ConfirmationTimestamp == nil {
		t.Errorf("expected ConfirmationTimestamp to be set")
	}

	// Verify Review is CONFIRMED and has ConfirmedPrimaryRootDomain (Requirement 10)
	if confirmedReview.Status != "CONFIRMED" {
		t.Errorf("expected review status CONFIRMED, got %s", confirmedReview.Status)
	}
	if confirmedReview.SelectedRootDomain != "example.com" {
		t.Errorf("expected SelectedRootDomain 'example.com', got '%s'", confirmedReview.SelectedRootDomain)
	}

	// 3. Duplicate confirmation attempt must fail closed (Requirement 8)
	target2 := &models.Target{
		ID:             "target-duplicate-02",
		Name:           "Duplicate Target",
		AllowedDomains: []string{"example.com"},
		Status:         models.TargetStatusActive,
	}
	_, _, errDup := store.ConfirmScopeAndCreateTarget(ctx, review.ID, "example.com", target2, "operator2@nexus.ai", "dup attempt")
	if errDup == nil {
		t.Fatalf("expected error on duplicate confirmation of already CONFIRMED scope import, got nil")
	}
}

// TestConfirmationConcurrency ensures exactly one concurrent confirmation succeeds (Requirement 9)
func TestConfirmationConcurrency(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStorage()

	importID := "import-concurrent-race"
	review := &models.ScopeImportReview{
		ID:                   importID,
		Status:               "READY_FOR_REVIEW",
		CanonicalScopeSHA256: "canon-hash-race-12345",
		RootDomains: []models.RootDomainCandidate{
			{NormalizedDomain: "root-a.com", Confidence: "HIGH"},
			{NormalizedDomain: "root-b.com", Confidence: "HIGH"},
		},
		CanonicalScope: &models.CanonicalScope{
			IncludeHosts: []models.AdvancedScopeRule{{Enabled: true, Host: `^.*\.root-a\.com$`}},
		},
	}
	store.SaveImportReview(ctx, review)

	var wg sync.WaitGroup
	var successCount int
	var conflictCount int
	var mu sync.Mutex
	var winningRoot string
	var winningOperator string

	for i := 0; i < 2; i++ {
		wg.Add(1)
		selectedRoot := "root-a.com"
		operator := "operator-A"
		targetID := "target-race-A"
		if i == 1 {
			selectedRoot = "root-b.com"
			operator = "operator-B"
			targetID = "target-race-B"
		}
		tgt := &models.Target{
			ID:             targetID,
			Name:           "Race Target",
			AllowedDomains: []string{selectedRoot},
			Status:         models.TargetStatusActive,
		}

		go func(root, op string, targetDef *models.Target) {
			defer wg.Done()
			cTarget, _, err := store.ConfirmScopeAndCreateTarget(ctx, importID, root, targetDef, op, "concurrent confirmation test")
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				successCount++
				winningRoot = cTarget.RootDomain
				winningOperator = cTarget.ConfirmedBy
			} else {
				conflictCount++
			}
		}(selectedRoot, operator, tgt)
	}
	wg.Wait()

	if successCount != 1 || conflictCount != 1 {
		t.Fatalf("expected exactly 1 success and 1 conflict in concurrent confirmation, got success=%d, conflict=%d", successCount, conflictCount)
	}

	// Verify no mixed provenance fields (Requirement 9)
	finalReview, err := store.GetImportReview(ctx, importID)
	if err != nil {
		t.Fatalf("failed to get final import review: %v", err)
	}
	if finalReview.SelectedRootDomain != winningRoot {
		t.Fatalf("provenance mismatch: review root '%s' does not match winning target root '%s'", finalReview.SelectedRootDomain, winningRoot)
	}
	if finalReview.ConfirmedBy != winningOperator {
		t.Fatalf("provenance mismatch: review confirmedBy '%s' does not match winning operator '%s'", finalReview.ConfirmedBy, winningOperator)
	}
}

// TestJSONCorruptionFailClosed tests that safeUnmarshal returns explicit storage error instead of silent fallback (Requirement 13)
func TestJSONCorruptionFailClosed(t *testing.T) {
	corruptedJSON := []byte(`{"invalid_json: true, unterminated`)

	var dest map[string]interface{}
	err := safeUnmarshal(corruptedJSON, &dest, "security_state.test_field")
	if err == nil {
		t.Fatalf("expected storage error on corrupted JSON, got nil")
	}

	expectedSub := "storage JSON corruption in security_state.test_field"
	if dest != nil {
		t.Fatalf("expected destination to remain nil, got %v", dest)
	}
	if err.Error()[:len(expectedSub)] != expectedSub {
		t.Errorf("expected error prefix '%s', got '%s'", expectedSub, err.Error())
	}

	// Empty and null data should succeed gracefully
	var destEmpty map[string]interface{}
	if err := safeUnmarshal([]byte(""), &destEmpty, "empty"); err != nil {
		t.Fatalf("expected nil error on empty bytes, got %v", err)
	}
	if err := safeUnmarshal([]byte("null"), &destEmpty, "null"); err != nil {
		t.Fatalf("expected nil error on null bytes, got %v", err)
	}
}

// TestTargetIsolation verifies cross-target access restrictions (Requirement 18 & 19)
func TestTargetIsolation(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStorage()

	tA := &models.Target{ID: "target-A", Name: "Target A", Status: models.TargetStatusActive}
	tB := &models.Target{ID: "target-B", Name: "Target B", Status: models.TargetStatusActive}
	_ = store.Create(ctx, tA)
	_ = store.Create(ctx, tB)

	// Create jobs for each target
	jA := &models.ScanJob{ID: "job-A-1", TargetID: tA.ID, Type: "PORT_SCAN", Status: models.JobStatusQueued, CreatedAt: time.Now().UTC()}
	jB := &models.ScanJob{ID: "job-B-1", TargetID: tB.ID, Type: "PORT_SCAN", Status: models.JobStatusQueued, CreatedAt: time.Now().UTC()}
	_ = store.CreateJob(ctx, jA)
	_ = store.CreateJob(ctx, jB)

	// List jobs scoped to target-A
	listA, err := store.ListJobs(ctx, tA.ID)
	if err != nil {
		t.Fatalf("failed to list jobs for target A: %v", err)
	}
	for _, j := range listA {
		if j.TargetID != tA.ID {
			t.Fatalf("target isolation violation: found job belonging to target '%s' in target '%s' list", j.TargetID, tA.ID)
		}
	}

	// List jobs scoped to target-B
	listB, err := store.ListJobs(ctx, tB.ID)
	if err != nil {
		t.Fatalf("failed to list jobs for target B: %v", err)
	}
	for _, j := range listB {
		if j.TargetID != tB.ID {
			t.Fatalf("target isolation violation: found job belonging to target '%s' in target '%s' list", j.TargetID, tB.ID)
		}
	}
}
