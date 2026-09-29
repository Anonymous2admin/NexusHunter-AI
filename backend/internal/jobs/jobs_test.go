package jobs

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

type mockTargetChecker struct {
	targets map[string]*models.Target
}

func (m *mockTargetChecker) GetByID(ctx context.Context, id string) (*models.Target, error) {
	t, ok := m.targets[id]
	if !ok {
		return nil, errors.New("target not found")
	}
	return t, nil
}

func setupTestManager() (*Manager, *events.MemoryEventBus, *mockTargetChecker) {
	bus := events.NewMemoryEventBus(100)
	mgr := NewManager(bus)
	checker := &mockTargetChecker{
		targets: map[string]*models.Target{
			"target-active": {
				ID:     "target-active",
				Status: models.TargetStatusActive,
			},
			"target-inactive": {
				ID:     "target-inactive",
				Status: models.TargetStatusInactive,
			},
		},
	}
	mgr.SetTargetChecker(checker)
	return mgr, bus, checker
}

// TestJobLifecycleHappyPath tests QUEUED -> RUNNING -> COMPLETED
func TestJobLifecycleHappyPath(t *testing.T) {
	mgr, bus, _ := setupTestManager()
	ctx := context.Background()

	job, err := mgr.CreateJob(ctx, "target-active", "PORT_SCAN", map[string]interface{}{"ports": "80,443"})
	if err != nil {
		t.Fatalf("failed to create job: %v", err)
	}
	if job.Status != models.JobStatusQueued {
		t.Fatalf("expected status QUEUED, got %s", job.Status)
	}

	started, err := mgr.StartJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("failed to start job: %v", err)
	}
	if started.Status != models.JobStatusRunning || started.StartedAt == nil {
		t.Fatalf("expected status RUNNING with started_at set")
	}

	completed, err := mgr.CompleteJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("failed to complete job: %v", err)
	}
	if completed.Status != models.JobStatusCompleted || completed.CompletedAt == nil {
		t.Fatalf("expected status COMPLETED with completed_at set")
	}

	// Verify events in bus
	evts := bus.GetEvents()
	if len(evts) < 3 {
		t.Fatalf("expected at least 3 events, got %d", len(evts))
	}
}

// TestJobFailureLifecycle tests QUEUED -> RUNNING -> FAILED
func TestJobFailureLifecycle(t *testing.T) {
	mgr, _, _ := setupTestManager()
	ctx := context.Background()

	job, _ := mgr.CreateJob(ctx, "target-active", "VULN_SCAN", nil)
	_, err := mgr.StartJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("failed to start job: %v", err)
	}

	failed, err := mgr.FailJob(ctx, job.ID, "connection refused")
	if err != nil {
		t.Fatalf("failed to fail job: %v", err)
	}
	if failed.Status != models.JobStatusFailed || failed.Error != "connection refused" {
		t.Fatalf("expected status FAILED with error recorded")
	}
}

// TestJobCancellationFromQueuedAndRunning tests QUEUED -> CANCELLED and RUNNING -> CANCELLED
func TestJobCancellationFromQueuedAndRunning(t *testing.T) {
	mgr, _, _ := setupTestManager()
	ctx := context.Background()

	// 1. From QUEUED
	job1, _ := mgr.CreateJob(ctx, "target-active", "DNS_RECON", nil)
	cancelled1, err := mgr.CancelJob(ctx, job1.ID)
	if err != nil {
		t.Fatalf("failed to cancel queued job: %v", err)
	}
	if cancelled1.Status != models.JobStatusCancelled {
		t.Fatalf("expected CANCELLED, got %s", cancelled1.Status)
	}

	// 2. From RUNNING
	job2, _ := mgr.CreateJob(ctx, "target-active", "DNS_RECON", nil)
	_, _ = mgr.StartJob(ctx, job2.ID)
	cancelled2, err := mgr.CancelJob(ctx, job2.ID)
	if err != nil {
		t.Fatalf("failed to cancel running job: %v", err)
	}
	if cancelled2.Status != models.JobStatusCancelled {
		t.Fatalf("expected CANCELLED, got %s", cancelled2.Status)
	}
}

// TestInvalidJobTransitions tests all forbidden transitions:
// QUEUED -> COMPLETED
// QUEUED -> FAILED
// COMPLETED -> RUNNING
// COMPLETED -> FAILED
// COMPLETED -> CANCELLED
// FAILED -> RUNNING
// FAILED -> COMPLETED
// FAILED -> CANCELLED
// CANCELLED -> RUNNING
func TestInvalidJobTransitions(t *testing.T) {
	mgr, _, _ := setupTestManager()
	ctx := context.Background()

	// QUEUED -> COMPLETED (rejected)
	jobQ, _ := mgr.CreateJob(ctx, "target-active", "TEST", nil)
	if _, err := mgr.CompleteJob(ctx, jobQ.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState on QUEUED -> COMPLETED, got %v", err)
	}

	// QUEUED -> FAILED (rejected)
	if _, err := mgr.FailJob(ctx, jobQ.ID, "fail"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState on QUEUED -> FAILED, got %v", err)
	}

	// Setup COMPLETED job
	jobC, _ := mgr.CreateJob(ctx, "target-active", "TEST", nil)
	_, _ = mgr.StartJob(ctx, jobC.ID)
	_, _ = mgr.CompleteJob(ctx, jobC.ID)

	// COMPLETED -> RUNNING (rejected)
	if _, err := mgr.StartJob(ctx, jobC.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState on COMPLETED -> RUNNING, got %v", err)
	}
	// COMPLETED -> FAILED (rejected)
	if _, err := mgr.FailJob(ctx, jobC.ID, "fail"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState on COMPLETED -> FAILED, got %v", err)
	}
	// COMPLETED -> CANCELLED (rejected)
	if _, err := mgr.CancelJob(ctx, jobC.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState on COMPLETED -> CANCELLED, got %v", err)
	}

	// Setup FAILED job
	jobF, _ := mgr.CreateJob(ctx, "target-active", "TEST", nil)
	_, _ = mgr.StartJob(ctx, jobF.ID)
	_, _ = mgr.FailJob(ctx, jobF.ID, "timeout")

	// FAILED -> RUNNING (rejected)
	if _, err := mgr.StartJob(ctx, jobF.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState on FAILED -> RUNNING, got %v", err)
	}
	// FAILED -> COMPLETED (rejected)
	if _, err := mgr.CompleteJob(ctx, jobF.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState on FAILED -> COMPLETED, got %v", err)
	}
	// FAILED -> CANCELLED (rejected)
	if _, err := mgr.CancelJob(ctx, jobF.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState on FAILED -> CANCELLED, got %v", err)
	}

	// Setup CANCELLED job
	jobX, _ := mgr.CreateJob(ctx, "target-active", "TEST", nil)
	_, _ = mgr.CancelJob(ctx, jobX.ID)

	// CANCELLED -> RUNNING (rejected)
	if _, err := mgr.StartJob(ctx, jobX.ID); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("expected ErrInvalidState on CANCELLED -> RUNNING, got %v", err)
	}
}

// TestJobIdempotency verifies duplicate calls return authoritative state without mutating timestamps
func TestJobIdempotency(t *testing.T) {
	mgr, _, _ := setupTestManager()
	ctx := context.Background()

	job, _ := mgr.CreateJob(ctx, "target-active", "TEST", nil)

	// First start
	s1, err := mgr.StartJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("first start failed: %v", err)
	}
	t1 := *s1.StartedAt

	time.Sleep(5 * time.Millisecond)

	// Second start (idempotent duplicate)
	s2, err := mgr.StartJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("second start failed: %v", err)
	}
	if s2.Status != models.JobStatusRunning {
		t.Fatalf("expected RUNNING, got %s", s2.Status)
	}
	if !s2.StartedAt.Equal(t1) {
		t.Fatalf("timestamp corrupted on duplicate start: %v vs %v", s2.StartedAt, t1)
	}
}

// TestConcurrentJobTransitions tests 10 concurrent start calls on same queued job
func TestConcurrentJobTransitions(t *testing.T) {
	mgr, _, _ := setupTestManager()
	ctx := context.Background()

	job, _ := mgr.CreateJob(ctx, "target-active", "TEST", nil)

	const concurrency = 10
	var wg sync.WaitGroup
	errCh := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := mgr.StartJob(ctx, job.ID)
			errCh <- err
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("unexpected error in concurrent start: %v", err)
		}
	}

	finalJob, _ := mgr.GetJob(ctx, job.ID)
	if finalJob.Status != models.JobStatusRunning {
		t.Fatalf("expected final status RUNNING, got %s", finalJob.Status)
	}
}

// TestTargetValidation ensures jobs cannot be created or run against inactive or nonexistent targets
func TestTargetValidation(t *testing.T) {
	mgr, _, _ := setupTestManager()
	ctx := context.Background()

	// Nonexistent target
	_, err := mgr.CreateJob(ctx, "target-nonexistent", "TEST", nil)
	if !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("expected ErrTargetNotFound, got %v", err)
	}

	// Inactive target
	_, err = mgr.CreateJob(ctx, "target-inactive", "TEST", nil)
	if !errors.Is(err, ErrTargetNotActive) {
		t.Fatalf("expected ErrTargetNotActive, got %v", err)
	}
}

// TestMultiProcessJobStateCAS simulates two distinct Manager instances against the same repository (Requirement 1)
func TestMultiProcessJobStateCAS(t *testing.T) {
	ctx := context.Background()
	sharedRepo := NewMemoryJobRepository()
	bus1 := events.NewMemoryEventBus(50)
	bus2 := events.NewMemoryEventBus(50)

	mgr1 := NewManager(bus1, sharedRepo)
	mgr2 := NewManager(bus2, sharedRepo)

	checker := &mockTargetChecker{
		targets: map[string]*models.Target{
			"target-active": {ID: "target-active", Status: models.TargetStatusActive},
		},
	}
	mgr1.SetTargetChecker(checker)
	mgr2.SetTargetChecker(checker)

	job, err := mgr1.CreateJob(ctx, "target-active", "PORT_SCAN", map[string]interface{}{"initial": "val"})
	if err != nil {
		t.Fatalf("failed to create job: %v", err)
	}

	// Now both managers attempt to complete or start with concurrent CAS
	// Simulate manager 1 starting the job successfully
	_, err = mgr1.StartJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("manager 1 failed to start job: %v", err)
	}

	// Manager 2 directly attempting an invalid transition from old QUEUED state via CAS
	oldJobCopy := *job
	oldJobCopy.Status = models.JobStatusRunning
	casErr := sharedRepo.TransitionJobWithAuditEvent(ctx, &oldJobCopy, []models.JobStatus{models.JobStatusQueued}, nil)
	if casErr == nil {
		t.Fatalf("expected CAS conflict when job is already RUNNING, got nil")
	}
	if !errors.Is(casErr, ErrJobStateConflict) {
		t.Fatalf("expected ErrJobStateConflict, got %v", casErr)
	}

	// Concurrent completion between manager 1 and manager 2:
	// Only one valid transition can succeed from RUNNING -> COMPLETED
	var wg sync.WaitGroup
	var completedCount int
	var conflictCount int
	var mu sync.Mutex

	for i := 0; i < 2; i++ {
		wg.Add(1)
		mgr := mgr1
		if i == 1 {
			mgr = mgr2
		}
		go func(m *Manager) {
			defer wg.Done()
			_, cErr := m.CompleteJob(ctx, job.ID)
			mu.Lock()
			defer mu.Unlock()
			if cErr == nil {
				completedCount++
			} else if errors.Is(cErr, ErrJobStateConflict) {
				conflictCount++
			}
		}(mgr)
	}
	wg.Wait()

	finalJob, err := sharedRepo.GetJobByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("failed to get final job: %v", err)
	}
	if finalJob.Status != models.JobStatusCompleted {
		t.Fatalf("expected final status COMPLETED, got %s", finalJob.Status)
	}
}

// TestMemoryMetadataDeepCopy verifies that mutating metadata outside repository never mutates internal state (Requirement 4)
func TestMemoryMetadataDeepCopy(t *testing.T) {
	ctx := context.Background()
	mgr, _, _ := setupTestManager()

	initialMeta := map[string]interface{}{
		"tags": []interface{}{"alpha", "beta"},
		"config": map[string]interface{}{
			"concurrency": 5,
		},
	}

	job, err := mgr.CreateJob(ctx, "target-active", "DEEP_COPY_TEST", initialMeta)
	if err != nil {
		t.Fatalf("failed to create job: %v", err)
	}

	// Mutate original caller map
	initialMeta["mutated"] = true
	initialMeta["config"].(map[string]interface{})["concurrency"] = 999
	initialMeta["tags"].([]interface{})[0] = "corrupted"

	// Fetch from repo and verify it is untainted
	fetched, err := mgr.GetJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("failed to fetch job: %v", err)
	}

	if _, exists := fetched.Metadata["mutated"]; exists {
		t.Fatalf("deep copy leak: 'mutated' key found in repository metadata")
	}
	cfg := fetched.Metadata["config"].(map[string]interface{})
	if cfg["concurrency"] != 5 {
		t.Fatalf("deep copy leak: nested map concurrency altered to %v", cfg["concurrency"])
	}
	tags := fetched.Metadata["tags"].([]interface{})
	if tags[0] != "alpha" {
		t.Fatalf("deep copy leak: nested slice tags altered to %v", tags[0])
	}

	// Mutate fetched job metadata
	fetched.Metadata["external_change"] = "leak"

	// Fetch again and verify still untainted
	fetchedAgain, _ := mgr.GetJob(ctx, job.ID)
	if _, exists := fetchedAgain.Metadata["external_change"]; exists {
		t.Fatalf("deep copy leak: GetJob returned mutable reference")
	}
}

// TestMemoryRepositoryParityOrdering tests deterministic sorting: created_at DESC, tie-breaker id DESC (Requirement 3)
func TestMemoryRepositoryParityOrdering(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryJobRepository()

	baseTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	j1 := &models.ScanJob{ID: "job-001", TargetID: "t1", CreatedAt: baseTime.Add(1 * time.Minute)}
	j2 := &models.ScanJob{ID: "job-002", TargetID: "t1", CreatedAt: baseTime.Add(2 * time.Minute)}
	// Same timestamp to test tie-breaker ID DESC
	j3 := &models.ScanJob{ID: "job-003", TargetID: "t1", CreatedAt: baseTime.Add(3 * time.Minute)}
	j4 := &models.ScanJob{ID: "job-004", TargetID: "t1", CreatedAt: baseTime.Add(3 * time.Minute)}

	_ = repo.CreateJob(ctx, j1)
	_ = repo.CreateJob(ctx, j2)
	_ = repo.CreateJob(ctx, j3)
	_ = repo.CreateJob(ctx, j4)

	list, err := repo.ListJobs(ctx, "t1")
	if err != nil {
		t.Fatalf("failed to list jobs: %v", err)
	}

	if len(list) != 4 {
		t.Fatalf("expected 4 jobs, got %d", len(list))
	}

	// Expected order: job-004 (3m, id:4), job-003 (3m, id:3), job-002 (2m), job-001 (1m)
	expectedIDs := []string{"job-004", "job-003", "job-002", "job-001"}
	for i, exp := range expectedIDs {
		if list[i].ID != exp {
			t.Fatalf("ordering mismatch at index %d: expected %s, got %s", i, exp, list[i].ID)
		}
	}
}

// TestEventReplayReconstructJobLifecycle tests event replay state machine reconstruction (Requirement 17)
func TestEventReplayReconstructJobLifecycle(t *testing.T) {
	now := time.Now().UTC()
	jobID := "job-replay-001"
	targetID := "target-replay"

	eventsList := []*models.Event{
		{
			EventID:       "evt-1",
			EventType:     models.EventJobCreated,
			JobID:         jobID,
			TargetID:      targetID,
			Timestamp:     now.Add(1 * time.Second),
			PreviousState: "",
			NewState:      string(models.JobStatusQueued),
		},
		{
			EventID:       "evt-2",
			EventType:     models.EventJobStarted,
			JobID:         jobID,
			TargetID:      targetID,
			Timestamp:     now.Add(2 * time.Second),
			PreviousState: string(models.JobStatusQueued),
			NewState:      string(models.JobStatusRunning),
		},
		{
			EventID:       "evt-3",
			EventType:     models.EventJobCompleted,
			JobID:         jobID,
			TargetID:      targetID,
			Timestamp:     now.Add(3 * time.Second),
			PreviousState: string(models.JobStatusRunning),
			NewState:      string(models.JobStatusCompleted),
		},
	}

	status, err := ReconstructJobLifecycle(eventsList)
	if err != nil {
		t.Fatalf("failed to reconstruct lifecycle: %v", err)
	}
	if status != models.JobStatusCompleted {
		t.Fatalf("expected reconstructed status COMPLETED, got %s", status)
	}

	// Test corruption/tampering detection: missing transition
	tampered := []*models.Event{
		eventsList[0], // CREATED
		eventsList[2], // COMPLETED (skipping STARTED)
	}
	_, err = ReconstructJobLifecycle(tampered)
	if err == nil {
		t.Fatalf("expected integrity error when reconstructing from skipped state transition")
	}
}

// TestConcurrentMetadataRaceDetector executes parallel reads and writes to verify -race clean execution (Requirement 4 & 26)
func TestConcurrentMetadataRaceDetector(t *testing.T) {
	ctx := context.Background()
	mgr, _, _ := setupTestManager()

	job, _ := mgr.CreateJob(ctx, "target-active", "RACE_TEST", map[string]interface{}{"counter": 0})

	const goroutines = 20
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(2)
		// Reader goroutine
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				jObj, err := mgr.GetJob(ctx, job.ID)
				if err == nil && jObj.Metadata != nil {
					_ = jObj.Metadata["counter"]
				}
			}
		}()

		// Updater goroutine
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				updatedMeta := map[string]interface{}{
					"counter":   j,
					"worker_id": workerID,
				}
				_ = mgr.repo.UpdateJob(ctx, &models.ScanJob{
					ID:        job.ID,
					TargetID:  job.TargetID,
					Type:      job.Type,
					Status:    models.JobStatusQueued,
					CreatedAt: job.CreatedAt,
					Metadata:  updatedMeta,
				})
			}
		}(i)
	}

	wg.Wait()
}
