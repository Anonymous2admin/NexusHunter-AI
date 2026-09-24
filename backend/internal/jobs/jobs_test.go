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
