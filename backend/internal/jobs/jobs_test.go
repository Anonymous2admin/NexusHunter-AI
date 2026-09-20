package jobs

import (
	"context"
	"testing"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

func TestJobLifecycle(t *testing.T) {
	bus := events.NewMemoryEventBus(50)
	mgr := NewManager(bus)
	ctx := context.Background()

	// Step 1: Create Job
	job, err := mgr.CreateJob(ctx, "target-123", "PASSIVE_DNS_ENUMERATION", map[string]interface{}{"depth": 1})
	if err != nil {
		t.Fatalf("failed to create job: %v", err)
	}
	if job.Status != models.JobStatusQueued {
		t.Fatalf("expected status QUEUED, got %s", job.Status)
	}

	// Step 2: Start Job
	started, err := mgr.StartJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("failed to start job: %v", err)
	}
	if started.Status != models.JobStatusRunning || started.StartedAt == nil {
		t.Fatalf("expected status RUNNING with started_at timestamp")
	}

	// Step 3: Complete Job
	completed, err := mgr.CompleteJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("failed to complete job: %v", err)
	}
	if completed.Status != models.JobStatusCompleted || completed.CompletedAt == nil {
		t.Fatalf("expected status COMPLETED with completed_at timestamp")
	}

	// Invalid Transition: Complete an already completed job
	_, err = mgr.CompleteJob(ctx, job.ID)
	if err == nil {
		t.Fatalf("expected error completing an already completed job")
	}
}

func TestJobFailureLifecycle(t *testing.T) {
	bus := events.NewMemoryEventBus(50)
	mgr := NewManager(bus)
	ctx := context.Background()

	job, _ := mgr.CreateJob(ctx, "target-456", "TLS_SAN_COLLECTION", nil)
	_, _ = mgr.StartJob(ctx, job.ID)

	failed, err := mgr.FailJob(ctx, job.ID, "remote host timed out during TLS handshake")
	if err != nil {
		t.Fatalf("failed to fail job: %v", err)
	}
	if failed.Status != models.JobStatusFailed || failed.Error == "" {
		t.Fatalf("expected status FAILED with error message set")
	}
}

func TestJobCancellation(t *testing.T) {
	bus := events.NewMemoryEventBus(50)
	mgr := NewManager(bus)
	ctx := context.Background()

	job, _ := mgr.CreateJob(ctx, "target-789", "WHOIS_CORRELATION", nil)
	cancelled, err := mgr.CancelJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("failed to cancel queued job: %v", err)
	}
	if cancelled.Status != models.JobStatusCancelled {
		t.Fatalf("expected status CANCELLED, got %s", cancelled.Status)
	}
}
