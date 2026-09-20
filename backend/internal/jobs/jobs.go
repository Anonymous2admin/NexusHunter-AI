package jobs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

var (
	ErrJobNotFound      = errors.New("scan job not found")
	ErrInvalidState     = errors.New("invalid job state transition")
	ErrMissingTarget    = errors.New("target id is required to create a scan job")
	ErrMissingJobType   = errors.New("job type is required")
	ErrTargetNotActive  = errors.New("cannot enqueue scan job for inactive or missing target")
)

// JobService specifies the lifecycle management interface for scan jobs.
type JobService interface {
	CreateJob(ctx context.Context, targetID string, jobType string, metadata map[string]interface{}) (*models.ScanJob, error)
	GetJob(ctx context.Context, id string) (*models.ScanJob, error)
	ListJobs(ctx context.Context, targetID string) ([]*models.ScanJob, error)
	StartJob(ctx context.Context, id string) (*models.ScanJob, error)
	CompleteJob(ctx context.Context, id string) (*models.ScanJob, error)
	FailJob(ctx context.Context, id string, failureReason string) (*models.ScanJob, error)
	CancelJob(ctx context.Context, id string) (*models.ScanJob, error)
}

// Manager implements JobService with in-memory persistence and event publishing.
type Manager struct {
	mu       sync.RWMutex
	jobs     map[string]*models.ScanJob
	eventBus events.EventBus
}

// NewManager creates a new Job Manager instance.
func NewManager(eventBus events.EventBus) *Manager {
	return &Manager{
		jobs:     make(map[string]*models.ScanJob),
		eventBus: eventBus,
	}
}

// CreateJob enqueues a new scan job attributable to an explicit target.
func (m *Manager) CreateJob(ctx context.Context, targetID string, jobType string, metadata map[string]interface{}) (*models.ScanJob, error) {
	if targetID == "" {
		return nil, ErrMissingTarget
	}
	if jobType == "" {
		return nil, ErrMissingJobType
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	jobID := events.GenerateID("job")
	now := time.Now().UTC()

	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	job := &models.ScanJob{
		ID:        jobID,
		TargetID:  targetID,
		Type:      jobType,
		Status:    models.JobStatusQueued,
		CreatedAt: now,
		Metadata:  metadata,
	}

	m.jobs[jobID] = job

	if m.eventBus != nil {
		_ = m.eventBus.Publish(ctx, models.Event{
			EventType: models.EventJobCreated,
			JobID:     job.ID,
			TargetID:  job.TargetID,
			Timestamp: now,
			Payload: map[string]interface{}{
				"job_id":   job.ID,
				"type":     job.Type,
				"status":   job.Status,
				"metadata": metadata,
			},
		})
	}

	return job, nil
}

// GetJob retrieves a scan job by its identifier.
func (m *Manager) GetJob(ctx context.Context, id string) (*models.ScanJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	job, exists := m.jobs[id]
	if !exists {
		return nil, ErrJobNotFound
	}
	// Return a copy to prevent mutation
	copied := *job
	return &copied, nil
}

// ListJobs retrieves all jobs, optionally filtered by targetID.
func (m *Manager) ListJobs(ctx context.Context, targetID string) ([]*models.ScanJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*models.ScanJob, 0, len(m.jobs))
	for _, job := range m.jobs {
		if targetID == "" || job.TargetID == targetID {
			copied := *job
			result = append(result, &copied)
		}
	}
	return result, nil
}

// StartJob transitions a QUEUED job to RUNNING.
func (m *Manager) StartJob(ctx context.Context, id string) (*models.ScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	job, exists := m.jobs[id]
	if !exists {
		return nil, ErrJobNotFound
	}

	if job.Status != models.JobStatusQueued {
		return nil, fmt.Errorf("%w: cannot start job in state %s", ErrInvalidState, job.Status)
	}

	now := time.Now().UTC()
	job.Status = models.JobStatusRunning
	job.StartedAt = &now

	if m.eventBus != nil {
		_ = m.eventBus.Publish(ctx, models.Event{
			EventType: models.EventJobStarted,
			JobID:     job.ID,
			TargetID:  job.TargetID,
			Timestamp: now,
			Payload: map[string]interface{}{
				"job_id": job.ID,
				"status": job.Status,
			},
		})
	}

	copied := *job
	return &copied, nil
}

// CompleteJob transitions a RUNNING job to COMPLETED.
func (m *Manager) CompleteJob(ctx context.Context, id string) (*models.ScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	job, exists := m.jobs[id]
	if !exists {
		return nil, ErrJobNotFound
	}

	if job.Status != models.JobStatusRunning {
		return nil, fmt.Errorf("%w: cannot complete job in state %s", ErrInvalidState, job.Status)
	}

	now := time.Now().UTC()
	job.Status = models.JobStatusCompleted
	job.CompletedAt = &now

	if m.eventBus != nil {
		_ = m.eventBus.Publish(ctx, models.Event{
			EventType: models.EventJobCompleted,
			JobID:     job.ID,
			TargetID:  job.TargetID,
			Timestamp: now,
			Payload: map[string]interface{}{
				"job_id": job.ID,
				"status": job.Status,
			},
		})
	}

	copied := *job
	return &copied, nil
}

// FailJob transitions a job to FAILED with error documentation.
func (m *Manager) FailJob(ctx context.Context, id string, failureReason string) (*models.ScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	job, exists := m.jobs[id]
	if !exists {
		return nil, ErrJobNotFound
	}

	if job.Status == models.JobStatusCompleted || job.Status == models.JobStatusCancelled {
		return nil, fmt.Errorf("%w: cannot fail job in terminal state %s", ErrInvalidState, job.Status)
	}

	now := time.Now().UTC()
	job.Status = models.JobStatusFailed
	job.CompletedAt = &now
	job.Error = failureReason

	if m.eventBus != nil {
		_ = m.eventBus.Publish(ctx, models.Event{
			EventType: models.EventJobFailed,
			JobID:     job.ID,
			TargetID:  job.TargetID,
			Timestamp: now,
			Payload: map[string]interface{}{
				"job_id": job.ID,
				"status": job.Status,
				"error":  failureReason,
			},
		})
	}

	copied := *job
	return &copied, nil
}

// CancelJob transitions an active (QUEUED or RUNNING) job to CANCELLED.
func (m *Manager) CancelJob(ctx context.Context, id string) (*models.ScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	job, exists := m.jobs[id]
	if !exists {
		return nil, ErrJobNotFound
	}

	if job.Status == models.JobStatusCompleted || job.Status == models.JobStatusFailed || job.Status == models.JobStatusCancelled {
		return nil, fmt.Errorf("%w: cannot cancel job in terminal state %s", ErrInvalidState, job.Status)
	}

	now := time.Now().UTC()
	job.Status = models.JobStatusCancelled
	job.CompletedAt = &now

	copied := *job
	return &copied, nil
}
