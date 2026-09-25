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
	ErrJobNotFound     = errors.New("scan job not found")
	ErrInvalidState    = errors.New("invalid job state transition")
	ErrMissingTarget   = errors.New("target id is required to create a scan job")
	ErrMissingJobType  = errors.New("job type is required")
	ErrTargetNotFound  = errors.New("associated target does not exist")
	ErrTargetNotActive = errors.New("cannot execute scan job for inactive or archived target")
)

// TargetChecker checks if a target exists and is currently active.
type TargetChecker interface {
	GetByID(ctx context.Context, id string) (*models.Target, error)
}

// JobRepository specifies the durable storage interface for scan jobs.
// Guarantees that across process restarts, all QUEUED/RUNNING/COMPLETED/FAILED/CANCELLED
// job states remain durable and fully recoverable.
type JobRepository interface {
	CreateJob(ctx context.Context, job *models.ScanJob) error
	GetJobByID(ctx context.Context, id string) (*models.ScanJob, error)
	ListJobs(ctx context.Context, targetID string) ([]*models.ScanJob, error)
	UpdateJob(ctx context.Context, job *models.ScanJob) error
	DeleteJob(ctx context.Context, id string) error
}

// MemoryJobRepository provides in-memory durable job storage for development and test harnesses.
type MemoryJobRepository struct {
	mu   sync.RWMutex
	jobs map[string]*models.ScanJob
}

// NewMemoryJobRepository initializes a process-isolated job repository.
func NewMemoryJobRepository() *MemoryJobRepository {
	return &MemoryJobRepository{
		jobs: make(map[string]*models.ScanJob),
	}
}

func (m *MemoryJobRepository) CreateJob(ctx context.Context, job *models.ScanJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *job
	m.jobs[job.ID] = &cp
	return nil
}

func (m *MemoryJobRepository) GetJobByID(ctx context.Context, id string) (*models.ScanJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, exists := m.jobs[id]
	if !exists {
		return nil, ErrJobNotFound
	}
	cp := *j
	return &cp, nil
}

func (m *MemoryJobRepository) ListJobs(ctx context.Context, targetID string) ([]*models.ScanJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.ScanJob
	for _, j := range m.jobs {
		if targetID == "" || j.TargetID == targetID {
			cp := *j
			res = append(res, &cp)
		}
	}
	return res, nil
}

func (m *MemoryJobRepository) UpdateJob(ctx context.Context, job *models.ScanJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.jobs[job.ID]; !exists {
		return ErrJobNotFound
	}
	cp := *job
	m.jobs[job.ID] = &cp
	return nil
}

func (m *MemoryJobRepository) DeleteJob(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.jobs[id]; !exists {
		return ErrJobNotFound
	}
	delete(m.jobs, id)
	return nil
}

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

// Manager implements JobService backed by a durable JobRepository and event publishing.
// Single-process guarantees: A local mutex coordinates in-process concurrency, while
// the backing JobRepository enforces transactional state persistence.
type Manager struct {
	mu            sync.RWMutex
	repo          JobRepository
	eventBus      events.EventBus
	targetChecker TargetChecker
}

// NewManager creates a new Job Manager instance backed by an authoritative JobRepository.
func NewManager(eventBus events.EventBus, repo ...JobRepository) *Manager {
	var r JobRepository
	if len(repo) > 0 && repo[0] != nil {
		r = repo[0]
	} else {
		r = NewMemoryJobRepository()
	}
	return &Manager{
		repo:     r,
		eventBus: eventBus,
	}
}

// SetJobRepository registers or swaps the underlying durable JobRepository.
func (m *Manager) SetJobRepository(repo JobRepository) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.repo = repo
}

// SetTargetChecker registers a TargetChecker dependency for target activity verification.
func (m *Manager) SetTargetChecker(checker TargetChecker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.targetChecker = checker
}

// validateTargetActive checks target existence and active status.
func (m *Manager) validateTargetActive(ctx context.Context, targetID string) error {
	if m.targetChecker == nil {
		return nil
	}
	target, err := m.targetChecker.GetByID(ctx, targetID)
	if err != nil || target == nil {
		return ErrTargetNotFound
	}
	if target.Status != models.TargetStatusActive {
		return ErrTargetNotActive
	}
	return nil
}

// CreateJob enqueues a new scan job attributable to an explicit target.
func (m *Manager) CreateJob(ctx context.Context, targetID string, jobType string, metadata map[string]interface{}) (*models.ScanJob, error) {
	if targetID == "" {
		return nil, ErrMissingTarget
	}
	if jobType == "" {
		return nil, ErrMissingJobType
	}

	if err := m.validateTargetActive(ctx, targetID); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	jobID := events.GenerateID("job")
	now := time.Now().UTC()
	corrID := events.GenerateID("corr")

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

	if err := m.repo.CreateJob(ctx, job); err != nil {
		return nil, fmt.Errorf("failed to persist new scan job: %w", err)
	}

	if m.eventBus != nil {
		if err := m.eventBus.Publish(ctx, models.Event{
			EventID:   events.GenerateID("evt"),
			EventType: models.EventJobCreated,
			JobID:     job.ID,
			TargetID:  job.TargetID,
			Timestamp: now,
			Payload: map[string]interface{}{
				"job_id":         job.ID,
				"target_id":      job.TargetID,
				"timestamp":      now.Format(time.RFC3339),
				"correlation_id": corrID,
				"previous_state": "",
				"new_state":      string(models.JobStatusQueued),
				"job_type":       job.Type,
				"metadata":       metadata,
			},
		}); err != nil {
			return nil, fmt.Errorf("failed to publish job created audit event: %w", err)
		}
	}

	copied := *job
	return &copied, nil
}

// GetJob retrieves a scan job by its identifier.
func (m *Manager) GetJob(ctx context.Context, id string) (*models.ScanJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.repo.GetJobByID(ctx, id)
}

// ListJobs retrieves all jobs, optionally filtered by targetID.
func (m *Manager) ListJobs(ctx context.Context, targetID string) ([]*models.ScanJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.repo.ListJobs(ctx, targetID)
}

// StartJob transitions a QUEUED job to RUNNING. Idempotent if already RUNNING.
func (m *Manager) StartJob(ctx context.Context, id string) (*models.ScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	job, err := m.repo.GetJobByID(ctx, id)
	if err != nil || job == nil {
		return nil, ErrJobNotFound
	}

	if err := m.validateTargetActive(ctx, job.TargetID); err != nil {
		return nil, err
	}

	// Idempotency: duplicate start returns existing running job without state corruption
	if job.Status == models.JobStatusRunning {
		copied := *job
		return &copied, nil
	}

	// Reject all invalid transitions (e.g. COMPLETED -> RUNNING, FAILED -> RUNNING, CANCELLED -> RUNNING)
	if job.Status != models.JobStatusQueued {
		return nil, fmt.Errorf("%w: cannot start job in state %s", ErrInvalidState, job.Status)
	}

	now := time.Now().UTC()
	prevStatus := job.Status
	job.Status = models.JobStatusRunning
	job.StartedAt = &now
	corrID := events.GenerateID("corr")

	if err := m.repo.UpdateJob(ctx, job); err != nil {
		return nil, fmt.Errorf("failed to persist job state transition: %w", err)
	}

	if m.eventBus != nil {
		if err := m.eventBus.Publish(ctx, models.Event{
			EventID:   events.GenerateID("evt"),
			EventType: models.EventJobStarted,
			JobID:     job.ID,
			TargetID:  job.TargetID,
			Timestamp: now,
			Payload: map[string]interface{}{
				"job_id":         job.ID,
				"target_id":      job.TargetID,
				"timestamp":      now.Format(time.RFC3339),
				"correlation_id": corrID,
				"previous_state": string(prevStatus),
				"new_state":      string(models.JobStatusRunning),
				"job_type":       job.Type,
			},
		}); err != nil {
			return nil, fmt.Errorf("failed to publish job started audit event: %w", err)
		}
	}

	copied := *job
	return &copied, nil
}

// CompleteJob transitions a RUNNING job to COMPLETED. Idempotent if already COMPLETED.
func (m *Manager) CompleteJob(ctx context.Context, id string) (*models.ScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	job, err := m.repo.GetJobByID(ctx, id)
	if err != nil || job == nil {
		return nil, ErrJobNotFound
	}

	if err := m.validateTargetActive(ctx, job.TargetID); err != nil {
		return nil, err
	}

	// Idempotency: duplicate complete returns existing completed job
	if job.Status == models.JobStatusCompleted {
		copied := *job
		return &copied, nil
	}

	// Reject invalid transitions (e.g. QUEUED -> COMPLETED, FAILED -> COMPLETED, CANCELLED -> COMPLETED)
	if job.Status != models.JobStatusRunning {
		return nil, fmt.Errorf("%w: cannot complete job in state %s", ErrInvalidState, job.Status)
	}

	now := time.Now().UTC()
	prevStatus := job.Status
	job.Status = models.JobStatusCompleted
	job.CompletedAt = &now
	corrID := events.GenerateID("corr")

	if err := m.repo.UpdateJob(ctx, job); err != nil {
		return nil, fmt.Errorf("failed to persist job completion: %w", err)
	}

	if m.eventBus != nil {
		if err := m.eventBus.Publish(ctx, models.Event{
			EventID:   events.GenerateID("evt"),
			EventType: models.EventJobCompleted,
			JobID:     job.ID,
			TargetID:  job.TargetID,
			Timestamp: now,
			Payload: map[string]interface{}{
				"job_id":         job.ID,
				"target_id":      job.TargetID,
				"timestamp":      now.Format(time.RFC3339),
				"correlation_id": corrID,
				"previous_state": string(prevStatus),
				"new_state":      string(models.JobStatusCompleted),
				"job_type":       job.Type,
			},
		}); err != nil {
			return nil, fmt.Errorf("failed to publish job completed audit event: %w", err)
		}
	}

	copied := *job
	return &copied, nil
}

// FailJob transitions a RUNNING job to FAILED with error documentation.
// Rejects QUEUED -> FAILED, COMPLETED -> FAILED, CANCELLED -> FAILED.
func (m *Manager) FailJob(ctx context.Context, id string, failureReason string) (*models.ScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	job, err := m.repo.GetJobByID(ctx, id)
	if err != nil || job == nil {
		return nil, ErrJobNotFound
	}

	if err := m.validateTargetActive(ctx, job.TargetID); err != nil {
		return nil, err
	}

	// Idempotency: duplicate failure returns existing failed job
	if job.Status == models.JobStatusFailed {
		copied := *job
		return &copied, nil
	}

	// Reject QUEUED -> FAILED, COMPLETED -> FAILED, CANCELLED -> FAILED
	if job.Status != models.JobStatusRunning {
		return nil, fmt.Errorf("%w: cannot fail job in state %s (must be RUNNING)", ErrInvalidState, job.Status)
	}

	now := time.Now().UTC()
	prevStatus := job.Status
	job.Status = models.JobStatusFailed
	job.CompletedAt = &now
	job.Error = failureReason
	corrID := events.GenerateID("corr")

	if err := m.repo.UpdateJob(ctx, job); err != nil {
		return nil, fmt.Errorf("failed to persist job failure: %w", err)
	}

	if m.eventBus != nil {
		if err := m.eventBus.Publish(ctx, models.Event{
			EventID:   events.GenerateID("evt"),
			EventType: models.EventJobFailed,
			JobID:     job.ID,
			TargetID:  job.TargetID,
			Timestamp: now,
			Payload: map[string]interface{}{
				"job_id":         job.ID,
				"target_id":      job.TargetID,
				"timestamp":      now.Format(time.RFC3339),
				"correlation_id": corrID,
				"previous_state": string(prevStatus),
				"new_state":      string(models.JobStatusFailed),
				"job_type":       job.Type,
				"error":          failureReason,
			},
		}); err != nil {
			return nil, fmt.Errorf("failed to publish job failed audit event: %w", err)
		}
	}

	copied := *job
	return &copied, nil
}

// CancelJob transitions an active (QUEUED or RUNNING) job to CANCELLED.
// Rejects terminal states: COMPLETED -> CANCELLED, FAILED -> CANCELLED.
func (m *Manager) CancelJob(ctx context.Context, id string) (*models.ScanJob, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	job, err := m.repo.GetJobByID(ctx, id)
	if err != nil || job == nil {
		return nil, ErrJobNotFound
	}

	if err := m.validateTargetActive(ctx, job.TargetID); err != nil {
		return nil, err
	}

	// Idempotency: duplicate cancel returns existing cancelled job
	if job.Status == models.JobStatusCancelled {
		copied := *job
		return &copied, nil
	}

	// Reject cancelling terminal jobs
	if job.Status == models.JobStatusCompleted || job.Status == models.JobStatusFailed {
		return nil, fmt.Errorf("%w: cannot cancel job in terminal state %s", ErrInvalidState, job.Status)
	}

	now := time.Now().UTC()
	prevStatus := job.Status
	job.Status = models.JobStatusCancelled
	job.CompletedAt = &now
	corrID := events.GenerateID("corr")

	if err := m.repo.UpdateJob(ctx, job); err != nil {
		return nil, fmt.Errorf("failed to persist job cancellation: %w", err)
	}

	if m.eventBus != nil {
		if err := m.eventBus.Publish(ctx, models.Event{
			EventID:   events.GenerateID("evt"),
			EventType: models.EventJobCancelled,
			JobID:     job.ID,
			TargetID:  job.TargetID,
			Timestamp: now,
			Payload: map[string]interface{}{
				"job_id":         job.ID,
				"target_id":      job.TargetID,
				"timestamp":      now.Format(time.RFC3339),
				"correlation_id": corrID,
				"previous_state": string(prevStatus),
				"new_state":      string(models.JobStatusCancelled),
				"job_type":       job.Type,
			},
		}); err != nil {
			return nil, fmt.Errorf("failed to publish job cancelled audit event: %w", err)
		}
	}

	copied := *job
	return &copied, nil
}
