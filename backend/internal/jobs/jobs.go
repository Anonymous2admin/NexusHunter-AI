package jobs

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

var (
	ErrJobNotFound      = errors.New("scan job not found")
	ErrJobStateConflict = errors.New("job state transition conflict")
	ErrInvalidState     = errors.New("invalid job state transition")
	ErrMissingTarget    = errors.New("target id is required to create a scan job")
	ErrMissingJobType   = errors.New("job type is required")
	ErrTargetNotFound   = errors.New("associated target does not exist")
	ErrTargetNotActive  = errors.New("cannot execute scan job for inactive or archived target")
)

// Deep copy helpers (Requirement 4)
func deepCopyScanJob(job *models.ScanJob) *models.ScanJob {
	if job == nil {
		return nil
	}
	cp := *job
	if job.StartedAt != nil {
		t := *job.StartedAt
		cp.StartedAt = &t
	}
	if job.CompletedAt != nil {
		t := *job.CompletedAt
		cp.CompletedAt = &t
	}
	cp.Metadata = deepCopyMap(job.Metadata)
	return &cp
}

func deepCopyMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	res := make(map[string]interface{}, len(m))
	for k, v := range m {
		res[k] = deepCopyValue(v)
	}
	return res
}

func deepCopyValue(v interface{}) interface{} {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case map[string]interface{}:
		return deepCopyMap(val)
	case []interface{}:
		res := make([]interface{}, len(val))
		for i, elem := range val {
			res[i] = deepCopyValue(elem)
		}
		return res
	case []string:
		res := make([]string, len(val))
		copy(res, val)
		return res
	case []int:
		res := make([]int, len(val))
		copy(res, val)
		return res
	default:
		return val
	}
}

// TargetChecker checks if a target exists and is currently active.
type TargetChecker interface {
	GetByID(ctx context.Context, id string) (*models.Target, error)
}

// AuditEventRecorder specifies durable event persistence for audit events.
type AuditEventRecorder interface {
	Record(ctx context.Context, event *models.Event) error
}

// JobRepository specifies the durable storage interface for scan jobs.
// Guarantees that across process restarts, all QUEUED/RUNNING/COMPLETED/FAILED/CANCELLED
// job states remain durable and fully recoverable.
type JobRepository interface {
	CreateJob(ctx context.Context, job *models.ScanJob) error
	CreateJobWithAuditEvent(ctx context.Context, job *models.ScanJob, event *models.Event) error
	GetJobByID(ctx context.Context, id string) (*models.ScanJob, error)
	ListJobs(ctx context.Context, targetID string) ([]*models.ScanJob, error)
	UpdateJob(ctx context.Context, job *models.ScanJob) error
	UpdateJobWithAuditEvent(ctx context.Context, job *models.ScanJob, event *models.Event) error
	TransitionJobWithAuditEvent(ctx context.Context, job *models.ScanJob, expectedOldStatus []models.JobStatus, event *models.Event) error
	DeleteJob(ctx context.Context, id string) error
}

// MemoryJobRepository provides in-memory job storage for development and test harnesses.
// Architectural Notice (Requirement 5):
// PROCESS_LOCAL_ONLY, NON_DURABLE. Does not survive process restarts.
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
	m.jobs[job.ID] = deepCopyScanJob(job)
	return nil
}

func (m *MemoryJobRepository) CreateJobWithAuditEvent(ctx context.Context, job *models.ScanJob, event *models.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobs[job.ID] = deepCopyScanJob(job)
	return nil
}

func (m *MemoryJobRepository) GetJobByID(ctx context.Context, id string) (*models.ScanJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, exists := m.jobs[id]
	if !exists {
		return nil, ErrJobNotFound
	}
	return deepCopyScanJob(j), nil
}

func (m *MemoryJobRepository) ListJobs(ctx context.Context, targetID string) ([]*models.ScanJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var res []*models.ScanJob
	for _, j := range m.jobs {
		if targetID == "" || j.TargetID == targetID {
			res = append(res, deepCopyScanJob(j))
		}
	}
	// Deterministic sorting matching PostgreSQL (Requirement 3): created_at DESC, tie-breaker id DESC
	sort.Slice(res, func(i, j int) bool {
		if res[i].CreatedAt.Equal(res[j].CreatedAt) {
			return res[i].ID > res[j].ID
		}
		return res[i].CreatedAt.After(res[j].CreatedAt)
	})
	return res, nil
}

func (m *MemoryJobRepository) UpdateJob(ctx context.Context, job *models.ScanJob) error {
	return m.TransitionJobWithAuditEvent(ctx, job, nil, nil)
}

func (m *MemoryJobRepository) UpdateJobWithAuditEvent(ctx context.Context, job *models.ScanJob, event *models.Event) error {
	var expected []models.JobStatus
	if event != nil && event.PreviousState != "" {
		expected = []models.JobStatus{models.JobStatus(event.PreviousState)}
	}
	return m.TransitionJobWithAuditEvent(ctx, job, expected, event)
}

func (m *MemoryJobRepository) TransitionJobWithAuditEvent(ctx context.Context, job *models.ScanJob, expectedOldStatus []models.JobStatus, event *models.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	curr, exists := m.jobs[job.ID]
	if !exists {
		return ErrJobNotFound
	}

	if len(expectedOldStatus) > 0 {
		matched := false
		for _, s := range expectedOldStatus {
			if curr.Status == s {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%w: job '%s' expected status in %v but found '%s'", ErrJobStateConflict, job.ID, expectedOldStatus, curr.Status)
		}
	}

	m.jobs[job.ID] = deepCopyScanJob(job)
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
	HandleTargetDeactivated(ctx context.Context, targetID string) error
}

// Manager implements JobService backed by a durable JobRepository and event publishing.
// Single-process guarantees: A local mutex coordinates in-process concurrency, while
// the backing JobRepository enforces transactional state persistence.
type Manager struct {
	mu            sync.RWMutex
	repo          JobRepository
	eventBus      events.EventBus
	eventRepo     AuditEventRecorder
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

// SetEventRepository registers a durable event repository for audit event persistence.
func (m *Manager) SetEventRepository(eventRepo AuditEventRecorder) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventRepo = eventRepo
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

// persistJobCreate executes atomic creation of job state and audit event.
func (m *Manager) persistJobCreate(ctx context.Context, job *models.ScanJob, event *models.Event) error {
	if atomicRepo, ok := m.repo.(interface {
		CreateJobWithAuditEvent(ctx context.Context, job *models.ScanJob, event *models.Event) error
	}); ok {
		if err := atomicRepo.CreateJobWithAuditEvent(ctx, job, event); err != nil {
			return fmt.Errorf("failed to persist job and audit event atomically: %w", err)
		}
	} else {
		if err := m.repo.CreateJob(ctx, job); err != nil {
			return fmt.Errorf("failed to persist new scan job: %w", err)
		}
		if m.eventRepo != nil && event != nil {
			if err := m.eventRepo.Record(ctx, event); err != nil {
				return fmt.Errorf("failed to persist audit event: %w", err)
			}
		}
	}

	if m.eventBus != nil && event != nil {
		_ = m.eventBus.Publish(ctx, *event)
	}
	return nil
}

// persistJobTransition executes atomic update of job state and audit event guarded by database-side CAS.
func (m *Manager) persistJobTransition(ctx context.Context, job *models.ScanJob, expectedOldStatus []models.JobStatus, event *models.Event) error {
	if casRepo, ok := m.repo.(interface {
		TransitionJobWithAuditEvent(ctx context.Context, job *models.ScanJob, expectedOldStatus []models.JobStatus, event *models.Event) error
	}); ok {
		if err := casRepo.TransitionJobWithAuditEvent(ctx, job, expectedOldStatus, event); err != nil {
			return err
		}
	} else if atomicRepo, ok := m.repo.(interface {
		UpdateJobWithAuditEvent(ctx context.Context, job *models.ScanJob, event *models.Event) error
	}); ok {
		if err := atomicRepo.UpdateJobWithAuditEvent(ctx, job, event); err != nil {
			return err
		}
	} else {
		if err := m.repo.UpdateJob(ctx, job); err != nil {
			return fmt.Errorf("failed to persist job state transition: %w", err)
		}
		if m.eventRepo != nil && event != nil {
			if err := m.eventRepo.Record(ctx, event); err != nil {
				return fmt.Errorf("failed to persist audit event: %w", err)
			}
		}
	}

	// Requirement 2: Publish to in-memory bus AFTER transaction commit.
	// If bus publish fails, log structured error, do NOT claim durable audit failed, do NOT rollback DB transaction.
	if m.eventBus != nil && event != nil {
		if pubErr := m.eventBus.Publish(ctx, *event); pubErr != nil {
			log.Printf("[DEGRADED_BUS_DELIVERY] event_id=%s job_id=%s err=%v", event.EventID, job.ID, pubErr)
		}
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
		Metadata:  deepCopyMap(metadata),
	}

	auditEvent := &models.Event{
		EventID:       events.GenerateID("evt"),
		EventType:     models.EventJobCreated,
		JobID:         job.ID,
		TargetID:      job.TargetID,
		Timestamp:     now,
		CorrelationID: corrID,
		PreviousState: "",
		NewState:      string(models.JobStatusQueued),
		CreatedAt:     now,
		Payload: map[string]interface{}{
			"job_id":         job.ID,
			"target_id":      job.TargetID,
			"timestamp":      now.Format(time.RFC3339),
			"correlation_id": corrID,
			"previous_state": "",
			"new_state":      string(models.JobStatusQueued),
			"job_type":       job.Type,
			"metadata":       deepCopyMap(metadata),
		},
	}

	if err := m.persistJobCreate(ctx, job, auditEvent); err != nil {
		return nil, err
	}

	return deepCopyScanJob(job), nil
}

// GetJob retrieves a scan job by its identifier.
func (m *Manager) GetJob(ctx context.Context, id string) (*models.ScanJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	j, err := m.repo.GetJobByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return deepCopyScanJob(j), nil
}

// ListJobs retrieves all jobs, optionally filtered by targetID.
func (m *Manager) ListJobs(ctx context.Context, targetID string) ([]*models.ScanJob, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.repo.ListJobs(ctx, targetID)
}

// StartJob transitions a QUEUED job to RUNNING guarded by optimistic CAS.
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
		return deepCopyScanJob(job), nil
	}

	// Reject invalid transitions
	if job.Status != models.JobStatusQueued {
		return nil, fmt.Errorf("%w: cannot start job in state %s", ErrInvalidState, job.Status)
	}

	now := time.Now().UTC()
	prevStatus := job.Status
	job.Status = models.JobStatusRunning
	job.StartedAt = &now
	corrID := events.GenerateID("corr")

	auditEvent := &models.Event{
		EventID:       events.GenerateID("evt"),
		EventType:     models.EventJobStarted,
		JobID:         job.ID,
		TargetID:      job.TargetID,
		Timestamp:     now,
		CorrelationID: corrID,
		PreviousState: string(prevStatus),
		NewState:      string(models.JobStatusRunning),
		CreatedAt:     now,
		Payload: map[string]interface{}{
			"job_id":         job.ID,
			"target_id":      job.TargetID,
			"timestamp":      now.Format(time.RFC3339),
			"correlation_id": corrID,
			"previous_state": string(prevStatus),
			"new_state":      string(models.JobStatusRunning),
			"job_type":       job.Type,
		},
	}

	if err := m.persistJobTransition(ctx, job, []models.JobStatus{models.JobStatusQueued}, auditEvent); err != nil {
		return nil, err
	}

	return deepCopyScanJob(job), nil
}

// CompleteJob transitions a RUNNING job to COMPLETED guarded by optimistic CAS.
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
		return deepCopyScanJob(job), nil
	}

	// Reject invalid transitions
	if job.Status != models.JobStatusRunning {
		return nil, fmt.Errorf("%w: cannot complete job in state %s", ErrInvalidState, job.Status)
	}

	now := time.Now().UTC()
	prevStatus := job.Status
	job.Status = models.JobStatusCompleted
	job.CompletedAt = &now
	corrID := events.GenerateID("corr")

	auditEvent := &models.Event{
		EventID:       events.GenerateID("evt"),
		EventType:     models.EventJobCompleted,
		JobID:         job.ID,
		TargetID:      job.TargetID,
		Timestamp:     now,
		CorrelationID: corrID,
		PreviousState: string(prevStatus),
		NewState:      string(models.JobStatusCompleted),
		CreatedAt:     now,
		Payload: map[string]interface{}{
			"job_id":         job.ID,
			"target_id":      job.TargetID,
			"timestamp":      now.Format(time.RFC3339),
			"correlation_id": corrID,
			"previous_state": string(prevStatus),
			"new_state":      string(models.JobStatusCompleted),
			"job_type":       job.Type,
		},
	}

	if err := m.persistJobTransition(ctx, job, []models.JobStatus{models.JobStatusRunning}, auditEvent); err != nil {
		return nil, err
	}

	return deepCopyScanJob(job), nil
}

// FailJob transitions a RUNNING job to FAILED guarded by optimistic CAS.
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
		return deepCopyScanJob(job), nil
	}

	// Reject invalid transitions
	if job.Status != models.JobStatusRunning {
		return nil, fmt.Errorf("%w: cannot fail job in state %s (must be RUNNING)", ErrInvalidState, job.Status)
	}

	now := time.Now().UTC()
	prevStatus := job.Status
	job.Status = models.JobStatusFailed
	job.CompletedAt = &now
	job.Error = failureReason
	corrID := events.GenerateID("corr")

	auditEvent := &models.Event{
		EventID:       events.GenerateID("evt"),
		EventType:     models.EventJobFailed,
		JobID:         job.ID,
		TargetID:      job.TargetID,
		Timestamp:     now,
		CorrelationID: corrID,
		PreviousState: string(prevStatus),
		NewState:      string(models.JobStatusFailed),
		CreatedAt:     now,
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
	}

	if err := m.persistJobTransition(ctx, job, []models.JobStatus{models.JobStatusRunning}, auditEvent); err != nil {
		return nil, err
	}

	return deepCopyScanJob(job), nil
}

// CancelJob transitions an active (QUEUED or RUNNING) job to CANCELLED guarded by optimistic CAS.
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
		return deepCopyScanJob(job), nil
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

	auditEvent := &models.Event{
		EventID:       events.GenerateID("evt"),
		EventType:     models.EventJobCancelled,
		JobID:         job.ID,
		TargetID:      job.TargetID,
		Timestamp:     now,
		CorrelationID: corrID,
		PreviousState: string(prevStatus),
		NewState:      string(models.JobStatusCancelled),
		CreatedAt:     now,
		Payload: map[string]interface{}{
			"job_id":         job.ID,
			"target_id":      job.TargetID,
			"timestamp":      now.Format(time.RFC3339),
			"correlation_id": corrID,
			"previous_state": string(prevStatus),
			"new_state":      string(models.JobStatusCancelled),
			"job_type":       job.Type,
		},
	}

	if err := m.persistJobTransition(ctx, job, []models.JobStatus{models.JobStatusQueued, models.JobStatusRunning}, auditEvent); err != nil {
		return nil, err
	}

	return deepCopyScanJob(job), nil
}

// HandleTargetDeactivated cancels all active (QUEUED or RUNNING) jobs for a target that was deactivated or deleted.
func (m *Manager) HandleTargetDeactivated(ctx context.Context, targetID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	jobList, err := m.repo.ListJobs(ctx, targetID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, job := range jobList {
		if job.Status == models.JobStatusQueued || job.Status == models.JobStatusRunning {
			prevStatus := job.Status
			job.Status = models.JobStatusCancelled
			job.CompletedAt = &now
			job.Error = "target deactivated or deleted: lifecycle violation fail-closed"
			corrID := events.GenerateID("corr")
			auditEvent := &models.Event{
				EventID:       events.GenerateID("evt"),
				EventType:     models.EventJobCancelled,
				JobID:         job.ID,
				TargetID:      job.TargetID,
				Timestamp:     now,
				CorrelationID: corrID,
				PreviousState: string(prevStatus),
				NewState:      string(models.JobStatusCancelled),
				CreatedAt:     now,
				Payload: map[string]interface{}{
					"job_id":         job.ID,
					"target_id":      job.TargetID,
					"timestamp":      now.Format(time.RFC3339),
					"correlation_id": corrID,
					"previous_state": string(prevStatus),
					"new_state":      string(models.JobStatusCancelled),
					"error":          "target deactivated or deleted: lifecycle violation fail-closed",
				},
			}
			_ = m.persistJobTransition(ctx, job, []models.JobStatus{models.JobStatusQueued, models.JobStatusRunning}, auditEvent)
		}
	}
	return nil
}

// ReconstructJobLifecycle audits the event sequence for a given job and derives the final reconstructed state (Requirement 17).
func ReconstructJobLifecycle(eventsList []*models.Event) (models.JobStatus, error) {
	if len(eventsList) == 0 {
		return "", errors.New("no audit events to reconstruct lifecycle")
	}

	// Sort events chronologically ASC, tie-breaker event_id ASC
	sorted := make([]*models.Event, len(eventsList))
	copy(sorted, eventsList)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Timestamp.Equal(sorted[j].Timestamp) {
			return sorted[i].EventID < sorted[j].EventID
		}
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	var current models.JobStatus
	for i, evt := range sorted {
		switch evt.EventType {
		case models.EventJobCreated:
			if i != 0 {
				return "", fmt.Errorf("unexpected JOB_CREATED event at step %d", i)
			}
			if evt.NewState != string(models.JobStatusQueued) {
				return "", fmt.Errorf("JOB_CREATED event has invalid new_state: %s", evt.NewState)
			}
			current = models.JobStatusQueued

		case models.EventJobStarted:
			if current != models.JobStatusQueued {
				return "", fmt.Errorf("cannot transition to RUNNING from state %s (event_id=%s)", current, evt.EventID)
			}
			if evt.PreviousState != string(models.JobStatusQueued) || evt.NewState != string(models.JobStatusRunning) {
				return "", fmt.Errorf("inconsistent states in JOB_STARTED: prev=%s, new=%s", evt.PreviousState, evt.NewState)
			}
			current = models.JobStatusRunning

		case models.EventJobCompleted:
			if current != models.JobStatusRunning {
				return "", fmt.Errorf("cannot transition to COMPLETED from state %s (event_id=%s)", current, evt.EventID)
			}
			if evt.PreviousState != string(models.JobStatusRunning) || evt.NewState != string(models.JobStatusCompleted) {
				return "", fmt.Errorf("inconsistent states in JOB_COMPLETED: prev=%s, new=%s", evt.PreviousState, evt.NewState)
			}
			current = models.JobStatusCompleted

		case models.EventJobFailed:
			if current != models.JobStatusRunning {
				return "", fmt.Errorf("cannot transition to FAILED from state %s (event_id=%s)", current, evt.EventID)
			}
			if evt.PreviousState != string(models.JobStatusRunning) || evt.NewState != string(models.JobStatusFailed) {
				return "", fmt.Errorf("inconsistent states in JOB_FAILED: prev=%s, new=%s", evt.PreviousState, evt.NewState)
			}
			current = models.JobStatusFailed

		case models.EventJobCancelled:
			if current != models.JobStatusQueued && current != models.JobStatusRunning {
				return "", fmt.Errorf("cannot transition to CANCELLED from terminal state %s (event_id=%s)", current, evt.EventID)
			}
			if evt.NewState != string(models.JobStatusCancelled) {
				return "", fmt.Errorf("invalid new_state in JOB_CANCELLED: %s", evt.NewState)
			}
			current = models.JobStatusCancelled
		}
	}

	return current, nil
}
