package recon

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/jobs"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/storage"
)

var (
	ErrReconRunNotFound = errors.New("reconnaissance execution run not found")
	ErrTargetNotFound   = errors.New("target not found")
)

// ReconEngine defines the operational contract for triggering, monitoring, and canceling reconnaissance runs.
type ReconEngine interface {
	StartRecon(ctx context.Context, targetID string, opts ReconOptions) (*models.ScanJob, error)
	GetRun(ctx context.Context, jobID string) (*models.ReconRun, error)
	CancelRecon(ctx context.Context, jobID string) error
	GetPipeline() *Pipeline
}

// Engine implements ReconEngine with strict scope enforcement, job lifecycle management, and telemetry.
type Engine struct {
	mu         sync.Mutex
	pipeline   *Pipeline
	jobSvc     jobs.JobService
	targetRepo storage.TargetRepository
	reconRepo  storage.ReconRepository
	scopeSvc   scope.ScopeService
	eventBus   events.EventBus
	cancels    map[string]context.CancelFunc
}

// NewEngine creates an initialized Engine instance.
func NewEngine(
	pipeline *Pipeline,
	jobSvc jobs.JobService,
	targetRepo storage.TargetRepository,
	reconRepo storage.ReconRepository,
	scopeSvc scope.ScopeService,
	eventBus events.EventBus,
) *Engine {
	return &Engine{
		pipeline:   pipeline,
		jobSvc:     jobSvc,
		targetRepo: targetRepo,
		reconRepo:  reconRepo,
		scopeSvc:   scopeSvc,
		eventBus:   eventBus,
		cancels:    make(map[string]context.CancelFunc),
	}
}

// GetPipeline returns the underlying pipeline for configuration inspection or testing.
func (e *Engine) GetPipeline() *Pipeline {
	return e.pipeline
}

// SetIntelAnalyzer forwards the passive intelligence analyzer to the recon pipeline.
func (e *Engine) SetIntelAnalyzer(analyzer IntelAnalyzer) {
	if e.pipeline != nil {
		e.pipeline.SetIntelAnalyzer(analyzer)
	}
}

// StartRecon begins an asynchronous, scoped reconnaissance scan for an authorized target.
func (e *Engine) StartRecon(ctx context.Context, targetID string, opts ReconOptions) (*models.ScanJob, error) {
	if targetID == "" {
		return nil, jobs.ErrMissingTarget
	}

	// 1. Fetch and rigorously validate target
	target, err := e.targetRepo.GetByID(ctx, targetID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrTargetNotFound
		}
		return nil, err
	}
	if target == nil {
		return nil, ErrTargetNotFound
	}

	// 2. Strict fail-closed scope check
	if err := e.scopeSvc.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("fail-closed scope validation rejected target: %w", err)
	}

	if target.Status != models.TargetStatusActive {
		return nil, jobs.ErrTargetNotActive
	}

	// 3. Create Scan Job
	metadata := map[string]interface{}{
		"target_root": target.RootDomain,
		"options":     opts,
	}
	job, err := e.jobSvc.CreateJob(ctx, targetID, "RECON", metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan job: %w", err)
	}

	// 4. Start Scan Job
	runningJob, err := e.jobSvc.StartJob(ctx, job.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to start scan job: %w", err)
	}

	// 5. Setup cancellable execution context
	runCtx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.cancels[job.ID] = cancel
	e.mu.Unlock()

	// 6. Launch pipeline asynchronously
	go func(j *models.ScanJob, t *models.Target, o ReconOptions) {
		defer func() {
			e.mu.Lock()
			delete(e.cancels, j.ID)
			e.mu.Unlock()
			cancel()
		}()

		run, execErr := e.pipeline.Execute(runCtx, j, t, o)
		if execErr != nil {
			_, _ = e.jobSvc.FailJob(context.Background(), j.ID, execErr.Error())
			return
		}

		if run != nil && run.Status == models.JobStatusCancelled {
			_, _ = e.jobSvc.CancelJob(context.Background(), j.ID)
			return
		}

		_, _ = e.jobSvc.CompleteJob(context.Background(), j.ID)
	}(runningJob, target, opts)

	return runningJob, nil
}

// GetRun returns the execution summary for a reconnaissance job.
func (e *Engine) GetRun(ctx context.Context, jobID string) (*models.ReconRun, error) {
	run, err := e.reconRepo.GetReconRunByJobID(ctx, jobID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrReconRunNotFound
		}
		return nil, err
	}
	return run, nil
}

// CancelRecon triggers graceful cancellation of an in-flight reconnaissance job.
func (e *Engine) CancelRecon(ctx context.Context, jobID string) error {
	e.mu.Lock()
	cancel, exists := e.cancels[jobID]
	if exists {
		cancel()
		delete(e.cancels, jobID)
	}
	e.mu.Unlock()

	_, err := e.jobSvc.CancelJob(ctx, jobID)
	return err
}
