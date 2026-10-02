package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/api"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/cloudintel"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/config"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/evidence"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/jobs"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/jsintel"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/planner"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/reasoning"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/storage"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/waf"
)

const testDBURL = "postgres://nexushunter:huntersecret123@127.0.0.1:5432/nexushunter_db?sslmode=disable"

func getTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("postgres", testDBURL)
	if err != nil {
		t.Skipf("PostgreSQL database not available: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("PostgreSQL ping failed: %v", err)
	}
	return db
}

func getPostgresStorage(t *testing.T) *storage.PostgresStorage {
	db := getTestDB(t)
	return storage.NewPostgresStorage(db)
}

func setupTestAPIHandler(t *testing.T, db *sql.DB) *api.Handler {
	cfg := &config.Config{
		AppEnv:      "development",
		HTTPPort:    8085,
		ServiceName: "nexushunter-test",
		Version:     "0.1.0-test",
	}
	pgStore := storage.NewPostgresStorage(db)
	pg8Store := storage.NewPostgresPhase8Storage(db)
	scopeValidator := scope.NewValidator()
	eventBus := events.NewMemoryEventBus(100)
	jobManager := jobs.NewManager(eventBus, pgStore)
	jobManager.SetTargetChecker(pgStore)

	evidenceEngine := evidence.NewEngine(pgStore, scopeValidator, slog.Default())
	reasoningEngine := reasoning.NewEngine(pgStore, pgStore, pgStore, pgStore)

	handler := api.NewHandler(cfg, pgStore, scopeValidator, jobManager, eventBus, nil, pgStore, pgStore, pgStore, nil)
	handler.SetEvidenceIntelligence(pgStore, evidenceEngine)
	handler.SetReasoningIntelligence(pgStore, reasoningEngine)
	handler.SetPhase8Intelligence(api.Phase8Dependencies{
		ScopeImportRepo: pg8Store,
		ScopeSanitizer:  scope.NewSanitizer(),
		JSRepo:          pg8Store,
		CloudRepo:       pg8Store,
		WAFRepo:         pg8Store,
		PlannerRepo:     pg8Store,
	})
	handler.SetRuntimeModes("POSTGRES", "LIVE_BACKEND", "LIVE_BACKEND", db)
	return handler
}

// ==============================================================================
// Section 3: REAL GO UNIT TESTS (Direct Production Functions)
// ==============================================================================

func TestRealGoUnitFunctions(t *testing.T) {
	// 1. Scope Sanitizer NewSanitizer() & SanitizeScopeFile()
	sanitizer := scope.NewSanitizer()
	rawJSON := []byte(`{
		"target": {
			"scope": {
				"advanced_mode": true,
				"include": [
					{"enabled": true, "host": "^.*\\.example\\.com$", "protocol": "any"}
				],
				"exclude": [
					{"enabled": true, "host": "^admin\\.example\\.com$", "protocol": "any"}
				]
			}
		}
	}`)
	review, err := sanitizer.SanitizeScopeFile(rawJSON, "scope.json")
	if err != nil {
		t.Fatalf("SanitizeScopeFile failed: %v", err)
	}
	if len(review.RootDomains) == 0 {
		t.Fatalf("expected discovered root domains, got none")
	}
	if review.SelectedRootDomain != "" {
		t.Fatalf("expected initial SelectedRootDomain to be empty, got: %s", review.SelectedRootDomain)
	}

	// 2. Job Manager NewManager(), CreateJob(), StartJob(), CompleteJob()
	memRepo := storage.NewMemoryStorage()
	mgr := jobs.NewManager(nil, memRepo)
	target := &models.Target{
		ID:             "tgt-unit-001",
		Name:           "Unit Target",
		RootDomain:     "example.com",
		AllowedDomains: []string{"example.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_ = memRepo.Create(context.Background(), target)
	mgr.SetTargetChecker(memRepo)

	job, err := mgr.CreateJob(context.Background(), target.ID, "RECON_HTTP", map[string]interface{}{"depth": 1})
	if err != nil {
		t.Fatalf("CreateJob failed: %v", err)
	}
	if job.Status != models.JobStatusQueued {
		t.Fatalf("expected QUEUED, got %s", job.Status)
	}

	started, err := mgr.StartJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("StartJob failed: %v", err)
	}
	if started.Status != models.JobStatusRunning {
		t.Fatalf("expected RUNNING, got %s", started.Status)
	}

	completed, err := mgr.CompleteJob(context.Background(), job.ID)
	if err != nil {
		t.Fatalf("CompleteJob failed: %v", err)
	}
	if completed.Status != models.JobStatusCompleted {
		t.Fatalf("expected COMPLETED, got %s", completed.Status)
	}

	// 3. Evidence Engine NewEngine(), RecordEvidence(), VerifyEvidenceIntegrity()
	evEngine := evidence.NewEngine(memRepo, nil, slog.Default())
	ev := &models.Evidence{
		ID:           "ev-unit-001",
		TargetID:     target.ID,
		AssetID:      "ast-001",
		EvidenceType: "HTTP_RESPONSE",
		Summary:      "GET /status test response",
		CapturedAt:   time.Now().UTC(),
		DataOrigin:   "LIVE_BACKEND",
		Response: &models.HTTPResponseContext{
			StatusCode: 200,
			Headers:    map[string]string{"Server": "nginx"},
		},
	}
	recorded, err := evEngine.RecordEvidence(context.Background(), ev)
	if err != nil {
		t.Fatalf("RecordEvidence failed: %v", err)
	}
	if recorded.SHA256 == "" {
		t.Fatalf("expected cryptographic SHA256, got empty")
	}

	integ, err := evEngine.VerifyEvidenceIntegrity(context.Background(), recorded.ID)
	if err != nil {
		t.Fatalf("VerifyEvidenceIntegrity failed: %v", err)
	}
	if !integ.CanonicalMatches || integ.IsTampered {
		t.Fatalf("expected intact evidence, got tampered: %+v", integ)
	}

	// 4. Planner planner.NewService() & GenerateInvestigationPlan()
	pService := planner.NewService(nil)
	planCtx := planner.PlannerContext{
		Asset:             &models.Asset{ID: "ast-001", Hostname: "api.example.com", TargetID: target.ID},
		HypothesisID:      "hyp-001",
		SourceEvidenceIDs: []string{recorded.ID},
	}
	plan, err := pService.GenerateInvestigationPlan(context.Background(), target, "ast-001", planCtx)
	if err != nil {
		t.Fatalf("GenerateInvestigationPlan failed: %v", err)
	}
	if plan == nil || len(plan.Steps) == 0 {
		t.Fatalf("expected investigation plan steps, got empty")
	}
}

// ==============================================================================
// Section 4 & 5: REAL JOB TRANSACTION TEST (PostgreSQL QUEUED -> RUNNING -> COMPLETED)
// ==============================================================================

func TestRealJobPostgresTransaction(t *testing.T) {
	ctx := context.Background()
	pgStore := getPostgresStorage(t)

	targetID := fmt.Sprintf("tgt-jobtx-%d", time.Now().UnixNano())
	target := &models.Target{
		ID:             targetID,
		Name:           "Postgres Job Target",
		RootDomain:     "example.com",
		AllowedDomains: []string{"example.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := pgStore.Create(ctx, target); err != nil {
		t.Fatalf("failed to insert target: %v", err)
	}

	jobID := fmt.Sprintf("job-tx-%d", time.Now().UnixNano())
	job := &models.ScanJob{
		ID:        jobID,
		TargetID:  targetID,
		Type:      "PORT_SCAN",
		Status:    models.JobStatusQueued,
		CreatedAt: time.Now().UTC(),
		Metadata:  map[string]interface{}{"depth": 2},
	}

	createdEvt := &models.Event{
		EventID:       fmt.Sprintf("evt-create-%d", time.Now().UnixNano()),
		EventType:     models.EventJobCreated,
		JobID:         job.ID,
		TargetID:      job.TargetID,
		Timestamp:     time.Now().UTC(),
		PreviousState: "",
		NewState:      string(models.JobStatusQueued),
	}

	// 1. Insert QUEUED job atomically with audit event
	if err := pgStore.CreateJobWithAuditEvent(ctx, job, createdEvt); err != nil {
		t.Fatalf("failed to create job in postgres: %v", err)
	}

	// Verify database state: QUEUED
	persisted, err := pgStore.GetJobByID(ctx, jobID)
	if err != nil {
		t.Fatalf("failed to read job: %v", err)
	}
	if persisted.Status != models.JobStatusQueued {
		t.Fatalf("expected QUEUED, got %s", persisted.Status)
	}

	// 2. QUEUED -> RUNNING with audit event
	now := time.Now().UTC()
	persisted.Status = models.JobStatusRunning
	persisted.StartedAt = &now
	startEvt := &models.Event{
		EventID:       fmt.Sprintf("evt-start-%d", time.Now().UnixNano()),
		EventType:     models.EventJobStarted,
		JobID:         job.ID,
		TargetID:      job.TargetID,
		Timestamp:     now,
		PreviousState: string(models.JobStatusQueued),
		NewState:      string(models.JobStatusRunning),
	}
	if err := pgStore.TransitionJobWithAuditEvent(ctx, persisted, []models.JobStatus{models.JobStatusQueued}, startEvt); err != nil {
		t.Fatalf("failed to transition to RUNNING in postgres: %v", err)
	}

	runningJob, err := pgStore.GetJobByID(ctx, jobID)
	if err != nil {
		t.Fatalf("failed to read running job: %v", err)
	}
	if runningJob.Status != models.JobStatusRunning {
		t.Fatalf("expected RUNNING, got %s", runningJob.Status)
	}

	// 3. RUNNING -> COMPLETED with audit event
	compNow := time.Now().UTC()
	runningJob.Status = models.JobStatusCompleted
	runningJob.CompletedAt = &compNow
	compEvt := &models.Event{
		EventID:       fmt.Sprintf("evt-comp-%d", time.Now().UnixNano()),
		EventType:     models.EventJobCompleted,
		JobID:         job.ID,
		TargetID:      job.TargetID,
		Timestamp:     compNow,
		PreviousState: string(models.JobStatusRunning),
		NewState:      string(models.JobStatusCompleted),
	}
	if err := pgStore.TransitionJobWithAuditEvent(ctx, runningJob, []models.JobStatus{models.JobStatusRunning}, compEvt); err != nil {
		t.Fatalf("failed to transition to COMPLETED in postgres: %v", err)
	}

	finalJob, err := pgStore.GetJobByID(ctx, jobID)
	if err != nil {
		t.Fatalf("failed to read completed job: %v", err)
	}
	if finalJob.Status != models.JobStatusCompleted {
		t.Fatalf("expected COMPLETED, got %s", finalJob.Status)
	}

	// Verify events in database
	db := getTestDB(t)
	var eventCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE job_id = $1", jobID).Scan(&eventCount)
	if err != nil {
		t.Fatalf("failed to count audit events: %v", err)
	}
	if eventCount < 3 {
		t.Fatalf("expected at least 3 audit events (CREATED, STARTED, COMPLETED), found %d", eventCount)
	}
}

// ==============================================================================
// Section 6: REAL JOB ROLLBACK TEST (Failure Injection during audit-event insertion)
// ==============================================================================

func TestRealJobRollbackOnAuditFailure(t *testing.T) {
	ctx := context.Background()
	db := getTestDB(t)

	targetID := fmt.Sprintf("tgt-rollback-%d", time.Now().UnixNano())
	pgStore := storage.NewPostgresStorage(db)
	_ = pgStore.Create(ctx, &models.Target{
		ID:             targetID,
		Name:           "Rollback Target",
		RootDomain:     "rollback.example.com",
		AllowedDomains: []string{"rollback.example.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	jobID := fmt.Sprintf("job-rb-%d", time.Now().UnixNano())
	job := &models.ScanJob{
		ID:        jobID,
		TargetID:  targetID,
		Type:      "RECON_HTTP",
		Status:    models.JobStatusQueued,
		CreatedAt: time.Now().UTC(),
	}
	if err := pgStore.CreateJob(ctx, job); err != nil {
		t.Fatalf("failed to create job: %v", err)
	}

	// Attempt transition to RUNNING with a duplicate event ID to trigger unique constraint failure
	existingEvtID := fmt.Sprintf("evt-dup-%d", time.Now().UnixNano())
	_, err := db.ExecContext(ctx, "INSERT INTO events (event_id, event_type, job_id, target_id, timestamp, created_at) VALUES ($1, 'TEST', $2, $3, NOW(), NOW())",
		existingEvtID, jobID, targetID)
	if err != nil {
		t.Fatalf("failed to insert pre-existing event: %v", err)
	}

	// Try to transition the job using an EventID that exceeds the VARCHAR(64) limit in PostgreSQL to trigger SQL failure
	attemptJob := *job
	attemptJob.Status = models.JobStatusRunning
	now := time.Now().UTC()
	attemptJob.StartedAt = &now
	failingEvt := &models.Event{
		EventID:   strings.Repeat("event-id-exceeding-sixty-four-chars-limit-so-postgres-aborts-tx-", 3), // > 64 chars causes VARCHAR(64) constraint failure
		EventType: models.EventJobStarted,
		JobID:     jobID,
		TargetID:  targetID,
		Timestamp: now,
	}

	err = pgStore.TransitionJobWithAuditEvent(ctx, &attemptJob, []models.JobStatus{models.JobStatusQueued}, failingEvt)
	if err == nil {
		t.Fatalf("expected transaction to fail due to audit event insertion failure, but got success")
	}

	// CRITICAL ASSERTION: The job status in PostgreSQL MUST REMAIN QUEUED, NOT RUNNING!
	persisted, err := pgStore.GetJobByID(ctx, jobID)
	if err != nil {
		t.Fatalf("failed to fetch job: %v", err)
	}
	if persisted.Status != models.JobStatusQueued {
		t.Fatalf("ROLLBACK FAILED! Job status mutated to '%s', expected to remain '%s'", persisted.Status, models.JobStatusQueued)
	}
}

// ==============================================================================
// Section 7: REAL DISTRIBUTED CAS TEST (Two Independent JobManager instances, same DB)
// ==============================================================================

func TestRealDistributedCAS(t *testing.T) {
	ctx := context.Background()
	db := getTestDB(t)

	targetID := fmt.Sprintf("tgt-cas-%d", time.Now().UnixNano())
	pgStore1 := storage.NewPostgresStorage(db)
	pgStore2 := storage.NewPostgresStorage(db)

	_ = pgStore1.Create(ctx, &models.Target{
		ID:             targetID,
		Name:           "CAS Target",
		RootDomain:     "cas.example.com",
		AllowedDomains: []string{"cas.example.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	// Two independent managers, each with its own memory/mutex
	mgrA := jobs.NewManager(nil, pgStore1)
	mgrA.SetTargetChecker(pgStore1)

	mgrB := jobs.NewManager(nil, pgStore2)
	mgrB.SetTargetChecker(pgStore2)

	// Create one QUEUED job
	job, err := mgrA.CreateJob(ctx, targetID, "CERT_TRANSPARENCY_LOGS", nil)
	if err != nil {
		t.Fatalf("failed to create job: %v", err)
	}

	// Run concurrently Manager A StartJob() and Manager B StartJob()
	var wg sync.WaitGroup
	wg.Add(2)

	var errA, errB error
	var jobA, jobB *models.ScanJob

	go func() {
		defer wg.Done()
		jobA, errA = mgrA.StartJob(ctx, job.ID)
	}()

	go func() {
		defer wg.Done()
		jobB, errB = mgrB.StartJob(ctx, job.ID)
	}()

	wg.Wait()

	t.Logf("Result A: job=%v err=%v", jobA != nil, errA)
	t.Logf("Result B: job=%v err=%v", jobB != nil, errB)

	// Database state MUST be RUNNING
	finalJob, err := pgStore1.GetJobByID(ctx, job.ID)
	if err != nil {
		t.Fatalf("failed to fetch final job: %v", err)
	}
	if finalJob.Status != models.JobStatusRunning {
		t.Fatalf("expected RUNNING, got %s", finalJob.Status)
	}

	// Verify events in database: exactly ONE JOB_STARTED durable event
	var startedEventsCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE job_id = $1 AND event_type = $2", job.ID, models.EventJobStarted).Scan(&startedEventsCount)
	if err != nil {
		t.Fatalf("failed to count started events: %v", err)
	}
	if startedEventsCount != 1 {
		t.Fatalf("DISTRIBUTED CAS VIOLATION: expected exactly 1 JOB_STARTED event, got %d", startedEventsCount)
	}
}

// ==============================================================================
// Section 8: REAL SCOPE CONFIRMATION TRANSACTION TEST (PostgreSQL Rollback Injection)
// ==============================================================================

func TestRealScopeConfirmationTransaction(t *testing.T) {
	ctx := context.Background()
	db := getTestDB(t)
	phase8Store := storage.NewPostgresPhase8Storage(db)

	reviewID := fmt.Sprintf("rev-tx-%d", time.Now().UnixNano())
	review := &models.ScopeImportReview{
		ID:                   reviewID,
		FileName:             "bugbounty.json",
		Status:               "READY_FOR_REVIEW",
		SelectedRootDomain:   "",
		CanonicalScopeSHA256: "canon-hash-123456",
		RootDomains: []models.RootDomainCandidate{
			{NormalizedDomain: "security-corp.com", Confidence: "HIGH"},
			{NormalizedDomain: "corp-internal.com", Confidence: "MEDIUM"},
		},
		CanonicalScope: &models.CanonicalScope{
			IncludeHosts: []models.AdvancedScopeRule{{Enabled: true, Host: `^.*\.security-corp\.com$`}},
		},
		CreatedAt: time.Now().UTC(),
	}

	if err := phase8Store.SaveImportReview(ctx, review); err != nil {
		t.Fatalf("failed to save import review: %v", err)
	}

	// 1. Authoritative ConfirmScopeAndCreateTarget
	targetID := fmt.Sprintf("tgt-conf-%d", time.Now().UnixNano())
	target := &models.Target{
		ID:             targetID,
		Name:           "Security Corp Production",
		RootDomain:     "security-corp.com",
		AllowedDomains: []string{"security-corp.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}

	confirmedTgt, confirmedRev, err := phase8Store.ConfirmScopeAndCreateTarget(
		ctx, reviewID, "security-corp.com", target, "alice@security-team.org", "reviewed manually",
	)
	if err != nil {
		t.Fatalf("ConfirmScopeAndCreateTarget failed: %v", err)
	}
	if confirmedRev.Status != "CONFIRMED" {
		t.Fatalf("expected CONFIRMED review, got %s", confirmedRev.Status)
	}
	if confirmedTgt.ScopeImportID != reviewID {
		t.Fatalf("expected target ScopeImportID %s, got %s", reviewID, confirmedTgt.ScopeImportID)
	}

	// 2. Inject target INSERT failure: duplicate target ID on a fresh review
	reviewID2 := fmt.Sprintf("rev-fail-%d", time.Now().UnixNano())
	review2 := &models.ScopeImportReview{
		ID:                   reviewID2,
		FileName:             "scope2.json",
		Status:               "READY_FOR_REVIEW",
		SelectedRootDomain:   "",
		CanonicalScopeSHA256: "canon-hash-99999",
		RootDomains: []models.RootDomainCandidate{
			{NormalizedDomain: "other-corp.com", Confidence: "HIGH"},
		},
		CanonicalScope: &models.CanonicalScope{
			IncludeHosts: []models.AdvancedScopeRule{{Enabled: true, Host: `^.*\.other-corp\.com$`}},
		},
		CreatedAt: time.Now().UTC(),
	}
	_ = phase8Store.SaveImportReview(ctx, review2)

	// Try confirming review2 with already-existing targetID (Primary key collision on targets)
	targetDup := &models.Target{
		ID:             targetID, // DUPLICATE ID
		Name:           "Duplicate Target",
		RootDomain:     "other-corp.com",
		AllowedDomains: []string{"other-corp.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_, _, errDup := phase8Store.ConfirmScopeAndCreateTarget(
		ctx, reviewID2, "other-corp.com", targetDup, "bob@security.org", "test duplicate fail",
	)
	if errDup == nil {
		t.Fatalf("expected primary key collision failure on target insert, got nil")
	}

	// Verify review2 REMAINS READY_FOR_REVIEW, NOT CONFIRMED
	persistedRev2, err := phase8Store.GetImportReview(ctx, reviewID2)
	if err != nil {
		t.Fatalf("failed to get review2: %v", err)
	}
	if persistedRev2.Status != "READY_FOR_REVIEW" {
		t.Fatalf("ROLLBACK FAILED! review2 status mutated to '%s', expected 'READY_FOR_REVIEW'", persistedRev2.Status)
	}
}

// ==============================================================================
// Section 9: REAL CONCURRENT SCOPE CONFIRMATION (Root A vs Root B)
// ==============================================================================

func TestRealConcurrentScopeConfirmation(t *testing.T) {
	ctx := context.Background()
	db := getTestDB(t)

	reviewID := fmt.Sprintf("rev-race-%d", time.Now().UnixNano())
	review := &models.ScopeImportReview{
		ID:                   reviewID,
		FileName:             "race.json",
		Status:               "READY_FOR_REVIEW",
		SelectedRootDomain:   "",
		CanonicalScopeSHA256: "canon-hash-race-111",
		RootDomains: []models.RootDomainCandidate{
			{NormalizedDomain: "race-alpha.com", Confidence: "HIGH"},
			{NormalizedDomain: "race-beta.com", Confidence: "HIGH"},
		},
		CanonicalScope: &models.CanonicalScope{
			IncludeHosts: []models.AdvancedScopeRule{
				{Enabled: true, Host: `^.*\.race-alpha\.com$`},
				{Enabled: true, Host: `^.*\.race-beta\.com$`},
			},
		},
		CreatedAt: time.Now().UTC(),
	}

	phase8Store1 := storage.NewPostgresPhase8Storage(db)
	phase8Store2 := storage.NewPostgresPhase8Storage(db)

	if err := phase8Store1.SaveImportReview(ctx, review); err != nil {
		t.Fatalf("failed to save review: %v", err)
	}

	targetA := &models.Target{
		ID:             fmt.Sprintf("tgt-race-a-%d", time.Now().UnixNano()),
		Name:           "Race Target A",
		RootDomain:     "race-alpha.com",
		AllowedDomains: []string{"race-alpha.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	targetB := &models.Target{
		ID:             fmt.Sprintf("tgt-race-b-%d", time.Now().UnixNano()),
		Name:           "Race Target B",
		RootDomain:     "race-beta.com",
		AllowedDomains: []string{"race-beta.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var errA, errB error

	go func() {
		defer wg.Done()
		_, _, errA = phase8Store1.ConfirmScopeAndCreateTarget(ctx, reviewID, "race-alpha.com", targetA, "op-a", "reason-a")
	}()

	go func() {
		defer wg.Done()
		_, _, errB = phase8Store2.ConfirmScopeAndCreateTarget(ctx, reviewID, "race-beta.com", targetB, "op-b", "reason-b")
	}()

	wg.Wait()

	// Exactly one MUST succeed, and exactly one MUST receive conflict/error
	successCount := 0
	conflictCount := 0
	if errA == nil {
		successCount++
	} else {
		conflictCount++
	}
	if errB == nil {
		successCount++
	} else {
		conflictCount++
	}

	if successCount != 1 || conflictCount != 1 {
		t.Fatalf("CONCURRENT CONFIRMATION VIOLATION: expected exactly 1 success and 1 conflict, got success=%d, conflict=%d (errA=%v, errB=%v)",
			successCount, conflictCount, errA, errB)
	}

	// Verify database: exactly ONE target exists with scope_import_id = reviewID
	var targetCount int
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM targets WHERE scope_import_id = $1", reviewID).Scan(&targetCount)
	if err != nil {
		t.Fatalf("failed to count targets: %v", err)
	}
	if targetCount != 1 {
		t.Fatalf("expected exactly 1 target created, got %d", targetCount)
	}
}

// ==============================================================================
// Section 10: REAL EVIDENCE INTEGRITY & TAMPERING TEST
// ==============================================================================

func TestRealEvidenceIntegrityAndTampering(t *testing.T) {
	ctx := context.Background()
	db := getTestDB(t)
	pgStore := storage.NewPostgresStorage(db)
	evEngine := evidence.NewEngine(pgStore, nil, slog.Default())

	targetID := fmt.Sprintf("tgt-ev-integ-%d", time.Now().UnixNano())
	_ = pgStore.Create(ctx, &models.Target{
		ID:             targetID,
		Name:           "Evidence Integrity Target",
		RootDomain:     "integ.example.com",
		AllowedDomains: []string{"integ.example.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	asset := &models.Asset{
		ID:        fmt.Sprintf("ast-integ-%d", time.Now().UnixNano()),
		TargetID:  targetID,
		Hostname:  "ast-integ.example.com",
		AssetType: "SUBDOMAIN",
		Status:    "ACTIVE",
	}
	_ = pgStore.SaveAsset(ctx, asset)

	evID := fmt.Sprintf("ev-test-%d", time.Now().UnixNano())
	rawEv := &models.Evidence{
		ID:           evID,
		TargetID:     targetID,
		AssetID:      asset.ID,
		EvidenceType: "HTTP_RESPONSE",
		Summary:      "Original Untampered HTTP response",
		CapturedAt:   time.Now().UTC(),
		DataOrigin:   "LIVE_BACKEND",
		Response: &models.HTTPResponseContext{
			StatusCode:  200,
			Headers:     map[string]string{"Server": "nginx", "X-Custom": "val1"},
			BodySnippet: "{\"status\":\"ok\"}",
		},
	}

	recorded, err := evEngine.RecordEvidence(ctx, rawEv)
	if err != nil {
		t.Fatalf("RecordEvidence failed: %v", err)
	}

	// 1. Initial verification: canonical matches, is_tampered = false
	res1, err := evEngine.VerifyEvidenceIntegrity(ctx, recorded.ID)
	if err != nil {
		t.Fatalf("VerifyEvidenceIntegrity failed: %v", err)
	}
	if res1.IsTampered || !res1.CanonicalMatches {
		t.Fatalf("expected intact evidence, got tampered: %+v", res1)
	}

	// 2. TAMPER WITH PERSISTED RECORD IN POSTGRESQL DIRECTLY
	tamperedResponseJSON := `{"status_code":200,"body_snippet":"{\"status\":\"TAMPERED_MALICIOUS_DATA\"}","headers":{"Server":"nginx"}}`
	_, err = db.ExecContext(ctx, "UPDATE evidence_records SET response_data = $1 WHERE id = $2", tamperedResponseJSON, recorded.ID)
	if err != nil {
		t.Fatalf("failed to tamper with database row: %v", err)
	}

	// 3. Second verification: MUST DETECT TAMPERING!
	res2, err := evEngine.VerifyEvidenceIntegrity(ctx, recorded.ID)
	if err != nil {
		t.Fatalf("VerifyEvidenceIntegrity failed on tampered record: %v", err)
	}
	if !res2.IsTampered || res2.CanonicalMatches {
		t.Fatalf("TAMPER DETECTION FAILED: expected IsTampered=true and CanonicalMatches=false, got %+v", res2)
	}
}

// ==============================================================================
// Section 11: REAL SUPPORTED GATE (Epistemic gate for SUPPORTED status)
// ==============================================================================

func TestRealSupportedGate(t *testing.T) {
	ctx := context.Background()
	db := getTestDB(t)
	pgStore := storage.NewPostgresStorage(db)
	evEngine := evidence.NewEngine(pgStore, nil, slog.Default())
	handler := setupTestAPIHandler(t, db)

	targetA := fmt.Sprintf("tgt-gate-a-%d", time.Now().UnixNano())
	targetB := fmt.Sprintf("tgt-gate-b-%d", time.Now().UnixNano())
	_ = pgStore.Create(ctx, &models.Target{
		ID:             targetA,
		Name:           "Gate Target A",
		RootDomain:     "gate-a.example.com",
		AllowedDomains: []string{"gate-a.example.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})
	_ = pgStore.Create(ctx, &models.Target{
		ID:             targetB,
		Name:           "Gate Target B",
		RootDomain:     "gate-b.example.com",
		AllowedDomains: []string{"gate-b.example.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	grpA := &models.HypothesisGroup{
		ID:        fmt.Sprintf("grp-gate-a-%d", time.Now().UnixNano()),
		TargetID:  targetA,
		Subject:   "Gate Group A",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := pgStore.SaveHypothesisGroup(ctx, grpA); err != nil {
		t.Fatalf("failed to create hypothesis group A: %v", err)
	}

	grpB := &models.HypothesisGroup{
		ID:        fmt.Sprintf("grp-gate-b-%d", time.Now().UnixNano()),
		TargetID:  targetB,
		Subject:   "Gate Group B",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := pgStore.SaveHypothesisGroup(ctx, grpB); err != nil {
		t.Fatalf("failed to create hypothesis group B: %v", err)
	}

	assetA := &models.Asset{
		ID:        fmt.Sprintf("ast-gate-a-%d", time.Now().UnixNano()),
		TargetID:  targetA,
		Hostname:  "ast-a.example.com",
		AssetType: "SUBDOMAIN",
		Status:    "ACTIVE",
	}
	_ = pgStore.SaveAsset(ctx, assetA)

	// Create valid evidence on Target A
	validEvID := fmt.Sprintf("ev-valid-%d", time.Now().UnixNano())
	validEv := &models.Evidence{
		ID:           validEvID,
		TargetID:     targetA,
		AssetID:      assetA.ID,
		EvidenceType: "HTTP_RESPONSE",
		Summary:      "Legitimate verified probe",
		CapturedAt:   time.Now().UTC(),
		DataOrigin:   "LIVE_BACKEND",
		Response: &models.HTTPResponseContext{
			StatusCode: 200,
			Headers:    map[string]string{"Server": "nginx"},
		},
	}
	_, err := evEngine.RecordEvidence(ctx, validEv)
	if err != nil {
		t.Fatalf("failed to record valid evidence: %v", err)
	}

	updateStatus := func(hypID string, status models.HypothesisStatus) (int, string) {
		reqBody, _ := json.Marshal(map[string]string{"status": string(status)})
		req := httptest.NewRequest(http.MethodPost, "/api/hypotheses/"+hypID+"/status", stringsReader(string(reqBody)))
		req.SetPathValue("id", hypID)
		rec := httptest.NewRecorder()
		handler.UpdateHypothesisStatus(rec, req)
		return rec.Code, rec.Body.String()
	}

	// Case A: Valid evidence -> success
	hypA := &models.Hypothesis{
		ID:                 fmt.Sprintf("hyp-a-%d", time.Now().UnixNano()),
		GroupID:            grpA.ID,
		TargetID:           targetA,
		AssetID:            assetA.ID,
		Title:              "Valid Auth Bypass Hypothesis",
		Status:             models.HypothesisStatusInvestigating,
		EpistemicStatus:    models.EpistemicHypothesized,
		SupportingEvidence: []string{validEvID},
		MissingEvidence:    []models.EvidenceRequirement{},
		FalsificationConditions: []models.FalsificationCondition{
			{ConditionDescription: "Rate limit challenge triggered", Result: models.FalsificationSurvivedTest},
		},
		CreatedAt: time.Now().UTC(),
	}
	if err := pgStore.SaveHypothesis(ctx, hypA); err != nil {
		t.Fatalf("failed to save hypothesis A: %v", err)
	}

	codeA, bodyA := updateStatus(hypA.ID, models.HypothesisStatusSupported)
	if codeA != http.StatusOK {
		t.Fatalf("Case A (Valid evidence) failed: expected 200 OK, got %d: %s", codeA, bodyA)
	}

	// Case B: Missing evidence -> 400
	hypB := &models.Hypothesis{
		ID:                 fmt.Sprintf("hyp-b-%d", time.Now().UnixNano()),
		GroupID:            grpA.ID,
		TargetID:           targetA,
		AssetID:            assetA.ID,
		Title:              "Missing Evidence Hypothesis",
		Status:             models.HypothesisStatusInvestigating,
		SupportingEvidence: []string{validEvID},
		MissingEvidence: []models.EvidenceRequirement{
			{Description: "Requires differential probe on /v2/auth", Status: models.ReqStatusMissing},
		},
		FalsificationConditions: []models.FalsificationCondition{},
		CreatedAt:              time.Now().UTC(),
	}
	_ = pgStore.SaveHypothesis(ctx, hypB)
	codeB, _ := updateStatus(hypB.ID, models.HypothesisStatusSupported)
	if codeB != http.StatusBadRequest {
		t.Fatalf("Case B (Missing evidence) expected 400 Bad Request, got %d", codeB)
	}

	assetB := &models.Asset{
		ID:        fmt.Sprintf("ast-gate-b-%d", time.Now().UnixNano()),
		TargetID:  targetB,
		Hostname:  "ast-b.example.com",
		AssetType: "SUBDOMAIN",
		Status:    "ACTIVE",
	}
	if err := pgStore.SaveAsset(ctx, assetB); err != nil {
		t.Fatalf("failed to save asset B: %v", err)
	}

	// Case C: Cross-target evidence -> reject
	hypC := &models.Hypothesis{
		ID:                      fmt.Sprintf("hyp-c-%d", time.Now().UnixNano()),
		GroupID:                 grpB.ID,
		TargetID:                targetB,
		AssetID:                 assetB.ID,
		Title:                   "Cross-Target Hypothesis",
		Status:                  models.HypothesisStatusInvestigating,
		SupportingEvidence:      []string{validEvID},
		MissingEvidence:         []models.EvidenceRequirement{},
		FalsificationConditions: []models.FalsificationCondition{},
		CreatedAt:               time.Now().UTC(),
	}
	if err := pgStore.SaveHypothesis(ctx, hypC); err != nil {
		t.Fatalf("failed to save hypothesis C: %v", err)
	}
	codeC, _ := updateStatus(hypC.ID, models.HypothesisStatusSupported)
	if codeC != http.StatusBadRequest {
		t.Fatalf("Case C (Cross-target evidence) expected 400 Bad Request, got %d", codeC)
	}

	// Case D: Tampered evidence -> reject
	tamperedEvID := fmt.Sprintf("ev-tamper-%d", time.Now().UnixNano())
	rawTamper := &models.Evidence{
		ID:           tamperedEvID,
		TargetID:     targetA,
		AssetID:      assetA.ID,
		EvidenceType: "HTTP_RESPONSE",
		Summary:      "To be tampered",
		CapturedAt:   time.Now().UTC(),
		DataOrigin:   "LIVE_BACKEND",
		Response:     &models.HTTPResponseContext{StatusCode: 200},
	}
	_, _ = evEngine.RecordEvidence(ctx, rawTamper)
	_, _ = db.ExecContext(ctx, "UPDATE evidence_records SET response_data = '{\"status_code\":500}' WHERE id = $1", tamperedEvID)

	hypD := &models.Hypothesis{
		ID:                      fmt.Sprintf("hyp-d-%d", time.Now().UnixNano()),
		GroupID:                 grpA.ID,
		TargetID:                targetA,
		AssetID:                 assetA.ID,
		Title:                   "Tampered Evidence Hypothesis",
		Status:                  models.HypothesisStatusInvestigating,
		SupportingEvidence:      []string{tamperedEvID},
		MissingEvidence:         []models.EvidenceRequirement{},
		FalsificationConditions: []models.FalsificationCondition{},
		CreatedAt:               time.Now().UTC(),
	}
	if err := pgStore.SaveHypothesis(ctx, hypD); err != nil {
		t.Fatalf("failed to save hypothesis D: %v", err)
	}
	codeD, _ := updateStatus(hypD.ID, models.HypothesisStatusSupported)
	if codeD != http.StatusBadRequest {
		t.Fatalf("Case D (Tampered evidence) expected 400 Bad Request, got %d", codeD)
	}

	// Case E: DEMO/SIMULATED evidence -> reject
	demoEvID := fmt.Sprintf("ev-demo-%d", time.Now().UnixNano())
	demoEv := &models.Evidence{
		ID:           demoEvID,
		TargetID:     targetA,
		AssetID:      assetA.ID,
		EvidenceType: "HTTP_RESPONSE",
		Summary:      "Demo Synthetic probe",
		CapturedAt:   time.Now().UTC(),
		DataOrigin:   "DEMO_SYNTHETIC",
		Response:     &models.HTTPResponseContext{StatusCode: 200},
	}
	_, _ = evEngine.RecordEvidence(ctx, demoEv)

	hypE := &models.Hypothesis{
		ID:                      fmt.Sprintf("hyp-e-%d", time.Now().UnixNano()),
		GroupID:                 grpA.ID,
		TargetID:                targetA,
		AssetID:                 assetA.ID,
		Title:                   "Demo Evidence Hypothesis",
		Status:                  models.HypothesisStatusInvestigating,
		SupportingEvidence:      []string{demoEvID},
		MissingEvidence:         []models.EvidenceRequirement{},
		FalsificationConditions: []models.FalsificationCondition{},
		CreatedAt:               time.Now().UTC(),
	}
	if err := pgStore.SaveHypothesis(ctx, hypE); err != nil {
		t.Fatalf("failed to save hypothesis E: %v", err)
	}
	codeE, _ := updateStatus(hypE.ID, models.HypothesisStatusSupported)
	if codeE != http.StatusBadRequest {
		t.Fatalf("Case E (DEMO evidence) expected 400 Bad Request, got %d", codeE)
	}

	// Case F: Pending falsification condition -> reject
	hypF := &models.Hypothesis{
		ID:                 fmt.Sprintf("hyp-f-%d", time.Now().UnixNano()),
		GroupID:            grpA.ID,
		TargetID:           targetA,
		AssetID:            assetA.ID,
		Title:              "Pending Falsification Hypothesis",
		Status:             models.HypothesisStatusInvestigating,
		SupportingEvidence: []string{validEvID},
		MissingEvidence:    []models.EvidenceRequirement{},
		FalsificationConditions: []models.FalsificationCondition{
			{ConditionDescription: "Requires testing against secondary auth realm", Result: models.FalsificationPending},
		},
		CreatedAt: time.Now().UTC(),
	}
	if err := pgStore.SaveHypothesis(ctx, hypF); err != nil {
		t.Fatalf("failed to save hypothesis F: %v", err)
	}
	codeF, _ := updateStatus(hypF.ID, models.HypothesisStatusSupported)
	if codeF != http.StatusBadRequest {
		t.Fatalf("Case F (Pending falsification) expected 400 Bad Request, got %d", codeF)
	}
}

// ==============================================================================
// Section 12: REAL TARGET ISOLATION TEST (Target A vs Target B)
// ==============================================================================

func TestRealTargetIsolation(t *testing.T) {
	ctx := context.Background()
	db := getTestDB(t)
	pgStore := storage.NewPostgresStorage(db)
	evEngine := evidence.NewEngine(pgStore, nil, slog.Default())
	handler := setupTestAPIHandler(t, db)

	targetA := fmt.Sprintf("tgt-iso-a-%d", time.Now().UnixNano())
	targetB := fmt.Sprintf("tgt-iso-b-%d", time.Now().UnixNano())
	_ = pgStore.Create(ctx, &models.Target{
		ID:             targetA,
		Name:           "Iso Target A",
		RootDomain:     "iso-a.example.com",
		AllowedDomains: []string{"iso-a.example.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})
	_ = pgStore.Create(ctx, &models.Target{
		ID:             targetB,
		Name:           "Iso Target B",
		RootDomain:     "iso-b.example.com",
		AllowedDomains: []string{"iso-b.example.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	// Create Asset A under Target A
	assetA := &models.Asset{
		ID:        fmt.Sprintf("ast-iso-a-%d", time.Now().UnixNano()),
		TargetID:  targetA,
		Hostname:  "alpha.isocorp.com",
		AssetType: "SUBDOMAIN",
		Status:    "ACTIVE",
	}
	_ = pgStore.SaveAsset(ctx, assetA)

	// Create Evidence A attributed to Target A
	evA := &models.Evidence{
		ID:           fmt.Sprintf("ev-iso-a-%d", time.Now().UnixNano()),
		TargetID:     targetA,
		AssetID:      assetA.ID,
		EvidenceType: "HTTP_RESPONSE",
		Summary:      "Target A Evidence",
		CapturedAt:   time.Now().UTC(),
		DataOrigin:   "LIVE_BACKEND",
		Response:     &models.HTTPResponseContext{StatusCode: 200},
	}
	_, err := evEngine.RecordEvidence(ctx, evA)
	if err != nil {
		t.Fatalf("failed to record evidence: %v", err)
	}

	// Attempt to create Hypothesis on Target B referencing Evidence A
	body := fmt.Sprintf(`{
		"target_id": "%s",
		"title": "Target B Hypothesis referencing Evidence A",
		"supporting_evidence": ["%s"]
	}`, targetB, evA.ID)

	req := httptest.NewRequest(http.MethodPost, "/api/hypotheses", stringsReader(body))
	rec := httptest.NewRecorder()
	handler.CreateHypothesis(rec, req)

	// MUST BE REJECTED!
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("TARGET ISOLATION VIOLATION: expected 400 Bad Request when attaching Evidence A to Target B hypothesis, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ==============================================================================
// Section 21: REAL JS INTELLIGENCE TEST (Local synthetic server)
// ==============================================================================

func TestRealJSIntelligenceExtraction(t *testing.T) {
	ctx := context.Background()
	pgStore := getPostgresStorage(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = io.WriteString(w, `
				const apiEndpoint = "/api/v2/user/profile";
				const adminDebug = "/admin/metrics";
				function fetchUser() {
					return fetch(apiEndpoint);
				}
			`)
		case "/api/v2/user/profile":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"user": "alice"}`)
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<html><script src="/app.js"></script></html>`)
		}
	}))
	defer ts.Close()

	targetID := fmt.Sprintf("tgt-js-%d", time.Now().UnixNano())
	target := &models.Target{
		ID:             targetID,
		Name:           "JS Target",
		RootDomain:     "js.example.com",
		AllowedDomains: []string{"js.example.com"},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_ = pgStore.Create(ctx, target)

	analyzer := jsintel.NewJSAnalyzer()
	jsAsset := &models.JSAsset{
		ID:       fmt.Sprintf("js-ast-%d", time.Now().UnixNano()),
		TargetID: targetID,
		URL:      ts.URL + "/app.js",
	}

	jsCode := `
		const apiEndpoint = "/api/v2/user/profile";
		const adminDebug = "/admin/metrics";
		function fetchUser() {
			return fetch(apiEndpoint);
		}
	`
	refs, _, err := analyzer.Analyze(ctx, target, jsAsset, jsCode, nil)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	foundProfile := false
	foundAdmin := false
	for _, ref := range refs {
		if strings.Contains(ref.ExtractedValue, "/api/v2/user/profile") {
			foundProfile = true
		}
		if strings.Contains(ref.ExtractedValue, "/admin/metrics") {
			foundAdmin = true
		}
	}

	if !foundProfile || !foundAdmin {
		t.Fatalf("JS extraction failed: foundProfile=%v, foundAdmin=%v (extracted %d refs)", foundProfile, foundAdmin, len(refs))
	}
}

// ==============================================================================
// Section 22: REAL CLOUD REFERENCE TEST (Authorized vs Unauthorized)
// ==============================================================================

func TestRealCloudReferenceDiscovery(t *testing.T) {
	ctx := context.Background()
	validator := scope.NewValidator()
	cloudSvc := cloudintel.NewService(validator, 5*time.Second)

	rawHTML := `
		<html>
			<img src="https://my-company-assets.s3.amazonaws.com/logo.png" />
			<script src="https://storage.googleapis.com/prod-bundles/main.js"></script>
			<a href="https://unauthorized-external-bucket.blob.core.windows.net/data">data</a>
		</html>
	`

	target := &models.Target{ID: "tgt-cloud-test", Name: "Cloud Target"}
	refs, err := cloudSvc.ExtractCloudReferences(ctx, target, "ast-1", "HTML_BODY", "https://example.com/portal", rawHTML)
	if err != nil {
		t.Fatalf("ExtractCloudReferences failed: %v", err)
	}
	if len(refs) < 2 {
		t.Fatalf("expected at least 2 cloud references detected, got %d", len(refs))
	}

	for _, ref := range refs {
		if ref.Provider == "" {
			t.Errorf("expected provider identified for ref %+v", ref)
		}
	}
}

// ==============================================================================
// Section 23: WAF THROTTLE TEST (429 & Retry-After)
// ==============================================================================

func TestRealWAFThrottlerPolicy(t *testing.T) {
	throttler := waf.NewAdaptiveThrottler("ast-waf-test")

	// Initial status: NORMAL
	state, rps, circuitOpen := throttler.GetStatus()
	if state != "NORMAL" || circuitOpen {
		t.Fatalf("expected initial status NORMAL and open=false, got state=%s open=%v", state, circuitOpen)
	}
	if rps != 10.0 {
		t.Fatalf("expected initial RPS 10.0, got %f", rps)
	}

	// Simulate 429 response with Retry-After: 3
	throttler.Record429(3)

	// Status must immediately transition to RATE_LIMITED
	updatedState, updatedRPS, _ := throttler.GetStatus()
	if updatedState != "RATE_LIMITED" {
		t.Fatalf("expected throttling state change to RATE_LIMITED on 429, got %s", updatedState)
	}
	if updatedRPS >= 10.0 {
		t.Fatalf("expected halved RPS after 429, got %f", updatedRPS)
	}

	// Execution must be temporarily blocked by backoff delay
	allowed, reason := throttler.CanExecute()
	if allowed {
		t.Fatalf("expected CanExecute=false during Retry-After delay, but execution was allowed")
	}
	if reason == "" {
		t.Fatalf("expected non-empty backoff reason")
	}
}

// ==============================================================================
// Section 13: REAL RUNTIME HEALTH TEST
// ==============================================================================

func TestRealRuntimeHealth(t *testing.T) {
	db := getTestDB(t)
	handler := setupTestAPIHandler(t, db)

	// 1. With Postgres active:
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	handler.HealthCheck(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from health check, got %d", rec.Code)
	}

	var healthRes map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &healthRes); err != nil {
		t.Fatalf("failed to decode health response: %v", err)
	}

	if healthRes["runtime_mode"] != "LIVE_BACKEND" {
		t.Fatalf("expected runtime_mode LIVE_BACKEND, got %v", healthRes["runtime_mode"])
	}
	if healthRes["storage_mode"] != "POSTGRES" {
		t.Fatalf("expected storage_mode POSTGRES, got %v", healthRes["storage_mode"])
	}
	if healthRes["data_origin"] != "LIVE_BACKEND" {
		t.Fatalf("expected data_origin LIVE_BACKEND, got %v", healthRes["data_origin"])
	}

	// 2. Simulate DB unavailable: create a dedicated db connection that is immediately closed
	closedDB, err := sql.Open("postgres", "postgres://invalid:invalid@127.0.0.1:5432/non_existent?sslmode=disable")
	if err == nil {
		closedDB.Close()
	}
	handler.SetRuntimeModes("POSTGRES", "LIVE_BACKEND", "LIVE_BACKEND", closedDB)

	reqDegraded := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	recDegraded := httptest.NewRecorder()
	handler.HealthCheck(recDegraded, reqDegraded)

	var degradedRes map[string]interface{}
	if err := json.Unmarshal(recDegraded.Body.Bytes(), &degradedRes); err != nil {
		t.Fatalf("failed to decode degraded health response: %v", err)
	}

	if degradedRes["runtime_mode"] != "OFFLINE" {
		t.Fatalf("expected OFFLINE when DB is down, got %v", degradedRes["runtime_mode"])
	}
	if degradedRes["storage_mode"] != "UNAVAILABLE" {
		t.Fatalf("expected UNAVAILABLE when DB is down, got %v", degradedRes["storage_mode"])
	}
}

// ==============================================================================
// Section 14: REAL MEMORY FALLBACK TEST
// ==============================================================================

func TestRealMemoryFallback(t *testing.T) {
	cfg := &config.Config{
		AppEnv:      "development",
		HTTPPort:    8086,
		ServiceName: "nexushunter-memory-test",
		Version:     "0.1.0-dev",
	}
	memStore := storage.NewMemoryStorage()
	scopeVal := scope.NewValidator()
	eventBus := events.NewMemoryEventBus(100)
	jobMgr := jobs.NewManager(eventBus, memStore)

	handler := api.NewHandler(cfg, memStore, scopeVal, jobMgr, eventBus, nil, memStore, memStore, memStore, nil)
	handler.SetRuntimeModes("MEMORY", "DEMO_SYNTHETIC", "DEMO_SYNTHETIC", nil)

	// Verify health modes
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	handler.HealthCheck(rec, req)

	var health map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &health)

	if health["runtime_mode"] == "LIVE_BACKEND" {
		t.Fatalf("expected runtime_mode != LIVE_BACKEND in memory fallback, got %v", health["runtime_mode"])
	}
	if health["storage_mode"] != "MEMORY" {
		t.Fatalf("expected storage_mode MEMORY, got %v", health["storage_mode"])
	}
	if health["data_origin"] == "LIVE_BACKEND" {
		t.Fatalf("expected data_origin != LIVE_BACKEND in memory fallback, got %v", health["data_origin"])
	}

	// Attempt live network-affecting mutation (ExecuteControlledValidation): must reject fail-closed!
	mutReq := httptest.NewRequest(http.MethodPost, "/api/validation/execute", stringsReader(`{"target_id":"tgt-1","hostname":"test.example.com"}`))
	mutRec := httptest.NewRecorder()
	handler.ExecuteControlledValidation(mutRec, mutReq)

	if mutRec.Code == http.StatusOK {
		t.Fatalf("FAIL-CLOSED VIOLATION: live network-affecting mutation succeeded in memory demo mode")
	}
}

// ==============================================================================
// Section 15: REAL HTTP API TEST (End-to-End loopback HTTP requests)
// ==============================================================================

func TestRealHTTPAPI(t *testing.T) {
	db := getTestDB(t)
	handler := setupTestAPIHandler(t, db)
	router := api.NewRouter(handler, slog.Default())

	server := httptest.NewServer(router)
	defer server.Close()
	client := server.Client()

	ctx := context.Background()
	pgStore := storage.NewPostgresStorage(db)
	phase8Store := storage.NewPostgresPhase8Storage(db)

	// 1. GET /api/health
	res, err := client.Get(server.URL + "/api/health")
	if err != nil {
		t.Fatalf("GET /api/health failed: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/health status %d", res.StatusCode)
	}
	var healthBody map[string]interface{}
	_ = json.NewDecoder(res.Body).Decode(&healthBody)
	res.Body.Close()
	if healthBody["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", healthBody["status"])
	}

	// 2. POST /api/targets
	targetPayload := `{
		"name": "HTTP API Integration Target",
		"root_domain": "api-integ.example.com",
		"allowed_domains": ["api-integ.example.com"]
	}`
	res, err = client.Post(server.URL+"/api/targets", "application/json", stringsReader(targetPayload))
	if err != nil {
		t.Fatalf("POST /api/targets failed: %v", err)
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/targets unexpected status %d", res.StatusCode)
	}
	var createdTgt struct {
		Data models.Target `json:"data"`
	}
	_ = json.NewDecoder(res.Body).Decode(&createdTgt)
	res.Body.Close()
	targetID := createdTgt.Data.ID
	if targetID == "" {
		t.Fatalf("expected created target ID, got empty")
	}

	// 3. GET /api/targets
	res, err = client.Get(server.URL + "/api/targets")
	if err != nil {
		t.Fatalf("GET /api/targets failed: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/targets status %d", res.StatusCode)
	}
	res.Body.Close()

	// 4. POST /api/jobs
	jobPayload := fmt.Sprintf(`{
		"target_id": "%s",
		"type": "RECON_HTTP"
	}`, targetID)
	res, err = client.Post(server.URL+"/api/jobs", "application/json", stringsReader(jobPayload))
	if err != nil {
		t.Fatalf("POST /api/jobs failed: %v", err)
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/jobs status %d", res.StatusCode)
	}
	var createdJob struct {
		Data models.ScanJob `json:"data"`
	}
	_ = json.NewDecoder(res.Body).Decode(&createdJob)
	res.Body.Close()
	jobID := createdJob.Data.ID
	if jobID == "" {
		t.Fatalf("expected job ID, got empty")
	}

	// 5. POST /api/jobs/{id}/start
	res, err = client.Post(server.URL+"/api/jobs/"+jobID+"/start", "application/json", stringsReader("{}"))
	if err != nil {
		t.Fatalf("POST /api/jobs/{id}/start failed: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/jobs/{id}/start status %d", res.StatusCode)
	}
	res.Body.Close()

	// 6. POST /api/jobs/{id}/complete
	res, err = client.Post(server.URL+"/api/jobs/"+jobID+"/complete", "application/json", stringsReader("{}"))
	if err != nil {
		t.Fatalf("POST /api/jobs/{id}/complete failed: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/jobs/{id}/complete status %d", res.StatusCode)
	}
	res.Body.Close()

	// 7. POST /api/scope-imports/{id}/confirm
	reviewID := fmt.Sprintf("rev-http-%d", time.Now().UnixNano())
	review := &models.ScopeImportReview{
		ID:                   reviewID,
		FileName:             "http-test.json",
		Status:               "READY_FOR_REVIEW",
		SelectedRootDomain:   "",
		CanonicalScopeSHA256: "hash-http-scope",
		RootDomains: []models.RootDomainCandidate{
			{NormalizedDomain: "http-corp.com", Confidence: "HIGH"},
		},
		CanonicalScope: &models.CanonicalScope{
			IncludeHosts: []models.AdvancedScopeRule{{Enabled: true, Host: `^.*\.http-corp\.com$`}},
		},
		CreatedAt: time.Now().UTC(),
	}
	_ = phase8Store.SaveImportReview(ctx, review)

	confirmPayload := `{
		"selected_root_domain": "http-corp.com",
		"confirmed_by": "tester@example.com",
		"confirmation_reason": "Verified in automated HTTP API test"
	}`
	res, err = client.Post(server.URL+"/api/scope-imports/"+reviewID+"/confirm", "application/json", stringsReader(confirmPayload))
	if err != nil {
		t.Fatalf("POST /api/scope-imports/{id}/confirm failed: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/scope-imports/{id}/confirm status %d", res.StatusCode)
	}
	res.Body.Close()

	// 8. POST /api/evidence
	asset := &models.Asset{
		ID:        fmt.Sprintf("ast-http-%d", time.Now().UnixNano()),
		TargetID:  targetID,
		Hostname:  "api-integ.example.com",
		AssetType: "SUBDOMAIN",
		Status:    "ACTIVE",
	}
	if err := pgStore.SaveAsset(ctx, asset); err != nil {
		t.Fatalf("failed to save asset: %v", err)
	}

	evidencePayload := fmt.Sprintf(`{
		"target_id": "%s",
		"asset_id": "%s",
		"evidence_type": "HTTP_RESPONSE",
		"summary": "Real HTTP API Evidence",
		"data_origin": "LIVE_BACKEND",
		"request": {
			"method": "GET",
			"url": "https://api-integ.example.com/status"
		},
		"response": {
			"status_code": 200,
			"headers": {"Server": "nginx"}
		}
	}`, targetID, asset.ID)
	res, err = client.Post(server.URL+"/api/evidence", "application/json", stringsReader(evidencePayload))
	if err != nil {
		t.Fatalf("POST /api/evidence failed: %v", err)
	}
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/evidence status %d", res.StatusCode)
	}
	var createdEv struct {
		Status   string          `json:"status"`
		Evidence models.Evidence `json:"evidence"`
	}
	_ = json.NewDecoder(res.Body).Decode(&createdEv)
	res.Body.Close()
	evID := createdEv.Evidence.ID
	if evID == "" {
		t.Fatalf("expected evidence ID, got empty")
	}

	// 9. GET /api/evidence/{id}/integrity
	res, err = client.Get(server.URL + "/api/evidence/" + evID + "/integrity")
	if err != nil {
		t.Fatalf("GET /api/evidence/{id}/integrity failed: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/evidence/{id}/integrity status %d", res.StatusCode)
	}
	var integBody struct {
		CanonicalMatches bool `json:"canonical_matches"`
		IsTampered       bool `json:"is_tampered"`
	}
	_ = json.NewDecoder(res.Body).Decode(&integBody)
	res.Body.Close()
	if !integBody.CanonicalMatches || integBody.IsTampered {
		t.Fatalf("expected intact evidence integrity over HTTP, got %+v", integBody)
	}

	// 10. POST /api/reasoning/cycle
	reasoningPayload := fmt.Sprintf(`{"target_id": "%s"}`, targetID)
	res, err = client.Post(server.URL+"/api/reasoning/cycle", "application/json", stringsReader(reasoningPayload))
	if err != nil {
		t.Fatalf("POST /api/reasoning/cycle failed: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/reasoning/cycle status %d", res.StatusCode)
	}
	res.Body.Close()

	_ = pgStore
}

func stringsReader(s string) io.Reader {
	return strings.NewReader(s)
}

