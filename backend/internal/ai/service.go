package ai

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/storage"
)

// Service coordinates gathering evidence, triggering analysis via the Python client,
// persisting candidates/signals, and managing candidate lifecycle states.
type Service interface {
	AnalyzeAsset(ctx context.Context, targetID, assetID string) (*models.AnalysisRun, []*models.FindingCandidate, error)
	AnalyzeTarget(ctx context.Context, targetID string) ([]*models.AnalysisRun, error)
	GetAnalysisRun(ctx context.Context, runID string) (*models.AnalysisRun, error)
	ListAnalysisRuns(ctx context.Context, targetID string) ([]*models.AnalysisRun, error)
	ListCandidates(ctx context.Context, filter models.CandidateFilter) ([]*models.FindingCandidate, int, error)
	GetCandidate(ctx context.Context, id string) (*models.FindingCandidate, error)
	UpdateCandidateState(ctx context.Context, id string, req models.UpdateCandidateStateRequest) (*models.FindingCandidate, error)
	ListSignals(ctx context.Context, targetID, assetID string) ([]*models.SecuritySignal, error)
	Health(ctx context.Context) (*HealthPayload, error)
}

type analysisService struct {
	client       Client
	analysisRepo storage.AIAnalysisRepository
	intelRepo    storage.AssetIntelligenceRepository
	eventBus     events.EventBus
	logger       *slog.Logger
}

// NewService instantiates the unified AI analysis domain service.
func NewService(
	client Client,
	analysisRepo storage.AIAnalysisRepository,
	intelRepo storage.AssetIntelligenceRepository,
	eventBus events.EventBus,
	logger *slog.Logger,
) Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &analysisService{
		client:       client,
		analysisRepo: analysisRepo,
		intelRepo:    intelRepo,
		eventBus:     eventBus,
		logger:       logger,
	}
}

func generateID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b))
}

// BuildStructuredEvidence gathers all intelligence data for an asset from the repository.
func (s *analysisService) BuildStructuredEvidence(ctx context.Context, targetID, assetID string) (*StructuredEvidencePayload, error) {
	detail, err := s.intelRepo.GetAssetDetail(ctx, targetID, assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch asset detail for %s: %w", assetID, err)
	}

	evidence := &StructuredEvidencePayload{
		TargetID:             targetID,
		AssetID:              assetID,
		Technologies:         make([]TechnologyEvidencePayload, 0),
		SecurityObservations: make([]SecurityObservationEvidencePayload, 0),
		URLs:                 make([]URLEvidencePayload, 0),
		PageAssets:           make([]any, 0),
		ResponseMetadata:     make(map[string]any),
	}

	// 1. Service evidence
	if len(detail.Services) > 0 {
		svc := detail.Services[0]
		headersMap := make(map[string]string)
		if svc.Headers != nil {
			for k, v := range svc.Headers {
				headersMap[k] = v
			}
		}
		evidence.Service = &ServiceEvidencePayload{
			URL:            svc.ServiceIdentity,
			StatusCode:     svc.StatusCode,
			ContentType:    svc.ContentType,
			PageTitle:      svc.PageTitle,
			WebServer:      svc.WebServer,
			ResponseTimeMS: int(svc.ResponseTimeMS),
			TLSVersion:     svc.TLSVersion,
			Headers:        headersMap,
		}
	}

	// 2. Technologies evidence
	for _, tech := range detail.Technologies {
		var ver string
		if tech.Version != nil {
			ver = *tech.Version
		}
		evidence.Technologies = append(evidence.Technologies, TechnologyEvidencePayload{
			TechnologyName: tech.TechnologyName,
			Category:       tech.Category,
			Version:        ver,
			Confidence:     string(tech.Confidence),
			Evidence:       tech.Evidence,
		})
	}

	// 3. Security observations evidence
	for _, obs := range detail.SecurityObservations {
		evidence.SecurityObservations = append(evidence.SecurityObservations, SecurityObservationEvidencePayload{
			PropertyName: obs.PropertyName,
			IsPresent:    obs.IsPresent,
			Details:      obs.Details,
			RawValue:     obs.RawValue,
		})
	}

	// 4. URLs evidence
	for _, u := range detail.URLs {
		evidence.URLs = append(evidence.URLs, URLEvidencePayload{
			URL:    u.URL,
			Depth:  u.Depth,
			Source: u.Source,
		})
	}

	// 5. Page Assets evidence
	for _, pa := range detail.PageAssets {
		evidence.PageAssets = append(evidence.PageAssets, map[string]any{
			"url":         pa.URL,
			"asset_type":  pa.AssetType,
			"source_page": pa.SourcePage,
			"in_scope":    pa.IsInScope,
		})
	}

	return evidence, nil
}

// AnalyzeAsset executes end-to-end analysis on a single asset.
func (s *analysisService) AnalyzeAsset(ctx context.Context, targetID, assetID string) (*models.AnalysisRun, []*models.FindingCandidate, error) {
	runID := generateID("run")
	now := time.Now().UTC()

	run := &models.AnalysisRun{
		ID:        runID,
		TargetID:  targetID,
		AssetID:   assetID,
		Status:    models.AnalysisRunStatusRunning,
		Provider:  "ai-engine",
		Model:     "analysis-service",
		CreatedAt: now,
	}

	if err := s.analysisRepo.SaveAnalysisRun(ctx, run); err != nil {
		s.logger.Warn("Failed to persist initial analysis run", slog.String("run_id", runID), slog.Any("error", err))
	}

	if s.eventBus != nil {
		_ = s.eventBus.Publish(ctx, models.Event{
			EventType: models.EventAnalysisStarted,
			TargetID:  targetID,
			Payload: map[string]any{
				"run_id":   runID,
				"asset_id": assetID,
			},
		})
	}

	evidence, err := s.BuildStructuredEvidence(ctx, targetID, assetID)
	if err != nil {
		run.Status = models.AnalysisRunStatusFailed
		run.Error = fmt.Sprintf("failed to compile structured evidence: %v", err)
		completedAt := time.Now().UTC()
		run.CompletedAt = &completedAt
		_ = s.analysisRepo.UpdateAnalysisRun(ctx, run)
		return run, nil, err
	}

	reqPayload := &AnalyzePayload{
		TargetID: targetID,
		AssetID:  assetID,
		RunID:    runID,
		Evidence: *evidence,
	}

	result, err := s.client.Analyze(ctx, reqPayload)
	if err != nil {
		run.Status = models.AnalysisRunStatusFailed
		run.Error = fmt.Sprintf("ai engine call failed: %v", err)
		completedAt := time.Now().UTC()
		run.CompletedAt = &completedAt
		_ = s.analysisRepo.UpdateAnalysisRun(ctx, run)

		if s.eventBus != nil {
			_ = s.eventBus.Publish(ctx, models.Event{
				EventType: models.EventAnalysisFailed,
				TargetID:  targetID,
				Payload: map[string]any{
					"run_id": runID,
					"error":  run.Error,
				},
			})
		}
		return run, nil, err
	}

	// Update run details from engine result
	run.Status = models.AnalysisRunStatusCompleted
	run.Provider = result.Provider
	run.Model = result.Model
	run.Summary = result.Summary
	run.ConfidenceNotes = result.ConfidenceNotes
	run.ExecutionTimeMS = result.ExecutionTimeMS
	completedTime := time.Now().UTC()
	run.CompletedAt = &completedTime
	run.SignalsCount = len(result.SignalsParsed)
	run.CandidatesCount = len(result.Candidates)

	// Persist Signals
	for _, sig := range result.SignalsParsed {
		sigModel := &models.SecuritySignal{
			ID:            sig.ID,
			AnalysisRunID: runID,
			TargetID:      sig.TargetID,
			AssetID:       sig.AssetID,
			SignalType:    sig.SignalType,
			SeverityHint:  sig.SeverityHint,
			Evidence:      sig.Evidence,
			Source:        sig.Source,
			URL:           sig.URL,
			Details:       sig.Details,
			DetectedAt:    sig.DetectedAt,
		}
		if sigModel.DetectedAt.IsZero() {
			sigModel.DetectedAt = time.Now().UTC()
		}
		if err := s.analysisRepo.SaveSecuritySignal(ctx, sigModel); err != nil {
			s.logger.Warn("Failed to persist security signal", slog.String("signal_id", sig.ID), slog.Any("error", err))
		} else if s.eventBus != nil {
			_ = s.eventBus.Publish(ctx, models.Event{
				EventType: models.EventSignalDetected,
				TargetID:  targetID,
				Payload: map[string]any{
					"signal_id":   sig.ID,
					"signal_type": sig.SignalType,
					"severity":    sig.SeverityHint,
				},
			})
		}
	}

	// Persist Candidates
	var savedCandidates []*models.FindingCandidate
	for _, c := range result.Candidates {
		candModel := &models.FindingCandidate{
			ID:                      c.ID,
			AnalysisRunID:           runID,
			TargetID:                c.TargetID,
			AssetID:                 c.AssetID,
			Category:                c.Category,
			Title:                   c.Title,
			Description:             c.Description,
			State:                   models.CandidateState(c.State),
			ConfidenceScore:         c.ConfidenceScore,
			Reasoning:               c.Reasoning,
			MissingEvidence:         c.MissingEvidence,
			ValidationSteps:         c.ValidationSteps,
			EvidenceReferences:      c.EvidenceReferences,
			RecommendedVerification: c.RecommendedVerification,
			IsMock:                  c.IsMock,
			CreatedAt:               c.CreatedAt,
			UpdatedAt:               c.UpdatedAt,
		}
		if candModel.CreatedAt.IsZero() {
			candModel.CreatedAt = time.Now().UTC()
		}
		if candModel.UpdatedAt.IsZero() {
			candModel.UpdatedAt = time.Now().UTC()
		}

		if err := s.analysisRepo.SaveFindingCandidate(ctx, candModel); err != nil {
			s.logger.Warn("Failed to persist finding candidate", slog.String("candidate_id", c.ID), slog.Any("error", err))
		} else {
			savedCandidates = append(savedCandidates, candModel)
			if s.eventBus != nil {
				_ = s.eventBus.Publish(ctx, models.Event{
					EventType: models.EventCandidateCreated,
					TargetID:  targetID,
					Payload: map[string]any{
						"candidate_id": c.ID,
						"category":     c.Category,
						"title":        c.Title,
						"confidence":   c.ConfidenceScore,
					},
				})
			}
		}

		// Persist Candidate Evidences
		for idx, ref := range c.EvidenceReferences {
			evi := &models.CandidateEvidence{
				ID:           generateID("evi"),
				CandidateID:  c.ID,
				EvidenceType: "reference",
				ReferenceID:  ref,
				Summary:      fmt.Sprintf("Evidence reference #%d for candidate %s", idx+1, c.ID),
				CollectedAt:  time.Now().UTC(),
			}
			_ = s.analysisRepo.SaveCandidateEvidence(ctx, evi)
		}
	}

	_ = s.analysisRepo.UpdateAnalysisRun(ctx, run)

	if s.eventBus != nil {
		_ = s.eventBus.Publish(ctx, models.Event{
			EventType: models.EventAnalysisCompleted,
			TargetID:  targetID,
			Payload: map[string]any{
				"run_id":     runID,
				"signals":    run.SignalsCount,
				"candidates": run.CandidatesCount,
				"duration":   run.ExecutionTimeMS,
			},
		})
	}

	return run, savedCandidates, nil
}

// AnalyzeTarget runs analysis across all live assets for a target.
func (s *analysisService) AnalyzeTarget(ctx context.Context, targetID string) ([]*models.AnalysisRun, error) {
	assets, _, err := s.intelRepo.ListAssetsFiltered(ctx, models.AssetFilter{
		TargetID: targetID,
		Limit:    100,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list assets for target %s: %w", targetID, err)
	}

	var runs []*models.AnalysisRun
	for _, asset := range assets {
		// Only analyze assets that have services or live status
		run, _, err := s.AnalyzeAsset(ctx, targetID, asset.ID)
		if err != nil {
			s.logger.Warn("Analysis failed for asset", slog.String("asset_id", asset.ID), slog.Any("error", err))
			continue
		}
		runs = append(runs, run)
	}

	return runs, nil
}

func (s *analysisService) GetAnalysisRun(ctx context.Context, runID string) (*models.AnalysisRun, error) {
	return s.analysisRepo.GetAnalysisRun(ctx, runID)
}

func (s *analysisService) ListAnalysisRuns(ctx context.Context, targetID string) ([]*models.AnalysisRun, error) {
	return s.analysisRepo.ListAnalysisRuns(ctx, targetID)
}

func (s *analysisService) ListCandidates(ctx context.Context, filter models.CandidateFilter) ([]*models.FindingCandidate, int, error) {
	return s.analysisRepo.ListFindingCandidates(ctx, filter)
}

func (s *analysisService) GetCandidate(ctx context.Context, id string) (*models.FindingCandidate, error) {
	return s.analysisRepo.GetFindingCandidate(ctx, id)
}

func (s *analysisService) UpdateCandidateState(ctx context.Context, id string, req models.UpdateCandidateStateRequest) (*models.FindingCandidate, error) {
	if err := s.analysisRepo.UpdateCandidateState(ctx, id, req.State, req.Reason); err != nil {
		return nil, err
	}

	candidate, err := s.analysisRepo.GetFindingCandidate(ctx, id)
	if err != nil {
		return nil, err
	}

	if s.eventBus != nil {
		_ = s.eventBus.Publish(ctx, models.Event{
			EventType: models.EventCandidateUpdated,
			TargetID:  candidate.TargetID,
			Payload: map[string]any{
				"candidate_id": id,
				"new_state":    req.State,
				"reason":       req.Reason,
			},
		})
	}

	return candidate, nil
}

func (s *analysisService) ListSignals(ctx context.Context, targetID, assetID string) ([]*models.SecuritySignal, error) {
	return s.analysisRepo.ListSecuritySignals(ctx, targetID, assetID)
}

func (s *analysisService) Health(ctx context.Context) (*HealthPayload, error) {
	return s.client.Health(ctx)
}
