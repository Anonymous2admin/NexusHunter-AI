package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/ai"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/api"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/cloudintel"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/config"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/evidence"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/intel"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/jobs"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/jsintel"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/planner"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/reasoning"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/recon"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/storage"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/waf"


	_ "github.com/lib/pq"
)

func main() {
	// 1. Initialize Configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// 2. Initialize Structured Logger (slog)
	var logLevel slog.Level
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	logger.Info("Starting NexusHunter-AI Server",
		slog.String("service", cfg.ServiceName),
		slog.String("version", cfg.Version),
		slog.String("env", cfg.AppEnv),
		slog.Int("port", cfg.HTTPPort),
	)

	// 3. Initialize Storage Layer (Postgres or In-Memory)
	var (
		targetStore      storage.TargetRepository
		jobStore         storage.JobRepository
		reconStore       storage.ReconRepository
		intelStore       storage.AssetIntelligenceRepository
		analysisStore    storage.AIAnalysisRepository
		secStore         storage.SecurityIntelligenceRepository
		evidenceStore    storage.EvidenceRepository
		reasoningStore   storage.ReasoningRepository
		scopeImportStore storage.ScopeImportRepository
		jsStore          storage.JSIntelligenceRepository
		cloudStore       storage.CloudIntelligenceRepository
		wafStore         storage.WAFIntelligenceRepository
		plannerStore     storage.HuntingPlannerRepository

		storageMode = "MEMORY"
		runtimeMode = "DEMO_SYNTHETIC"
		dataOrigin  = "DEMO_SYNTHETIC"
		dbConn      *sql.DB
	)
	if cfg.DatabaseURL != "" {
		logger.Info("Connecting to PostgreSQL database", slog.String("db_url", maskDatabaseURL(cfg.DatabaseURL)))
		db, err := sql.Open("postgres", cfg.DatabaseURL)
		if err != nil {
			logger.Error("Failed to open database connection pool", slog.Any("error", err))
			os.Exit(1)
		}
		pingCtx, pingCancel := context.WithTimeout(context.Background(), 2*time.Second)
		if pingErr := db.PingContext(pingCtx); pingErr != nil {
			pingCancel()
			_ = db.Close()
			if cfg.AppEnv == "production" {
				logger.Error("PostgreSQL database unreachable in production", slog.Any("error", pingErr))
				os.Exit(1)
			}
			logger.Warn("PostgreSQL database unreachable in development; falling back to high-speed in-memory store", slog.Any("error", pingErr))
			memStorage := storage.NewMemoryStorage()
			targetStore = memStorage
			jobStore = memStorage
			reconStore = memStorage
			intelStore = memStorage
			analysisStore = memStorage
			secStore = memStorage
			evidenceStore = memStorage
			reasoningStore = memStorage
			scopeImportStore = memStorage
			jsStore = memStorage
			cloudStore = memStorage
			wafStore = memStorage
			plannerStore = memStorage
		} else {
			pingCancel()
			defer db.Close()
			pgStorage := storage.NewPostgresStorage(db)
			targetStore = pgStorage
			jobStore = pgStorage
			reconStore = pgStorage
			intelStore = pgStorage
			analysisStore = pgStorage
			secStore = pgStorage
			evidenceStore = pgStorage
			reasoningStore = pgStorage

			pg8Storage := storage.NewPostgresPhase8Storage(db)
			scopeImportStore = pg8Storage
			jsStore = pg8Storage
			cloudStore = pg8Storage
			wafStore = pg8Storage
			plannerStore = pg8Storage

			storageMode = "POSTGRES"
			runtimeMode = "LIVE_BACKEND"
			dataOrigin = "LIVE_BACKEND"
			dbConn = db
		}
	} else {
		logger.Info("No DATABASE_URL configured; initializing high-speed in-memory store for local development")
		memStorage := storage.NewMemoryStorage()
		targetStore = memStorage
		jobStore = memStorage
		reconStore = memStorage
		intelStore = memStorage
		analysisStore = memStorage
		secStore = memStorage
		evidenceStore = memStorage
		reasoningStore = memStorage
		scopeImportStore = memStorage
		jsStore = memStorage
		cloudStore = memStorage
		wafStore = memStorage
		plannerStore = memStorage
	}

	// 4. Initialize Core Domain Services & Recon Engine
	scopeValidator := scope.NewValidator()
	eventBus := events.NewMemoryEventBus(500)
	jobManager := jobs.NewManager(eventBus, jobStore)
	jobManager.SetTargetChecker(targetStore)

	engineCfg := recon.DefaultEngineConfig()
	pipeline := recon.NewPipeline(
		engineCfg,
		scopeValidator,
		eventBus,
		reconStore,
		targetStore,
		nil,
		nil,
		nil,
	)
	reconEngine := recon.NewEngine(
		pipeline,
		jobManager,
		targetStore,
		reconStore,
		scopeValidator,
		eventBus,
	)

	// Initialize Asset Intelligence Engine and attach to recon pipeline
	intelEngine := intel.NewEngine(intelStore, eventBus)
	reconEngine.SetIntelAnalyzer(intelEngine)

	// Initialize Security Intelligence Engine
	secEngine := intel.NewSecurityIntelligenceEngine(secStore, targetStore, reconStore, intelStore, analysisStore, scopeValidator, eventBus)
	intelEngine.SetSecurityIntelligenceEngine(secEngine)

	// Initialize AI Analysis HTTP Client & Service
	aiClient := ai.NewClient(cfg.AIServiceURL, 60*time.Second)
	aiService := ai.NewService(aiClient, analysisStore, intelStore, eventBus, logger)

	// Initialize Phase 6 Evidence Intelligence & Reasoning Engine
	evidenceEngine := evidence.NewEngine(evidenceStore, scopeValidator, logger)

	// Initialize Phase 7 Security Reasoning & Investigation Engine
	reasoningEngine := reasoning.NewEngine(reasoningStore, evidenceStore, targetStore, reconStore)

	// Initialize Phase 8 Intelligence (Scope, JS, Cloud, WAF, Planner)
	scopeSanitizer := scope.NewSanitizer()
	jsIntelSvc := jsintel.NewService(scopeValidator, jsintel.DefaultLimits())
	cloudIntelSvc := cloudintel.NewService(scopeValidator, 10*time.Second)
	wafDetector := waf.NewDetector()
	plannerSvc := planner.NewService(scopeValidator)

	// 5. Setup HTTP Router & Handler
	handler := api.NewHandler(cfg, targetStore, scopeValidator, jobManager, eventBus, reconEngine, reconStore, intelStore, analysisStore, aiService)
	handler.SetSecurityIntelligence(secStore, secEngine)
	handler.SetEvidenceIntelligence(evidenceStore, evidenceEngine)
	handler.SetReasoningIntelligence(reasoningStore, reasoningEngine)
	handler.SetPhase8Intelligence(api.Phase8Dependencies{
		ScopeImportRepo: scopeImportStore,
		ScopeSanitizer:  scopeSanitizer,
		JSRepo:          jsStore,
		JSIntel:         jsIntelSvc,
		CloudRepo:       cloudStore,
		CloudIntel:      cloudIntelSvc,
		WAFRepo:         wafStore,
		WAFDetector:     wafDetector,
		PlannerRepo:     plannerStore,
		PlannerSvc:      plannerSvc,
	})
	handler.SetRuntimeModes(storageMode, runtimeMode, dataOrigin, dbConn)
	router := api.NewRouter(handler, logger)


	serverAddr := fmt.Sprintf("0.0.0.0:%d", cfg.HTTPPort)
	srv := &http.Server{
		Addr:         serverAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// 6. Start HTTP Server in background goroutine
	serverErrChan := make(chan error, 1)
	go func() {
		logger.Info("HTTP API server listening", slog.String("address", serverAddr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrChan <- err
		}
	}()

	// 7. Graceful Shutdown on SIGINT / SIGTERM
	quitChan := make(chan os.Signal, 1)
	signal.Notify(quitChan, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrChan:
		logger.Error("HTTP server failed unexpectedly", slog.Any("error", err))
		os.Exit(1)
	case sig := <-quitChan:
		logger.Info("Shutdown signal received, initiating graceful teardown...", slog.String("signal", sig.String()))

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("Graceful shutdown encountered error, forcing exit", slog.Any("error", err))
			os.Exit(1)
		}
		logger.Info("NexusHunter-AI server successfully terminated")
	}
}

func maskDatabaseURL(u string) string {
	if len(u) > 15 {
		return u[:10] + "..." + u[len(u)-5:]
	}
	return "***"
}
