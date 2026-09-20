package recon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/storage"
)

// IntelAnalyzer specifies passive fingerprinting and metadata analysis on safe probe results.
type IntelAnalyzer interface {
	AnalyzeHTTPProbe(ctx context.Context, targetID, assetID string, probe *HTTPProbeResult) error
}

// Pipeline executes the multi-stage, scoped reconnaissance lifecycle.
type Pipeline struct {
	config        EngineConfig
	scopeSvc      scope.ScopeService
	eventBus      events.EventBus
	reconRepo     storage.ReconRepository
	targetRepo    storage.TargetRepository
	subProvider   SubdomainProvider
	dnsResolver   DNSResolver
	httpProber    HTTPProber
	crawler       *Crawler
	intelAnalyzer IntelAnalyzer
}

// SetIntelAnalyzer attaches a passive intelligence analyzer to the pipeline.
func (p *Pipeline) SetIntelAnalyzer(analyzer IntelAnalyzer) {
	p.intelAnalyzer = analyzer
}

// NewPipeline assembles all reconnaissance components into an execution pipeline.
func NewPipeline(
	cfg EngineConfig,
	scopeSvc scope.ScopeService,
	bus events.EventBus,
	reconRepo storage.ReconRepository,
	targetRepo storage.TargetRepository,
	subProvider SubdomainProvider,
	dnsResolver DNSResolver,
	httpProber HTTPProber,
) *Pipeline {
	if subProvider == nil {
		subProvider = NewBaselineProvider(scopeSvc)
	}
	if dnsResolver == nil {
		dnsResolver = NewStandardDNSResolver(cfg.RequestTimeout)
	}
	if httpProber == nil {
		httpProber = NewStandardHTTPProber(cfg, scopeSvc)
	}
	crawler := NewCrawler(cfg, scopeSvc)

	return &Pipeline{
		config:      cfg,
		scopeSvc:    scopeSvc,
		eventBus:    bus,
		reconRepo:   reconRepo,
		targetRepo:  targetRepo,
		subProvider: subProvider,
		dnsResolver: dnsResolver,
		httpProber:  httpProber,
		crawler:     crawler,
	}
}

// Execute runs the reconnaissance pipeline for a specific job and target.
func (p *Pipeline) Execute(ctx context.Context, job *models.ScanJob, target *models.Target, opts ReconOptions) (*models.ReconRun, error) {
	// FAIL CLOSED: Validate target and scope up front
	if target == nil {
		return nil, scope.ErrTargetNil
	}
	if err := p.scopeSvc.ValidateTarget(target); err != nil {
		return nil, fmt.Errorf("fail-closed scope validation rejected target: %w", err)
	}

	runID := newID("run")
	now := time.Now().UTC()
	run := &models.ReconRun{
		ID:        runID,
		JobID:     job.ID,
		TargetID:  target.ID,
		Status:    models.JobStatusRunning,
		StartedAt: now,
	}

	if err := p.reconRepo.SaveReconRun(ctx, run); err != nil {
		return nil, fmt.Errorf("failed to initialize recon run record: %w", err)
	}

	p.publishEvent(models.EventReconStarted, job.ID, target.ID, map[string]interface{}{
		"run_id":  runID,
		"options": opts,
		"target":  target.RootDomain,
	})

	dedup := NewDeduplicator()
	progress := &AtomicProgress{}
	rateLimiter := NewRateLimiter(p.config.RequestsPerSecond, p.config.BurstSize)
	defer rateLimiter.Stop()

	// Periodic progress heartbeat
	progressTicker := time.NewTicker(2 * time.Second)
	defer progressTicker.Stop()
	stopHeartbeat := make(chan struct{})
	defer close(stopHeartbeat)

	go func() {
		for {
			select {
			case <-stopHeartbeat:
				return
			case <-ctx.Done():
				return
			case <-progressTicker.C:
				disc, res, prob, uDisc, uCrawl, errs, skip := progress.Snapshot()
				p.publishEvent(models.EventReconProgress, job.ID, target.ID, map[string]interface{}{
					"hosts_discovered":     disc,
					"hosts_resolved":       res,
					"http_probed":          prob,
					"urls_discovered":      uDisc,
					"urls_crawled":         uCrawl,
					"errors":               errs,
					"skipped_out_of_scope": skip,
				})
			}
		}
	}()

	var discoveredHosts []string
	var discoveredMu sync.Mutex

	// STAGE 1: Subdomain Discovery
	if opts.SubdomainDiscovery {
		subs, err := p.subProvider.Discover(ctx, target)
		if err != nil && ctx.Err() == nil {
			progress.IncErrors()
		}
		for _, host := range subs {
			if dedup.CheckAndAddHost(host) {
				discoveredMu.Lock()
				discoveredHosts = append(discoveredHosts, host)
				discoveredMu.Unlock()
				progress.IncDiscovered()

				// Persist asset
				asset := &models.Asset{
					ID:        newID("ast"),
					TargetID:  target.ID,
					Hostname:  host,
					AssetType: "SUBDOMAIN",
					Status:    "DISCOVERED",
					FirstSeen: time.Now().UTC(),
					LastSeen:  time.Now().UTC(),
				}
				if host == target.RootDomain {
					asset.AssetType = "ROOT_DOMAIN"
				}
				_ = p.reconRepo.SaveAsset(ctx, asset)

				p.publishEvent(models.EventSubdomainDiscovered, job.ID, target.ID, map[string]interface{}{
					"asset_id": asset.ID,
					"hostname": host,
					"source":   p.subProvider.Name(),
				})
				p.publishEvent(models.EventAssetCreated, job.ID, target.ID, map[string]interface{}{
					"asset_id":   asset.ID,
					"hostname":   host,
					"asset_type": asset.AssetType,
				})
			}
		}
	} else {
		// If subdomain discovery is disabled, use root domain as single seed
		if dedup.CheckAndAddHost(target.RootDomain) {
			discoveredHosts = append(discoveredHosts, target.RootDomain)
			progress.IncDiscovered()
			asset := &models.Asset{
				ID:        newID("ast"),
				TargetID:  target.ID,
				Hostname:  target.RootDomain,
				AssetType: "ROOT_DOMAIN",
				Status:    "DISCOVERED",
				FirstSeen: time.Now().UTC(),
				LastSeen:  time.Now().UTC(),
			}
			_ = p.reconRepo.SaveAsset(ctx, asset)
		}
	}

	if err := ctx.Err(); err != nil {
		return p.completeRun(ctx, run, progress, models.JobStatusCancelled)
	}

	// STAGE 2: Concurrent DNS Resolution
	resolvedHosts := make([]string, 0)
	var resolvedMu sync.Mutex

	if opts.DNSResolution && len(discoveredHosts) > 0 {
		dnsPool := NewWorkerPool[string](p.config.DNSWorkers, len(discoveredHosts), rateLimiter)
		dnsPool.Start(ctx, func(workerCtx context.Context, host string) {
			results, err := p.dnsResolver.Resolve(workerCtx, host)
			if err != nil {
				progress.IncErrors()
				return
			}

			hasLiveIP := false
			asset, _ := p.reconRepo.GetAssetByHostname(workerCtx, target.ID, host)
			assetID := ""
			if asset != nil {
				assetID = asset.ID
			}

			for _, rec := range results {
				if rec.Status == "NOERROR" && rec.Value != "" {
					hasLiveIP = true
					if dedup.CheckAndAddDNS(host, rec.RecordType, rec.Value) {
						dnsRec := &models.DNSRecord{
							ID:         newID("dns"),
							AssetID:    assetID,
							RecordType: rec.RecordType,
							Value:      rec.Value,
							FirstSeen:  time.Now().UTC(),
							LastSeen:   time.Now().UTC(),
						}
						_ = p.reconRepo.SaveDNSRecord(workerCtx, dnsRec)

						p.publishEvent(models.EventDNSResolved, job.ID, target.ID, map[string]interface{}{
							"asset_id":    assetID,
							"hostname":    host,
							"record_type": rec.RecordType,
							"value":       rec.Value,
						})
					}
				}
			}

			if hasLiveIP {
				progress.IncResolved()
				if assetID != "" {
					_ = p.reconRepo.UpdateAssetStatus(workerCtx, assetID, "RESOLVED")
				}
				resolvedMu.Lock()
				resolvedHosts = append(resolvedHosts, host)
				resolvedMu.Unlock()
			}
		})

		for _, h := range discoveredHosts {
			dnsPool.Submit(ctx, h)
		}
		dnsPool.Close()
	} else {
		resolvedHosts = discoveredHosts
	}

	if err := ctx.Err(); err != nil {
		return p.completeRun(ctx, run, progress, models.JobStatusCancelled)
	}

	// STAGE 3: Concurrent HTTP Probing
	type probeTarget struct {
		hostname string
		scheme   string
	}

	var liveProbeTargets []HTTPProbeResult
	var probeMu sync.Mutex

	if opts.HTTPProbe && len(resolvedHosts) > 0 {
		probesToRun := make([]probeTarget, 0, len(resolvedHosts)*2)
		for _, host := range resolvedHosts {
			probesToRun = append(probesToRun, probeTarget{hostname: host, scheme: "https"})
			probesToRun = append(probesToRun, probeTarget{hostname: host, scheme: "http"})
		}

		httpPool := NewWorkerPool[probeTarget](p.config.HTTPWorkers, len(probesToRun), rateLimiter)
		httpPool.Start(ctx, func(workerCtx context.Context, pt probeTarget) {
			rawURL := fmt.Sprintf("%s://%s", pt.scheme, pt.hostname)
			res, skip, err := p.httpProber.Probe(workerCtx, target, rawURL)
			if skip != nil {
				progress.IncSkipped()
				p.publishEvent(models.EventScopeSkipped, job.ID, target.ID, map[string]interface{}{
					"item":   skip.Item,
					"reason": skip.Reason,
					"stage":  skip.Stage,
				})
			}
			if err != nil {
				if err.Error() != ErrClassScopeRejected {
					progress.IncErrors()
				}
				return
			}
			if res != nil {
				if dedup.CheckAndAddHTTPService(res.URL) {
					progress.IncProbed()
					asset, _ := p.reconRepo.GetAssetByHostname(workerCtx, target.ID, res.Hostname)
					assetID := ""
					if asset != nil {
						assetID = asset.ID
						_ = p.reconRepo.UpdateAssetStatus(workerCtx, assetID, "LIVE")
					}

					svc := &models.HTTPService{
						ID:           newID("svc"),
						AssetID:      assetID,
						URL:          res.URL,
						StatusCode:   res.StatusCode,
						ContentType:  res.ContentType,
						ResponseTime: res.ResponseTime.Milliseconds(),
						FinalURL:     res.FinalURL,
						ServerHeader: res.ServerHeader,
						TLSVersion:   res.TLSVersion,
						FirstSeen:    time.Now().UTC(),
						LastSeen:     time.Now().UTC(),
					}
					_ = p.reconRepo.SaveHTTPService(workerCtx, svc)

					if p.intelAnalyzer != nil && assetID != "" {
						_ = p.intelAnalyzer.AnalyzeHTTPProbe(workerCtx, target.ID, assetID, res)
					}

					p.publishEvent(models.EventHTTPProbed, job.ID, target.ID, map[string]interface{}{
						"asset_id":      assetID,
						"hostname":      res.Hostname,
						"url":           res.URL,
						"status_code":   res.StatusCode,
						"response_time": res.ResponseTime.Milliseconds(),
						"server_header": res.ServerHeader,
						"tls_version":   res.TLSVersion,
					})

					probeMu.Lock()
					liveProbeTargets = append(liveProbeTargets, *res)
					probeMu.Unlock()
				}
			}
		})

		for _, pt := range probesToRun {
			httpPool.Submit(ctx, pt)
		}
		httpPool.Close()
	}

	if err := ctx.Err(); err != nil {
		return p.completeRun(ctx, run, progress, models.JobStatusCancelled)
	}

	// STAGE 4: Scoped Crawler
	if opts.Crawl && len(liveProbeTargets) > 0 {
		crawlPool := NewWorkerPool[HTTPProbeResult](p.config.CrawlerWorkers, len(liveProbeTargets), rateLimiter)
		crawlPool.Start(ctx, func(workerCtx context.Context, pt HTTPProbeResult) {
			asset, _ := p.reconRepo.GetAssetByHostname(workerCtx, target.ID, pt.Hostname)
			assetID := ""
			if asset != nil {
				assetID = asset.ID
			}

			err := p.crawler.CrawlSeed(
				workerCtx,
				target,
				assetID,
				pt.URL,
				dedup,
				func(cu CrawledURL) {
					progress.IncURLsDiscovered()
					uRec := &models.URLRecord{
						ID:        newID("url"),
						AssetID:   assetID,
						URL:       cu.URL,
						Source:    cu.Source,
						Depth:     cu.Depth,
						FirstSeen: time.Now().UTC(),
						LastSeen:  time.Now().UTC(),
					}
					_ = p.reconRepo.SaveURL(workerCtx, uRec)

					p.publishEvent(models.EventURLDiscovered, job.ID, target.ID, map[string]interface{}{
						"asset_id": assetID,
						"hostname": cu.Hostname,
						"url":      cu.URL,
						"source":   cu.Source,
						"depth":    cu.Depth,
					})
				},
				func(sk SkipEvent) {
					progress.IncSkipped()
					p.publishEvent(models.EventScopeSkipped, job.ID, target.ID, map[string]interface{}{
						"item":   sk.Item,
						"reason": sk.Reason,
						"stage":  sk.Stage,
					})
				},
			)
			if err != nil && workerCtx.Err() == nil {
				progress.IncErrors()
			} else {
				progress.IncURLsCrawled()
			}
		})

		for _, pt := range liveProbeTargets {
			crawlPool.Submit(ctx, pt)
		}
		crawlPool.Close()
	}

	if err := ctx.Err(); err != nil {
		return p.completeRun(ctx, run, progress, models.JobStatusCancelled)
	}

	return p.completeRun(ctx, run, progress, models.JobStatusCompleted)
}

func (p *Pipeline) completeRun(ctx context.Context, run *models.ReconRun, progress *AtomicProgress, status models.JobStatus) (*models.ReconRun, error) {
	now := time.Now().UTC()
	disc, res, prob, uDisc, uCrawl, errs, skip := progress.Snapshot()

	run.Status = status
	run.HostsDiscovered = disc
	run.HostsResolved = res
	run.HTTPProbed = prob
	run.URLsDiscovered = uDisc
	run.URLsCrawled = uCrawl
	run.Errors = errs
	run.SkippedOutOfScope = skip
	run.CompletedAt = &now

	_ = p.reconRepo.UpdateReconRun(ctx, run)

	eventKey := models.EventReconCompleted
	if status == models.JobStatusCancelled || status == models.JobStatusFailed {
		eventKey = models.EventReconFailed
	}

	p.publishEvent(eventKey, run.JobID, run.TargetID, map[string]interface{}{
		"run_id":               run.ID,
		"status":               status,
		"hosts_discovered":     disc,
		"hosts_resolved":       res,
		"http_probed":          prob,
		"urls_discovered":      uDisc,
		"urls_crawled":         uCrawl,
		"errors":               errs,
		"skipped_out_of_scope": skip,
	})

	return run, nil
}

func (p *Pipeline) publishEvent(eventType, jobID, targetID string, payload map[string]interface{}) {
	_ = p.eventBus.Publish(context.Background(), models.Event{
		EventID:   newID("evt"),
		EventType: eventType,
		JobID:     jobID,
		TargetID:  targetID,
		Timestamp: time.Now().UTC(),
		Payload:   payload,
	})
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}
