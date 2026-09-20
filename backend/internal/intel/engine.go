package intel

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/recon"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/storage"
)

// Engine coordinates passive technology fingerprinting, service intelligence, security observations, and change detection.
type Engine struct {
	repo      storage.AssetIntelligenceRepository
	eventBus  events.EventBus
	rules     []*FingerprintRule
	secEngine *SecurityIntelligenceEngine
}

// NewEngine instantiates a thread-safe asset intelligence engine with declarative fingerprint rules.
func NewEngine(repo storage.AssetIntelligenceRepository, eb events.EventBus) *Engine {
	return &Engine{
		repo:     repo,
		eventBus: eb,
		rules:    DefaultRules(),
	}
}

// SetSecurityIntelligenceEngine binds the security intelligence engine for real-time graph, invariant, and cluster synthesis.
func (e *Engine) SetSecurityIntelligenceEngine(se *SecurityIntelligenceEngine) {
	e.secEngine = se
}

// AnalyzeHTTPProbe executes complete passive intelligence extraction on a safe HTTP probe result.
func (e *Engine) AnalyzeHTTPProbe(ctx context.Context, targetID, assetID string, probe *recon.HTTPProbeResult) error {
	if probe == nil {
		return nil
	}

	u, err := url.Parse(probe.URL)
	scheme := "http"
	port := 80
	if err == nil {
		scheme = u.Scheme
		if u.Port() != "" {
			fmt.Sscanf(u.Port(), "%d", &port)
		} else if scheme == "https" {
			port = 443
		}
	}

	serviceIdent := fmt.Sprintf("%s://%s:%d", scheme, probe.Hostname, port)

	// 1. Extract HTML Metadata
	htmlMeta := ExtractHTMLMetadata(probe.RawBody)
	pageTitle := htmlMeta.Title
	if pageTitle == "" && probe.BodySnippet != "" {
		// Fallback extraction
		snipMeta := ExtractHTMLMetadata(probe.BodySnippet)
		pageTitle = snipMeta.Title
	}

	// 2. Fetch existing service observations to detect changes
	prevList, _, _ := e.repo.ListServiceObservations(ctx, models.ServiceFilter{
		TargetID: targetID,
		AssetID:  assetID,
		Limit:    10,
	})
	var prevSvc *models.ServiceObservation
	for _, s := range prevList {
		if s.ServiceIdentity == serviceIdent {
			prevSvc = s
			break
		}
	}

	serviceObs := &models.ServiceObservation{
		ID:              newID("svc"),
		AssetID:         assetID,
		TargetID:        targetID,
		ServiceIdentity: serviceIdent,
		Scheme:          scheme,
		Port:            port,
		StatusCode:      probe.StatusCode,
		PageTitle:       pageTitle,
		WebServer:       probe.ServerHeader,
		ContentType:     probe.ContentType,
		ContentLength:   probe.ContentLength,
		ResponseTimeMS:  probe.ResponseTime.Milliseconds(),
		TLSVersion:      probe.TLSVersion,
		Headers:         probe.Headers,
		FirstSeen:       time.Now().UTC(),
		LastSeen:        time.Now().UTC(),
	}

	// Save Service Observation
	if err := e.repo.SaveServiceObservation(ctx, serviceObs); err != nil {
		return fmt.Errorf("failed to save service observation: %w", err)
	}

	// Change Detection on Service
	if change := DetectServiceChanges(targetID, assetID, prevSvc, serviceObs); change != nil {
		_ = e.repo.RecordAssetChange(ctx, change)
		if e.eventBus != nil {
			_ = e.eventBus.Publish(ctx, models.Event{
				EventType: models.EventAssetChangeDetected,
				TargetID:  targetID,
				Payload: map[string]interface{}{
					"change": change,
				},
			})
		}
	}

	// 3. Technology Fingerprinting Matcher
	matchedTechs := e.matchTechnologies(probe, htmlMeta)

	// Fetch existing technologies for change detection
	existingTechs, _, _ := e.repo.ListTechnologyObservations(ctx, models.TechnologyFilter{
		TargetID: targetID,
		AssetID:  assetID,
		Limit:    100,
	})
	existingMap := make(map[string]bool)
	for _, et := range existingTechs {
		existingMap[et.TechnologyName] = true
	}

	for _, tech := range matchedTechs {
		tech.AssetID = assetID
		tech.TargetID = targetID
		tech.ServiceID = serviceObs.ID

		isNew := !existingMap[tech.TechnologyName]
		if err := e.repo.SaveTechnologyObservation(ctx, tech); err == nil {
			if isNew {
				existingMap[tech.TechnologyName] = true
				if change := DetectTechnologyChange(targetID, assetID, tech, true); change != nil {
					_ = e.repo.RecordAssetChange(ctx, change)
					if e.eventBus != nil {
						_ = e.eventBus.Publish(ctx, models.Event{
							EventType: models.EventAssetChangeDetected,
							TargetID:  targetID,
							Payload: map[string]interface{}{
								"change": change,
							},
						})
					}
				}
				if e.eventBus != nil {
					_ = e.eventBus.Publish(ctx, models.Event{
						EventType: models.EventTechnologyDetected,
						TargetID:  targetID,
						Payload: map[string]interface{}{
							"technology": tech,
						},
					})
				}
			}
		}
	}

	// 4. Passive Security Observations (HSTS, CSP, X-Frame-Options, etc.)
	secObsList := EvaluateSecurityObservations(assetID, targetID, serviceObs.ID, scheme, probe.Headers, probe.Cookies)
	for _, so := range secObsList {
		_ = e.repo.SaveSecurityObservation(ctx, so)
	}

	// 5. JavaScript & Page Assets
	pageAssets := ClassifyAndExtractPageAssets(assetID, targetID, probe.URL, htmlMeta)
	for _, pa := range pageAssets {
		_ = e.repo.SavePageAsset(ctx, pa)
	}

	// 6. Infer Asset Tags
	inferredTags := InferAssetTags(assetID, targetID, probe.Hostname, []int{port})
	for _, tag := range inferredTags {
		_ = e.repo.AddAssetTag(ctx, tag)
	}

	// 7. Publish Asset Updated Event
	if e.eventBus != nil {
		_ = e.eventBus.Publish(ctx, models.Event{
			EventType: models.EventAssetUpdated,
			TargetID:  targetID,
			Payload: map[string]interface{}{
				"asset_id":     assetID,
				"target_id":    targetID,
				"technologies": len(matchedTechs),
				"service":      serviceIdent,
			},
		})
	}

	// 8. Ingest into Security Intelligence Engine (Graph, Temporal, Invariants, Clusters)
	if e.secEngine != nil {
		_ = e.secEngine.IngestProbeResult(ctx, targetID, assetID, probe.Hostname, probe, nil, matchedTechs)
	}

	return nil
}

// matchTechnologies evaluates all loaded declarative rules against the probed HTTP response.
func (e *Engine) matchTechnologies(probe *recon.HTTPProbeResult, htmlMeta ExtractedPageMeta) []*models.TechnologyObservation {
	var results []*models.TechnologyObservation
	now := time.Now().UTC()

	// Track matches per technology name to allow cross-evidence corroboration
	type techMatchData struct {
		rule         *FingerprintRule
		version      *string
		matchValue   string
		detectionSrc string
		matchCount   int
	}
	techMap := make(map[string]*techMatchData)

	for _, rule := range e.rules {
		matched := false
		var matchVal string
		var extractedVer *string
		detectionSrc := ""

		switch rule.MatchTarget {
		case MatchHeader:
			detectionSrc = "response_header"
			if val, ok := FindHeaderCaseInsensitive(probe.Headers, rule.HeaderKey); ok {
				if rule.compiledRegex != nil && rule.compiledRegex.MatchString(val) {
					matched = true
					matchVal = fmt.Sprintf("%s: %s", rule.HeaderKey, val)
					if rule.compiledVersionRegex != nil {
						if sub := rule.compiledVersionRegex.FindStringSubmatch(val); len(sub) > 1 && sub[1] != "" {
							v := sub[1]
							extractedVer = &v
						}
					}
				}
			}

		case MatchCookie:
			detectionSrc = "cookie"
			for _, c := range probe.Cookies {
				if rule.compiledRegex != nil && rule.compiledRegex.MatchString(c) {
					matched = true
					matchVal = c
					break
				}
			}

		case MatchHTMLMeta:
			detectionSrc = "html_meta"
			if val, ok := htmlMeta.MetaTags[strings.ToLower(rule.MetaName)]; ok {
				if rule.compiledRegex != nil && rule.compiledRegex.MatchString(val) {
					matched = true
					matchVal = fmt.Sprintf("<meta name=\"%s\" content=\"%s\">", rule.MetaName, val)
					if rule.compiledVersionRegex != nil {
						if sub := rule.compiledVersionRegex.FindStringSubmatch(val); len(sub) > 1 && sub[1] != "" {
							v := sub[1]
							extractedVer = &v
						}
					}
				}
			}

		case MatchHTMLBody:
			detectionSrc = "html_body"
			bodyToScan := probe.RawBody
			if bodyToScan == "" {
				bodyToScan = probe.BodySnippet
			}
			if rule.compiledRegex != nil && rule.compiledRegex.MatchString(bodyToScan) {
				matched = true
				matchVal = rule.Pattern
				if rule.compiledVersionRegex != nil {
					if sub := rule.compiledVersionRegex.FindStringSubmatch(bodyToScan); len(sub) > 1 && sub[1] != "" {
						v := sub[1]
						extractedVer = &v
					}
				}
			}

		case MatchScriptSrc:
			detectionSrc = "script_src"
			for _, src := range htmlMeta.ScriptSources {
				if rule.compiledRegex != nil && rule.compiledRegex.MatchString(src) {
					matched = true
					matchVal = src
					if rule.compiledVersionRegex != nil {
						if sub := rule.compiledVersionRegex.FindStringSubmatch(src); len(sub) > 1 && sub[1] != "" {
							v := sub[1]
							extractedVer = &v
						}
					}
					break
				}
			}
		}

		if matched {
			if existing, found := techMap[rule.TechnologyName]; found {
				existing.matchCount++
				if extractedVer != nil && existing.version == nil {
					existing.version = extractedVer
				}
			} else {
				techMap[rule.TechnologyName] = &techMatchData{
					rule:         rule,
					version:      extractedVer,
					matchValue:   matchVal,
					detectionSrc: detectionSrc,
					matchCount:   1,
				}
			}
		}
	}

	for _, data := range techMap {
		conf, evidence := CalculateConfidence(data.rule, data.matchValue, data.version, data.matchCount)
		results = append(results, &models.TechnologyObservation{
			ID:              newID("tech"),
			TechnologyName:  data.rule.TechnologyName,
			Category:        data.rule.Category,
			Version:         data.version,
			Confidence:      conf,
			DetectionSource: data.detectionSrc,
			Evidence:        evidence,
			FirstSeen:       now,
			LastSeen:        now,
		})
	}

	return results
}
