package waf

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// WAFSignatures contains deterministic passive identification patterns.
type WAFSignature struct {
	Provider string
	Headers  map[string]string // header key -> substring or regex
	BodyPhrases []string
}

var knownSignatures = []WAFSignature{
	{
		Provider: "Cloudflare",
		Headers: map[string]string{
			"cf-ray":            "",
			"cf-cache-status":   "",
			"server":            "cloudflare",
		},
		BodyPhrases: []string{
			"Attention Required! | Cloudflare",
			"Cloudflare Ray ID",
			"cf-browser-verification",
		},
	},
	{
		Provider: "AWS WAF",
		Headers: map[string]string{
			"x-amzn-requestid": "",
			"x-amz-cf-id":      "",
			"x-amz-waf-action": "",
		},
		BodyPhrases: []string{
			"403 Forbidden: AWS WAF",
			"Request blocked by AWS WAF",
		},
	},
	{
		Provider: "Akamai",
		Headers: map[string]string{
			"x-akamai-transformed": "",
			"akamai-origin-hop":    "",
			"server":               "AkamaiGHost",
		},
		BodyPhrases: []string{
			"Access Denied: Akamai",
			"Reference&#32;&#35;",
		},
	},
	{
		Provider: "Fastly",
		Headers: map[string]string{
			"x-fastly-request-id": "",
			"fastly-restarts":     "",
		},
		BodyPhrases: []string{
			"Fastly error: unknown domain",
		},
	},
	{
		Provider: "Imperva",
		Headers: map[string]string{
			"x-iinfo": "",
			"x-cdn":   "incapsula",
		},
		BodyPhrases: []string{
			"Incapsula incident ID",
			"Powered by Imperva",
		},
	},
}

// Detector inspects HTTP traffic for WAF indicators and controls adaptive throttling.
type Detector interface {
	InspectResponse(ctx context.Context, targetID, assetID string, resp *http.Response, bodySnippet string) *models.WAFObservation
	GetAdaptiveThrottler(assetID string) *AdaptiveThrottler
}

type wafDetector struct {
	mu         sync.RWMutex
	throttlers map[string]*AdaptiveThrottler
}

// NewDetector creates an initialized WAF detector.
func NewDetector() Detector {
	return &wafDetector{
		throttlers: make(map[string]*AdaptiveThrottler),
	}
}

// GetAdaptiveThrottler returns or creates an adaptive rate limiter for the specified asset.
func (d *wafDetector) GetAdaptiveThrottler(assetID string) *AdaptiveThrottler {
	d.mu.Lock()
	defer d.mu.Unlock()

	if t, exists := d.throttlers[assetID]; exists {
		return t
	}
	t := NewAdaptiveThrottler(assetID)
	d.throttlers[assetID] = t
	return t
}

// InspectResponse evaluates HTTP response headers and body snippets to classify WAF presence.
func (d *wafDetector) InspectResponse(ctx context.Context, targetID, assetID string, resp *http.Response, bodySnippet string) *models.WAFObservation {
	matchedIndicators := make([]string, 0)
	observedHeaders := make([]string, 0)
	detectedProvider := "None Detected"
	confidence := "LOW"

	if resp == nil {
		return &models.WAFObservation{
			ID:                  fmt.Sprintf("waf-%s", assetID),
			TargetID:            targetID,
			AssetID:             assetID,
			Provider:            "None Detected",
			Confidence:          "LOW",
			ThrottlingState:     "NORMAL",
			CurrentRateLimitRPS: 10.0,
			CreatedAt:           time.Now().UTC(),
			UpdatedAt:           time.Now().UTC(),
		}
	}

	// 1. Signature checks
	for _, sig := range knownSignatures {
		providerMatches := 0

		for hdrKey, hdrValMatch := range sig.Headers {
			val := resp.Header.Get(hdrKey)
			if val != "" {
				observedHeaders = append(observedHeaders, fmt.Sprintf("%s: %s", hdrKey, val))
				if hdrValMatch == "" || strings.Contains(strings.ToLower(val), strings.ToLower(hdrValMatch)) {
					providerMatches++
					matchedIndicators = append(matchedIndicators, fmt.Sprintf("Header '%s' matches %s", hdrKey, sig.Provider))
				}
			}
		}

		for _, phrase := range sig.BodyPhrases {
			if strings.Contains(bodySnippet, phrase) {
				providerMatches += 2
				matchedIndicators = append(matchedIndicators, fmt.Sprintf("Body phrase '%s' detected", phrase))
			}
		}

		if providerMatches >= 2 {
			detectedProvider = sig.Provider
			confidence = "HIGH"
			break
		} else if providerMatches == 1 && detectedProvider == "None Detected" {
			detectedProvider = sig.Provider
			confidence = "MEDIUM"
		}
	}

	// 2. Status code & Throttling evaluation
	throttler := d.GetAdaptiveThrottler(assetID)
	retryAfter := 0

	if resp.StatusCode == http.StatusTooManyRequests {
		if rawRetry := resp.Header.Get("Retry-After"); rawRetry != "" {
			if secs, err := strconv.Atoi(rawRetry); err == nil {
				retryAfter = secs
			}
		}
		throttler.Record429(retryAfter)
		matchedIndicators = append(matchedIndicators, "HTTP 429 Too Many Requests observed")
	} else if resp.StatusCode == http.StatusForbidden && detectedProvider != "None Detected" {
		throttler.RecordBlock(detectedProvider)
		matchedIndicators = append(matchedIndicators, fmt.Sprintf("WAF challenge or 403 block by %s", detectedProvider))
	} else if resp.StatusCode == http.StatusOK {

		throttler.RecordSuccess()
	}

	state, rps, open := throttler.GetStatus()
	obs := &models.WAFObservation{
		ID:                  fmt.Sprintf("waf-%x", sha256.Sum256([]byte(targetID+assetID+detectedProvider)))[:16],
		TargetID:            targetID,
		AssetID:             assetID,
		Provider:            detectedProvider,
		Confidence:          confidence,
		MatchedIndicators:   matchedIndicators,
		ObservedHeaders:     observedHeaders,
		ThrottlingState:     state,
		CurrentRateLimitRPS: rps,
		RetryAfterSeconds:   retryAfter,
		CircuitBreakerOpen:  open,
		CreatedAt:           time.Now().UTC(),
		UpdatedAt:           time.Now().UTC(),
	}

	return obs
}
