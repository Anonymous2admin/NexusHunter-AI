package waf

import (
	"context"
	"net/http"
	"testing"
)

func TestWAF_DetectionAndThrottling(t *testing.T) {
	detector := NewDetector()

	// 1. Cloudflare header detection
	cfResp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Cf-Ray":          []string{"8899aabbccddeeff-IAD"},
			"Server":          []string{"cloudflare"},
			"Cf-Cache-Status": []string{"DYNAMIC"},
		},
	}

	obs := detector.InspectResponse(context.Background(), "tgt-1", "asset-1", cfResp, "")
	if obs.Provider != "Cloudflare" {
		t.Errorf("expected provider Cloudflare, got %s", obs.Provider)
	}
	if obs.Confidence != "HIGH" {
		t.Errorf("expected HIGH confidence, got %s", obs.Confidence)
	}

	// 2. HTTP 429 rate limit reaction
	throttledResp := &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header: http.Header{
			"Retry-After": []string{"5"},
		},
	}

	obs2 := detector.InspectResponse(context.Background(), "tgt-1", "asset-1", throttledResp, "Too Many Requests")
	if obs2.ThrottlingState != "RATE_LIMITED" {
		t.Errorf("expected RATE_LIMITED state, got %s", obs2.ThrottlingState)
	}
	if obs2.RetryAfterSeconds != 5 {
		t.Errorf("expected Retry-After 5 seconds, got %d", obs2.RetryAfterSeconds)
	}

	// 3. Repeated 429s trip circuit breaker
	detector.InspectResponse(context.Background(), "tgt-1", "asset-1", throttledResp, "")
	obs4 := detector.InspectResponse(context.Background(), "tgt-1", "asset-1", throttledResp, "")
	if !obs4.CircuitBreakerOpen {
		t.Errorf("expected circuit breaker to trip after 3 consecutive 429s")
	}
}
