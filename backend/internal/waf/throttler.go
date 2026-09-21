package waf

import (
	"sync"
	"time"
)

// AdaptiveThrottler dynamically modulates request rates and implements circuit breaker protections.
type AdaptiveThrottler struct {
	mu                 sync.RWMutex
	assetID            string
	currentRPS         float64
	minRPS             float64
	maxRPS             float64
	state              string // "NORMAL", "RATE_LIMITED", "REPEATED_429", "SUSTAINED_BLOCK", "PAUSED"
	consecutive429s    int
	consecutiveBlocks  int
	consecutiveSuccess int
	retryUntil         time.Time
	circuitBreakerOpen bool
	lastReason         string
}

// NewAdaptiveThrottler creates an initialized throttler with 10.0 initial RPS.
func NewAdaptiveThrottler(assetID string) *AdaptiveThrottler {
	return &AdaptiveThrottler{
		assetID:            assetID,
		currentRPS:         10.0,
		minRPS:             0.5,
		maxRPS:             20.0,
		state:              "NORMAL",
		circuitBreakerOpen: false,
	}
}

// Record429 updates state upon observing rate limit response.
func (t *AdaptiveThrottler) Record429(retryAfterSecs int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.consecutive429s++
	t.consecutiveSuccess = 0

	// Cut RPS by half, down to minRPS
	t.currentRPS = t.currentRPS * 0.5
	if t.currentRPS < t.minRPS {
		t.currentRPS = t.minRPS
	}

	if retryAfterSecs > 0 {
		t.retryUntil = time.Now().Add(time.Duration(retryAfterSecs) * time.Second)
	} else {
		// Backoff delay
		delaySec := t.consecutive429s * 2
		t.retryUntil = time.Now().Add(time.Duration(delaySec) * time.Second)
	}

	if t.consecutive429s >= 3 {
		t.state = "REPEATED_429"
		t.circuitBreakerOpen = true
		t.lastReason = "repeated 429 Too Many Requests observed; circuit breaker tripped"
	} else {
		t.state = "RATE_LIMITED"
		t.lastReason = "HTTP 429 observed; reducing rate"
	}
}

// RecordBlock updates state upon observing active WAF block or challenge.
func (t *AdaptiveThrottler) RecordBlock(provider string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.consecutiveBlocks++
	t.consecutiveSuccess = 0
	t.currentRPS = t.minRPS

	if t.consecutiveBlocks >= 2 {
		t.state = "SUSTAINED_BLOCK"
		t.circuitBreakerOpen = true
		t.lastReason = "sustained WAF challenge/block detected; halting scans against asset to prevent IP bans"
	} else {
		t.state = "WAF_THROTTLED"
		t.lastReason = "WAF block observed; throttling requests"
	}
}

// RecordSuccess gradually recovers transmission speed after stable requests.
func (t *AdaptiveThrottler) RecordSuccess() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.consecutiveSuccess++
	if t.consecutiveSuccess >= 10 {
		t.consecutive429s = 0
		t.consecutiveBlocks = 0
		t.circuitBreakerOpen = false
		t.state = "NORMAL"

		// Gradually step up RPS
		if t.currentRPS < t.maxRPS {
			t.currentRPS += 1.0
			if t.currentRPS > t.maxRPS {
				t.currentRPS = t.maxRPS
			}
		}
	}
}

// CanExecute checks if the circuit breaker or retry delay allows execution.
func (t *AdaptiveThrottler) CanExecute() (bool, string) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.circuitBreakerOpen {
		return false, t.lastReason
	}
	if time.Now().Before(t.retryUntil) {
		return false, "Retry-After backoff period is currently active"
	}
	return true, ""
}

// GetStatus returns the current status metrics.
func (t *AdaptiveThrottler) GetStatus() (state string, rps float64, circuitBreakerOpen bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.state, t.currentRPS, t.circuitBreakerOpen
}
