package recon

import (
	"sync"
	"time"
)

// Error classifications mandated by Phase 2 requirements.
const (
	ErrClassDNSError      = "DNS_ERROR"
	ErrClassHTTPTimeout   = "HTTP_TIMEOUT"
	ErrClassHTTPError     = "HTTP_ERROR"
	ErrClassCrawlError    = "CRAWL_ERROR"
	ErrClassScopeRejected = "SCOPE_REJECTED"
	ErrClassRateLimited   = "RATE_LIMITED"
	ErrClassInvalidURL    = "INVALID_URL"
	ErrClassInternalError = "INTERNAL_ERROR"
)

// ReconOptions configures which stages of the reconnaissance pipeline to execute.
type ReconOptions struct {
	SubdomainDiscovery bool `json:"subdomain_discovery"`
	DNSResolution      bool `json:"dns_resolution"`
	HTTPProbe          bool `json:"http_probe"`
	Crawl              bool `json:"crawl"`
}

// DefaultOptions returns conservative, authorized defaults for a recon job.
func DefaultOptions() ReconOptions {
	return ReconOptions{
		SubdomainDiscovery: true,
		DNSResolution:      true,
		HTTPProbe:          true,
		Crawl:              true,
	}
}

// ReconError records classified execution failures without crashing the scan.
type ReconError struct {
	Class     string    `json:"class"`
	Hostname  string    `json:"hostname,omitempty"`
	URL       string    `json:"url,omitempty"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// DiscoveredHost captures a normalized hostname candidate.
type DiscoveredHost struct {
	Hostname  string    `json:"hostname"`
	Source    string    `json:"source"`
	Timestamp time.Time `json:"timestamp"`
}

// DNSResult captures an individual record discovery.
type DNSResult struct {
	Hostname   string    `json:"hostname"`
	RecordType string    `json:"record_type"` // A, AAAA, CNAME
	Value      string    `json:"value"`
	Status     string    `json:"status"` // NOERROR, NXDOMAIN, TIMEOUT, ERROR
	Timestamp  time.Time `json:"timestamp"`
}

// HTTPProbeResult captures metadata from safe HTTP/HTTPS probing.
type HTTPProbeResult struct {
	Hostname        string            `json:"hostname"`
	URL             string            `json:"url"`
	StatusCode      int               `json:"status_code"`
	FinalURL        string            `json:"final_url,omitempty"`
	ResponseTime    time.Duration     `json:"response_time"`
	ContentType     string            `json:"content_type,omitempty"`
	ContentLength   int64             `json:"content_length"`
	ServerHeader    string            `json:"server_header,omitempty"`
	TLSVersion      string            `json:"tls_version,omitempty"`
	RedirectHistory []string          `json:"redirect_history,omitempty"`
	BodySnippet     string            `json:"body_snippet,omitempty"`
	RawBody         string            `json:"raw_body,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	Cookies         []string          `json:"cookies,omitempty"`
	Timestamp       time.Time         `json:"timestamp"`
}

// CrawledURL captures a discovered link.
type CrawledURL struct {
	AssetID   string    `json:"asset_id"`
	Hostname  string    `json:"hostname"`
	URL       string    `json:"url"`
	Source    string    `json:"source"`
	Depth     int       `json:"depth"`
	Timestamp time.Time `json:"timestamp"`
}

// SkipEvent details an item that was skipped due to fail-closed scope rules.
type SkipEvent struct {
	Item      string    `json:"item"`
	TargetID  string    `json:"target_id"`
	Reason    string    `json:"reason"`
	Stage     string    `json:"stage"` // "SUBDOMAIN", "DNS", "HTTP", "CRAWLER", "REDIRECT"
	Timestamp time.Time `json:"timestamp"`
}

// AtomicProgress tracks scan metrics safely across concurrent workers.
type AtomicProgress struct {
	mu                sync.RWMutex
	HostsDiscovered   int
	HostsResolved     int
	HTTPProbed        int
	URLsDiscovered    int
	URLsCrawled       int
	Errors            int
	SkippedOutOfScope int
}

// IncDiscovered increments discovered hosts counter.
func (p *AtomicProgress) IncDiscovered() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.HostsDiscovered++
}

// IncResolved increments resolved hosts counter.
func (p *AtomicProgress) IncResolved() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.HostsResolved++
}

// IncProbed increments HTTP probed counter.
func (p *AtomicProgress) IncProbed() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.HTTPProbed++
}

// IncURLsDiscovered increments URLs discovered counter.
func (p *AtomicProgress) IncURLsDiscovered() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.URLsDiscovered++
}

// IncURLsCrawled increments URLs crawled counter.
func (p *AtomicProgress) IncURLsCrawled() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.URLsCrawled++
}

// IncErrors increments error counter.
func (p *AtomicProgress) IncErrors() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Errors++
}

// IncSkipped increments out-of-scope skipped counter.
func (p *AtomicProgress) IncSkipped() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.SkippedOutOfScope++
}

// Snapshot returns a snapshot copy of current counters.
func (p *AtomicProgress) Snapshot() (discovered, resolved, probed, urlsDisc, urlsCrawl, errs, skipped int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.HostsDiscovered, p.HostsResolved, p.HTTPProbed, p.URLsDiscovered, p.URLsCrawled, p.Errors, p.SkippedOutOfScope
}
