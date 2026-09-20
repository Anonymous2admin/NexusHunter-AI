package recon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/events"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/storage"
)

// MockDNSResolver returns deterministic DNS answers for testing.
type MockDNSResolver struct {
	mu      sync.Mutex
	records map[string][]DNSResult
	delays  map[string]time.Duration
}

func NewMockDNSResolver() *MockDNSResolver {
	return &MockDNSResolver{
		records: make(map[string][]DNSResult),
		delays:  make(map[string]time.Duration),
	}
}

func (m *MockDNSResolver) Set(host string, results []DNSResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records[host] = results
}

func (m *MockDNSResolver) Resolve(ctx context.Context, hostname string) ([]DNSResult, error) {
	m.mu.Lock()
	delay := m.delays[hostname]
	results, exists := m.records[hostname]
	m.mu.Unlock()

	if delay > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
	}

	if !exists {
		return []DNSResult{
			{
				Hostname:   hostname,
				RecordType: "A",
				Status:     "NXDOMAIN",
				Timestamp:  time.Now().UTC(),
			},
		}, nil
	}

	return results, nil
}

// 1. Normalization Tests
func TestNormalizeHostname(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		shouldError bool
	}{
		{"EXAMPLE.COM", "example.com", false},
		{"  api.sub.example.com.  ", "api.sub.example.com", false},
		{"https://app.target.com/path", "app.target.com", false},
		{"host.example.com:8443", "host.example.com", false},
		{"192.168.1.1", "192.168.1.1", false},
		{"", "", true},
		{"invalid..host", "", true},
		{"-bad-host.com", "", true},
	}

	for _, tc := range tests {
		got, err := NormalizeHostname(tc.input)
		if tc.shouldError && err == nil {
			t.Errorf("expected error for '%s', got '%s'", tc.input, got)
		}
		if !tc.shouldError && (err != nil || got != tc.expected) {
			t.Errorf("for input '%s', expected '%s', got '%s' (err: %v)", tc.input, tc.expected, got, err)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		shouldError bool
	}{
		{"HTTPS://Example.COM:443/api/v1//users?b=2&a=1#section", "https://example.com/api/v1/users?a=1&b=2", false},
		{"http://example.com:80/path/./test/../final/", "http://example.com/path/final/", false},
		{"https://target.com", "https://target.com/", false},
		{"", "", true},
		{"ftp://example.com", "", true},
	}

	for _, tc := range tests {
		got, err := NormalizeURL(tc.input)
		if tc.shouldError && err == nil {
			t.Errorf("expected error for URL '%s', got '%s'", tc.input, got)
		}
		if !tc.shouldError && (err != nil || got != tc.expected) {
			t.Errorf("for input '%s', expected '%s', got '%s' (err: %v)", tc.input, tc.expected, got, err)
		}
	}
}

// 2. Deduplicator Tests
func TestDeduplicator(t *testing.T) {
	dedup := NewDeduplicator()

	if !dedup.CheckAndAddHost("example.com") {
		t.Errorf("expected first host check to return true")
	}
	if dedup.CheckAndAddHost("example.com") {
		t.Errorf("expected duplicate host check to return false")
	}

	if !dedup.CheckAndAddURL("https://example.com/login") {
		t.Errorf("expected first URL check to return true")
	}
	if dedup.CheckAndAddURL("https://example.com/login") {
		t.Errorf("expected duplicate URL check to return false")
	}

	if !dedup.CheckAndAddDNS("api.example.com", "A", "93.184.216.34") {
		t.Errorf("expected first DNS check to return true")
	}
	if dedup.CheckAndAddDNS("api.example.com", "A", "93.184.216.34") {
		t.Errorf("expected duplicate DNS check to return false")
	}

	hosts, urls, dns, _ := dedup.Count()
	if hosts != 1 || urls != 1 || dns != 1 {
		t.Errorf("unexpected counts: hosts=%d, urls=%d, dns=%d", hosts, urls, dns)
	}
}

// 3. Baseline Subdomain Discovery Provider Tests
func TestBaselineProvider_ScopeEnforcement(t *testing.T) {
	scopeValidator := scope.NewValidator()
	provider := NewBaselineProvider(scopeValidator)

	target := &models.Target{
		ID:             "tgt-test-1",
		RootDomain:     "target.com",
		AllowedDomains: []string{"target.com", "*.target.com"},
		ExcludedPatterns: []string{"admin.target.com"},
		Status:         models.TargetStatusActive,
	}

	results, err := provider.Discover(context.Background(), target)
	if err != nil {
		t.Fatalf("unexpected discovery error: %v", err)
	}

	if len(results) == 0 {
		t.Fatalf("expected discovered hostnames, got empty")
	}

	// Verify excluded host was dropped
	for _, h := range results {
		if h == "admin.target.com" {
			t.Fatalf("excluded host 'admin.target.com' was NOT dropped from discovery results!")
		}
		// Every result must strictly evaluate to in-scope
		dec := scopeValidator.Evaluate(target, h, "")
		if !dec.InScope {
			t.Fatalf("out of scope host '%s' slipped through discovery: %s", h, dec.Reason)
		}
	}
}

// 4. HTTP Prober Tests with Redirects and Scope Boundaries
func TestHTTPProber_RedirectEnforcement(t *testing.T) {
	scopeValidator := scope.NewValidator()
	cfg := DefaultEngineConfig()
	cfg.AllowLocalAddresses = true

	// Setup mock server
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/safe-redir":
			http.Redirect(w, r, ts.URL+"/final-page", http.StatusFound)
		case "/out-of-scope-redir":
			http.Redirect(w, r, "https://malicious-external-site.com/steal", http.StatusFound)
		case "/final-page":
			w.Header().Set("Server", "NexusMock/1.0")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>Welcome</body></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	tsHost, err := ExtractHostnameFromURL(ts.URL)
	if err != nil {
		t.Fatalf("failed to extract test server hostname: %v", err)
	}

	prober := NewStandardHTTPProber(cfg, scopeValidator)

	target := &models.Target{
		ID:             "tgt-http-test",
		RootDomain:     tsHost,
		AllowedDomains: []string{tsHost},
		Status:         models.TargetStatusActive,
	}

	// Case 1: In-scope redirect succeeds
	res, skip, err := prober.Probe(context.Background(), target, ts.URL+"/safe-redir")
	if err != nil {
		t.Fatalf("expected successful in-scope redirect probe, got: %v", err)
	}
	if skip != nil {
		t.Fatalf("expected no skip event for in-scope redirect, got: %+v", skip)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", res.StatusCode)
	}
	if res.ServerHeader != "NexusMock/1.0" {
		t.Errorf("expected server header 'NexusMock/1.0', got '%s'", res.ServerHeader)
	}

	// Case 2: Out-of-scope redirect is BLOCKED and recorded
	res, skip, err = prober.Probe(context.Background(), target, ts.URL+"/out-of-scope-redir")
	if err == nil || err.Error() != ErrClassScopeRejected {
		t.Errorf("expected scope rejection for external redirect, got: %v", err)
	}
	if skip == nil {
		t.Fatalf("expected skip event for out-of-scope redirect, got nil")
	}
	if !strings.Contains(skip.Item, "malicious-external-site.com") {
		t.Errorf("unexpected skip item: %s", skip.Item)
	}
}

// 5. Crawler Tests
func TestCrawler_RobotsAndSitemapExtraction(t *testing.T) {
	scopeValidator := scope.NewValidator()
	cfg := DefaultEngineConfig()
	cfg.AllowLocalAddresses = true
	cfg.MaxDepth = 2
	cfg.MaxURLsPerHost = 50

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin-secret\nAllow: /public-api\nSitemap: " + ts.URL + "/sitemap.xml\n"))
		case "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>` + ts.URL + `/from-sitemap</loc></url>
</urlset>`))
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>
<a href="/internal-link-1">Link 1</a>
<a href="https://external-domain.com/leak">External Link</a>
<form action="/form-endpoint" method="post"></form>
</body></html>`))
		case "/internal-link-1":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><a href="/nested-link-2">Nested</a></body></html>`))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("OK"))
		}
	}))
	defer ts.Close()

	tsHost, _ := ExtractHostnameFromURL(ts.URL)
	target := &models.Target{
		ID:             "tgt-crawl-test",
		RootDomain:     tsHost,
		AllowedDomains: []string{tsHost},
		Status:         models.TargetStatusActive,
	}

	crawler := NewCrawler(cfg, scopeValidator)
	dedup := NewDeduplicator()

	var discoveredURLs []CrawledURL
	var skipEvents []SkipEvent

	err := crawler.CrawlSeed(
		context.Background(),
		target,
		"asset-123",
		ts.URL+"/",
		dedup,
		func(cu CrawledURL) {
			discoveredURLs = append(discoveredURLs, cu)
		},
		func(sk SkipEvent) {
			skipEvents = append(skipEvents, sk)
		},
	)
	if err != nil {
		t.Fatalf("unexpected crawl error: %v", err)
	}

	// Verify crawled URLs
	foundRobots := false
	foundSitemap := false
	foundInternal1 := false
	foundForm := false

	for _, u := range discoveredURLs {
		if strings.HasSuffix(u.URL, "/from-sitemap") {
			foundSitemap = true
		}
		if strings.HasSuffix(u.URL, "/admin-secret") {
			foundRobots = true
		}
		if strings.HasSuffix(u.URL, "/internal-link-1") {
			foundInternal1 = true
		}
		if strings.HasSuffix(u.URL, "/form-endpoint") {
			foundForm = true
		}

		// Verify every crawled URL is in scope
		dec := scopeValidator.Evaluate(target, u.Hostname, u.URL)
		if !dec.InScope {
			t.Fatalf("out-of-scope URL was accepted by crawler: %s", u.URL)
		}
	}

	if !foundInternal1 {
		t.Errorf("failed to discover HTML anchor /internal-link-1")
	}
	if !foundForm {
		t.Errorf("failed to discover form action /form-endpoint")
	}
	if !foundRobots {
		t.Errorf("failed to extract path from robots.txt")
	}
	if !foundSitemap {
		t.Errorf("failed to extract URL from sitemap.xml")
	}

	// Verify out-of-scope external link was recorded in skips
	foundExternalSkip := false
	for _, sk := range skipEvents {
		if strings.Contains(sk.Item, "external-domain.com") {
			foundExternalSkip = true
		}
	}
	if !foundExternalSkip {
		t.Errorf("expected external link to trigger a recorded SkipEvent")
	}
}

// 6. Complete End-to-End Pipeline Integration Test
func TestReconPipeline_EndToEndIntegration(t *testing.T) {
	memStore := storage.NewMemoryStorage()
	scopeValidator := scope.NewValidator()
	eventBus := events.NewMemoryEventBus(200)

	// Mock Server
	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "NexusMock/1.0")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/api/v1/health">API</a></body></html>`))
	}))
	defer ts.Close()

	tsHost, _ := ExtractHostnameFromURL(ts.URL)

	target := &models.Target{
		ID:             "target-e2e-1",
		Name:           "E2E Recon Target",
		RootDomain:     tsHost,
		AllowedDomains: []string{tsHost},
		Status:         models.TargetStatusActive,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	_ = memStore.Create(context.Background(), target)

	job := &models.ScanJob{
		ID:        "job-e2e-1",
		TargetID:  target.ID,
		Type:      "RECON",
		Status:    models.JobStatusRunning,
		CreatedAt: time.Now().UTC(),
	}

	// Setup Mock DNS
	mockDNS := NewMockDNSResolver()
	mockDNS.Set(tsHost, []DNSResult{
		{
			Hostname:   tsHost,
			RecordType: "A",
			Value:      "127.0.0.1",
			Status:     "NOERROR",
			Timestamp:  time.Now().UTC(),
		},
	})

	cfg := DefaultEngineConfig()
	cfg.RequestTimeout = 2 * time.Second

	pipeline := NewPipeline(
		cfg,
		scopeValidator,
		eventBus,
		memStore,
		memStore,
		nil,
		mockDNS,
		nil,
	)

	opts := ReconOptions{
		SubdomainDiscovery: true,
		DNSResolution:      true,
		HTTPProbe:          true,
		Crawl:              true,
	}

	run, err := pipeline.Execute(context.Background(), job, target, opts)
	if err != nil {
		t.Fatalf("pipeline execution failed: %v", err)
	}

	if run.Status != models.JobStatusCompleted {
		t.Fatalf("expected job status COMPLETED, got %s", run.Status)
	}

	if run.HostsDiscovered == 0 {
		t.Errorf("expected discovered hosts > 0")
	}
	if run.HostsResolved == 0 {
		t.Errorf("expected resolved hosts > 0")
	}

	// Verify assets in storage
	assets, err := memStore.ListAssets(context.Background(), target.ID)
	if err != nil || len(assets) == 0 {
		t.Fatalf("failed to retrieve stored assets: %v", err)
	}

	// Verify DNS records in storage
	dnsRecs, err := memStore.ListDNSRecords(context.Background(), assets[0].ID)
	if err != nil || len(dnsRecs) == 0 {
		t.Fatalf("failed to retrieve stored DNS records: %v", err)
	}

	// Verify events were published
	recentEvents := eventBus.GetRecentEvents(50)
	if len(recentEvents) == 0 {
		t.Fatalf("expected events in event bus, got 0")
	}
}

func TestCrawler_RedirectSafety(t *testing.T) {
	scopeValidator := scope.NewValidator()
	cfg := DefaultEngineConfig()
	cfg.AllowLocalAddresses = true
	cfg.MaxDepth = 2
	cfg.MaxURLsPerHost = 10

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/safe-seed":
			// In-scope page containing a link that redirects out of scope
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><a href="` + ts.URL + `/redirect-to-external">External Redir</a></body></html>`))
		case "/redirect-to-external":
			// Redirects to an out-of-scope domain
			http.Redirect(w, r, "https://evil-unauthorized-destination.com/malicious-page", http.StatusFound)
		case "/robots.txt":
			http.NotFound(w, r)
		case "/sitemap.xml":
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	tsHost, err := ExtractHostnameFromURL(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}

	target := &models.Target{
		ID:             "target-crawler-redir-test",
		RootDomain:     tsHost,
		AllowedDomains: []string{tsHost},
		Status:         models.TargetStatusActive,
	}

	crawler := NewCrawler(cfg, scopeValidator)
	dedup := NewDeduplicator()

	var discoveredURLs []CrawledURL
	var skipEvents []SkipEvent

	err = crawler.CrawlSeed(
		context.Background(),
		target,
		"asset-1",
		ts.URL+"/safe-seed",
		dedup,
		func(u CrawledURL) { discoveredURLs = append(discoveredURLs, u) },
		func(s SkipEvent) { skipEvents = append(skipEvents, s) },
	)
	if err != nil {
		t.Fatalf("crawler error: %v", err)
	}

	// Verify that the out-of-scope redirected URL was NEVER crawled or added to discoveredURLs
	for _, u := range discoveredURLs {
		if strings.Contains(u.URL, "evil-unauthorized-destination.com") {
			t.Fatalf("CRITICAL SECURITY VIOLATION: out-of-scope redirect was discovered: %s", u.URL)
		}
	}

	// Verify that an out-of-scope skip event was recorded
	foundSkip := false
	for _, s := range skipEvents {
		if strings.Contains(s.Item, "evil-unauthorized-destination.com") {
			foundSkip = true
			break
		}
	}
	if !foundSkip {
		t.Errorf("expected a skip event recording out-of-scope redirect destination")
	}
}

func TestHTTPProber_SSRFDefense(t *testing.T) {
	scopeValidator := scope.NewValidator()
	cfg := DefaultEngineConfig()
	// Strict production default: AllowLocalAddresses is false
	cfg.AllowLocalAddresses = false

	prober := NewStandardHTTPProber(cfg, scopeValidator)

	target := &models.Target{
		ID:             "target-ssrf-defense",
		RootDomain:     "127.0.0.1",
		AllowedDomains: []string{"127.0.0.1", "169.254.169.254", "localhost"},
		Status:         models.TargetStatusActive,
	}

	// 1. Probe to localhost/127.0.0.1 must be blocked by SSRF dialer
	_, _, err := prober.Probe(context.Background(), target, "http://127.0.0.1:8080/admin")
	if err == nil {
		t.Fatal("expected probe to 127.0.0.1 to be blocked by SSRF defense, got nil error")
	}

	// 2. Probe to cloud metadata 169.254.169.254 must be blocked
	_, _, err = prober.Probe(context.Background(), target, "http://169.254.169.254/latest/meta-data/")
	if err == nil {
		t.Fatal("expected probe to 169.254.169.254 to be blocked by SSRF defense, got nil error")
	}
}


