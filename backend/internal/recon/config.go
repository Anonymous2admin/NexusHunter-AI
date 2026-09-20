package recon

import (
	"os"
	"strconv"
	"time"
)

// EngineConfig encapsulates performance, concurrency, safety limits, and rate limits for the recon engine.
type EngineConfig struct {
	DNSWorkers        int           `json:"dns_workers"`
	HTTPWorkers       int           `json:"http_workers"`
	CrawlerWorkers    int           `json:"crawler_workers"`
	MaxDepth          int           `json:"max_depth"`
	MaxURLsPerHost    int           `json:"max_urls_per_host"`
	MaxResponseBody   int64         `json:"max_response_body"`
	RequestTimeout    time.Duration `json:"request_timeout"`
	MaxRedirects      int           `json:"max_redirects"`
	RequestsPerSecond float64       `json:"requests_per_second"`
	BurstSize         int           `json:"burst_size"`
	UserAgent         string        `json:"user_agent"`
	AllowLocalAddresses bool        `json:"allow_local_addresses"` // Default false; only enabled in isolated test suites
}

// DefaultEngineConfig returns safe, high-speed, bounded defaults.
func DefaultEngineConfig() EngineConfig {
	dnsWorkers := getEnvInt("DNS_WORKERS", 10)
	httpWorkers := getEnvInt("HTTP_WORKERS", 10)
	crawlerWorkers := getEnvInt("CRAWLER_WORKERS", 5)
	maxDepth := getEnvInt("MAX_DEPTH", 2)
	maxURLs := getEnvInt("MAX_URLS_PER_HOST", 500)
	maxRespBody := getEnvInt64("MAX_RESPONSE_BODY", 2*1024*1024) // 2MB
	reqTimeoutSec := getEnvInt("REQUEST_TIMEOUT_SEC", 10)
	maxRedirects := getEnvInt("MAX_REDIRECTS", 5)
	rps := getEnvFloat("REQUESTS_PER_SECOND", 20.0)
	burst := getEnvInt("BURST_SIZE", 30)

	ua := os.Getenv("RECON_USER_AGENT")
	if ua == "" {
		ua = "NexusHunter-AI/0.2.0 (Authorized Security Research; Personal Scoped Audit)"
	}

	return EngineConfig{
		DNSWorkers:        dnsWorkers,
		HTTPWorkers:       httpWorkers,
		CrawlerWorkers:    crawlerWorkers,
		MaxDepth:          maxDepth,
		MaxURLsPerHost:    maxURLs,
		MaxResponseBody:   maxRespBody,
		RequestTimeout:    time.Duration(reqTimeoutSec) * time.Second,
		MaxRedirects:      maxRedirects,
		RequestsPerSecond: rps,
		BurstSize:         burst,
		UserAgent:         ua,
	}
}

func getEnvInt(key string, fallback int) int {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func getEnvInt64(key string, fallback int64) int64 {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func getEnvFloat(key string, fallback float64) float64 {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(val, 64)
	if err != nil || f <= 0 {
		return fallback
	}
	return f
}
