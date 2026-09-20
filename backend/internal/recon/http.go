package recon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/safenet"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
)

var (
	ErrRedirectOutOfScope = errors.New("redirect target is out of scope")
	ErrMaxRedirects       = errors.New("maximum redirect count exceeded")
)

// HTTPProber defines methods for safe HTTP endpoint verification.
type HTTPProber interface {
	Probe(ctx context.Context, target *models.Target, rawURL string) (*HTTPProbeResult, *SkipEvent, error)
}

// StandardHTTPProber performs non-invasive HTTP and HTTPS probes while enforcing redirect scope checks.
type StandardHTTPProber struct {
	client   *http.Client
	config   EngineConfig
	scopeSvc scope.ScopeService
}

// NewStandardHTTPProber builds an HTTP probe client with scoped redirect checking, SSRF defenses, and safe TLS inspection.
func NewStandardHTTPProber(cfg EngineConfig, scopeSvc scope.ScopeService) *StandardHTTPProber {
	prober := &StandardHTTPProber{
		config:   cfg,
		scopeSvc: scopeSvc,
	}

	transport := safenet.NewSafeTransportWithConfig(cfg.RequestTimeout, cfg.AllowLocalAddresses)

	prober.client = &http.Client{
		Transport: transport,
		Timeout:   cfg.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxRedirects {
				return ErrMaxRedirects
			}
			return nil
		},
	}

	return prober
}

// Probe executes an HTTP GET request to check service availability, strictly enforcing scope across redirects.
func (p *StandardHTTPProber) Probe(ctx context.Context, target *models.Target, rawURL string) (*HTTPProbeResult, *SkipEvent, error) {
	normURL, err := NormalizeURL(rawURL)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s", errors.New(ErrClassInvalidURL), err)
	}

	host, err := ExtractHostnameFromURL(normURL)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s", errors.New(ErrClassInvalidURL), err)
	}

	// 1. Initial Scope Validation
	decision := p.scopeSvc.Evaluate(target, host, normURL)
	if !decision.InScope {
		skip := &SkipEvent{
			Item:      normURL,
			TargetID:  target.ID,
			Reason:    decision.Reason,
			Stage:     "HTTP",
			Timestamp: time.Now().UTC(),
		}
		return nil, skip, errors.New(ErrClassScopeRejected)
	}

	var redirectHistory []string
	var outOfScopeSkip *SkipEvent

	// Create scoped custom client for this specific request to inspect redirects in real time
	scopedClient := *p.client
	scopedClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= p.config.MaxRedirects {
			return ErrMaxRedirects
		}

		// 1. Check SSRF boundary on redirect host
		if !p.config.AllowLocalAddresses {
			if restricted, reason := safenet.IsRestrictedHost(req.Context(), req.URL.Hostname()); restricted {
				outOfScopeSkip = &SkipEvent{
					Item:      req.URL.String(),
					TargetID:  target.ID,
					Reason:    fmt.Sprintf("SSRF_VIOLATION: redirect targets %s", reason),
					Stage:     "REDIRECT",
					Timestamp: time.Now().UTC(),
				}
				return safenet.ErrSSRFRedirectBlocked
			}
		} else {
			destHost := strings.Trim(req.URL.Hostname(), "[]")
			if destHost == "169.254.169.254" || strings.HasPrefix(destHost, "169.254.") {
				return safenet.ErrSSRFRedirectBlocked
			}
		}

		// 2. Strict Scope Evaluation
		redirectHost := req.URL.Hostname()
		redirDecision := p.scopeSvc.Evaluate(target, redirectHost, req.URL.String())
		if !redirDecision.InScope {
			outOfScopeSkip = &SkipEvent{
				Item:      req.URL.String(),
				TargetID:  target.ID,
				Reason:    fmt.Sprintf("Redirect destination out of scope: %s", redirDecision.Reason),
				Stage:     "REDIRECT",
				Timestamp: time.Now().UTC(),
			}
			return ErrRedirectOutOfScope
		}

		// 3. Strip sensitive authentication headers on cross-origin redirect
		if len(via) > 0 {
			prevURL := via[len(via)-1].URL
			if !strings.EqualFold(prevURL.Host, req.URL.Host) {
				req.Header.Del("Authorization")
				req.Header.Del("Cookie")
				req.Header.Del("Proxy-Authorization")
			}
		}

		redirectHistory = append(redirectHistory, req.URL.String())
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s", errors.New(ErrClassInternalError), err)
	}

	req.Header.Set("User-Agent", p.config.UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	startTime := time.Now()
	resp, err := scopedClient.Do(req)
	duration := time.Since(startTime)

	if err != nil {
		if errors.Is(err, ErrRedirectOutOfScope) || (err != nil && strings.Contains(err.Error(), ErrRedirectOutOfScope.Error())) {
			// Safe stop: redirect was prevented from leaving scope
			return nil, outOfScopeSkip, errors.New(ErrClassScopeRejected)
		}
		if errors.Is(err, context.DeadlineExceeded) || (err != nil && strings.Contains(err.Error(), "timeout")) {
			return nil, nil, errors.New(ErrClassHTTPTimeout)
		}
		return nil, nil, fmt.Errorf("%w: %s", errors.New(ErrClassHTTPError), err)
	}
	defer resp.Body.Close()

	// Read limited body (bounded by MaxResponseBody)
	limitReader := io.LimitReader(resp.Body, p.config.MaxResponseBody)
	bodyBytes, _ := io.ReadAll(limitReader)

	// TLS Version extraction if available
	tlsVer := ""
	if resp.TLS != nil {
		switch resp.TLS.Version {
		case tls.VersionTLS13:
			tlsVer = "TLS 1.3"
		case tls.VersionTLS12:
			tlsVer = "TLS 1.2"
		case tls.VersionTLS11:
			tlsVer = "TLS 1.1"
		case tls.VersionTLS10:
			tlsVer = "TLS 1.0"
		default:
			tlsVer = fmt.Sprintf("TLS 0x%04x", resp.TLS.Version)
		}
	}

	snippet := string(bodyBytes)
	rawBody := snippet
	if len(snippet) > 1024 {
		snippet = snippet[:1024]
	}

	headersMap := make(map[string]string)
	for k, v := range resp.Header {
		headersMap[k] = strings.Join(v, ", ")
	}

	var cookiesList []string
	for _, c := range resp.Cookies() {
		cookiesList = append(cookiesList, c.String())
	}

	result := &HTTPProbeResult{
		Hostname:        host,
		URL:             normURL,
		StatusCode:      resp.StatusCode,
		FinalURL:        resp.Request.URL.String(),
		ResponseTime:    duration,
		ContentType:     resp.Header.Get("Content-Type"),
		ContentLength:   resp.ContentLength,
		ServerHeader:    resp.Header.Get("Server"),
		TLSVersion:      tlsVer,
		RedirectHistory: redirectHistory,
		BodySnippet:     snippet,
		RawBody:         rawBody,
		Headers:         headersMap,
		Cookies:         cookiesList,
		Timestamp:       time.Now().UTC(),
	}

	return result, nil, nil
}
