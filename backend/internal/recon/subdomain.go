package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
)

// SubdomainProvider defines the contract for asset discovery sources.
type SubdomainProvider interface {
	Name() string
	Discover(ctx context.Context, target *models.Target) ([]string, error)
}

// BaselineProvider implements an authorized, safe, non-invasive baseline subdomain discovery provider.
// It combines configured scope seeds, safe standard permutations, and passive Certificate Transparency querying.
// Requires NO commercial API keys and enforces strict zero-credential requirements.
type BaselineProvider struct {
	scopeSvc   scope.ScopeService
	httpClient *http.Client
	commonSubs []string
}

// NewBaselineProvider initializes a safe default subdomain provider.
func NewBaselineProvider(scopeSvc scope.ScopeService) *BaselineProvider {
	return &BaselineProvider{
		scopeSvc: scopeSvc,
		httpClient: &http.Client{
			Timeout: 6 * time.Second,
		},
		commonSubs: []string{
			"www", "api", "app", "dev", "stage", "staging", "auth", "admin",
			"portal", "mail", "vpn", "docs", "cdn", "test", "internal", "status",
			"beta", "m", "mobile", "secure", "login", "sso", "dashboard",
		},
	}
}

// Name returns the provider identifier.
func (p *BaselineProvider) Name() string {
	return "BASELINE_PASSIVE_PROVIDER"
}

// Discover produces a set of normalized, deduplicated hostnames that STRICTLY pass target scope validation.
func (p *BaselineProvider) Discover(ctx context.Context, target *models.Target) ([]string, error) {
	if target == nil {
		return nil, scope.ErrTargetNil
	}

	rawCandidates := make([]string, 0)

	// 1. Seed root domain and explicitly allowed domains
	if target.RootDomain != "" {
		rawCandidates = append(rawCandidates, target.RootDomain)
	}
	for _, ad := range target.AllowedDomains {
		clean := strings.TrimSpace(ad)
		if strings.HasPrefix(clean, "*.") {
			base := strings.TrimPrefix(clean, "*.")
			rawCandidates = append(rawCandidates, base)
			// Permute baseline common subdomains for allowed wildcard domains
			for _, sub := range p.commonSubs {
				rawCandidates = append(rawCandidates, fmt.Sprintf("%s.%s", sub, base))
			}
		} else if clean != "" {
			rawCandidates = append(rawCandidates, clean)
		}
	}

	// 2. Passive Certificate Transparency query (crt.sh) - best effort with strict timeout
	ctCandidates := p.queryPassiveCT(ctx, target.RootDomain)
	rawCandidates = append(rawCandidates, ctCandidates...)

	// 3. Normalization, Deduplication, and Strict Scope Enforcement
	discovered := make([]string, 0)
	seen := make(map[string]struct{})

	for _, cand := range rawCandidates {
		select {
		case <-ctx.Done():
			return discovered, ctx.Err()
		default:
		}

		normHost, err := NormalizeHostname(cand)
		if err != nil {
			// Skip malformed hostnames
			continue
		}

		if _, exists := seen[normHost]; exists {
			continue
		}
		seen[normHost] = struct{}{}

		// CRITICAL: Strict Fail-Closed Scope Validation
		decision := p.scopeSvc.Evaluate(target, normHost, "")
		if !decision.InScope {
			// Out of scope: fail closed and ignore
			continue
		}

		discovered = append(discovered, normHost)
	}

	return discovered, nil
}

// queryPassiveCT attempts a safe query to crt.sh JSON endpoint.
// Failures or timeouts are gracefully handled and never break the scan.
func (p *BaselineProvider) queryPassiveCT(ctx context.Context, domain string) []string {
	cleanDomain, err := NormalizeHostname(domain)
	if err != nil || cleanDomain == "" {
		return nil
	}

	reqURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", cleanDomain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "NexusHunter-AI/0.2.0 (Security Research)")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		// Network failure or timeout: silently proceed with baseline candidates
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	type crtEntry struct {
		NameValue string `json:"name_value"`
	}

	var entries []crtEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil
	}

	results := make([]string, 0, len(entries))
	for _, entry := range entries {
		// crt.sh entries can contain multi-line SANs or wildcard prefixes
		lines := strings.Split(entry.NameValue, "\n")
		for _, line := range lines {
			val := strings.TrimSpace(line)
			val = strings.TrimPrefix(val, "*.")
			if val != "" {
				results = append(results, val)
			}
		}
	}

	return results
}
