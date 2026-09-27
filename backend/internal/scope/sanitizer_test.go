package scope

import (
	"errors"
	"testing"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

func TestScopeImportSanitizer_KeyAndValueTrimming(t *testing.T) {
	sanitizer := NewScopeImportSanitizer()

	raw := []byte(`{
		"target ": {
			"scope ": {
				"advanced_mode ": true,
				"include ": [
					{
						"enabled ": true,
						"host ": "  ^.*\\.shopify\\.com$  ",
						"protocol ": " any "
					}
				],
				"exclude ": [
					{
						"enabled ": true,
						"host ": "  ^admin\\.shopify\\.com$  ",
						"protocol ": " any "
					}
				]
			}
		}
	}`)

	review, err := sanitizer.SanitizeScopeFile(raw, "burp_export.json")
	if err != nil {
		t.Fatalf("expected successful sanitization, got error: %v", err)
	}

	// Requirement 8: Before human confirmation, SelectedRootDomain must remain strictly empty
	if review.SelectedRootDomain != "" {
		t.Errorf("expected selected root domain to be empty before confirmation, got '%s'", review.SelectedRootDomain)
	}

	if len(review.RootDomains) != 1 || review.RootDomains[0].NormalizedDomain != "shopify.com" {
		t.Errorf("expected discovered root domain 'shopify.com', got %+v", review.RootDomains)
	}

	if len(review.Normalizations) == 0 {
		t.Errorf("expected recorded normalizations for trimmed keys and values")
	}

	// Verify fail-closed evaluation with the canonical scope
	validator := NewValidator()
	target := &models.Target{
		ID:         "tgt-test",
		Name:       "Shopify Program",
		RootDomain: review.RootDomains[0].NormalizedDomain,
		Status:     models.TargetStatusActive,
		ScopeConfig: &models.AdvancedScopeConfig{
			AdvancedMode: true,
			Include:      review.CanonicalScope.IncludeHosts,
			Exclude:      review.CanonicalScope.ExcludeHosts,
		},
	}

	// In-scope test
	dec1 := validator.Evaluate(target, "app.shopify.com", "https://app.shopify.com/dashboard")
	if !dec1.InScope {
		t.Errorf("expected app.shopify.com to be in scope, reason: %s", dec1.Reason)
	}

	// Excluded host test (higher precedence)
	dec2 := validator.Evaluate(target, "admin.shopify.com", "https://admin.shopify.com/login")
	if dec2.InScope {
		t.Errorf("expected admin.shopify.com to be blocked by exclude rule, got in-scope")
	}
}

func TestScopeImportSanitizer_CorruptedWildcardRepair(t *testing.T) {
	sanitizer := NewScopeImportSanitizer()

	// Intentional corrupted representation: "^. \.rei\.com$ "
	raw := []byte(`{
		"target": {
			"scope": {
				"include": [
					{
						"enabled": true,
						"host": "^. \\.rei\\.com$ "
					}
				]
			}
		}
	}`)

	review, err := sanitizer.SanitizeScopeFile(raw, "corrupted_scope.json")
	if err != nil {
		t.Fatalf("expected successful sanitization, got: %v", err)
	}

	if len(review.RootDomains) != 1 || review.RootDomains[0].NormalizedDomain != "rei.com" {
		t.Errorf("expected root domain candidate 'rei.com', got %+v", review.RootDomains)
	}

	if len(review.CanonicalScope.IncludeHosts) != 1 {
		t.Fatalf("expected 1 include host rule, got %d", len(review.CanonicalScope.IncludeHosts))
	}

	normalizedPattern := review.CanonicalScope.IncludeHosts[0].Host
	if normalizedPattern != `^.*\.rei\.com$` {
		t.Errorf("expected normalized pattern '^.*\\.rei\\.com$', got '%s'", normalizedPattern)
	}

	// Verify a warning normalization was recorded
	var foundWarning bool
	for _, n := range review.Normalizations {
		if n.Severity == "WARNING" && n.Normalized == `^.*\.rei\.com$` {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Errorf("expected warning normalization record for corrupted wildcard regex repair")
	}
}

func TestScopeImportSanitizer_MultiRootDomainDiscovery(t *testing.T) {
	sanitizer := NewScopeImportSanitizer()

	raw := []byte(`{
		"scope": [
			{ "asset_identifier": "*.shopify.com", "eligible_for_bounty": true },
			{ "asset_identifier": "*.shopify.io", "eligible_for_bounty": true },
			{ "asset_identifier": "*.shopifycloud.com", "eligible_for_bounty": false }
		]
	}`)

	review, err := sanitizer.SanitizeScopeFile(raw, "multi_domain_h1.json")
	if err != nil {
		t.Fatalf("expected successful multi-domain parsing, got: %v", err)
	}

	// Requirement 13: Exclude-only rules (*.shopifycloud.com) MUST NOT derive authoritative roots.
	// Only shopify.com and shopify.io from eligible_for_bounty=true are candidates.
	if len(review.RootDomains) != 2 {
		t.Errorf("expected 2 root domain candidates (exclude rule ignored), got %d", len(review.RootDomains))
	}

	domainsMap := make(map[string]bool)
	for _, d := range review.RootDomains {
		domainsMap[d.NormalizedDomain] = true
	}

	if !domainsMap["shopify.com"] || !domainsMap["shopify.io"] {
		t.Errorf("expected shopify.com and shopify.io to be discovered, got: %v", domainsMap)
	}
	if domainsMap["shopifycloud.com"] {
		t.Errorf("shopifycloud.com must NOT be in candidates because it came from an exclude rule")
	}

	// Requirement 8: When roots exist, SelectedRootDomain must remain strictly empty before confirmation!
	if review.SelectedRootDomain != "" {
		t.Errorf("expected SelectedRootDomain to be empty before confirmation (got '%s')", review.SelectedRootDomain)
	}
}

// Requirement 13: Public-Suffix-Aware domain extraction test
func TestScopeImportSanitizer_PublicSuffixExtraction(t *testing.T) {
	sanitizer := NewScopeImportSanitizer()

	raw := []byte(`{
		"target": {
			"scope": {
				"include": [
					{ "enabled": true, "host": "^sub\\.corp\\.example\\.co\\.uk$" },
					{ "enabled": true, "host": "^api\\.stage\\.example\\.com\\.au$" },
					{ "enabled": true, "host": "^internal\\.example\\.com$" }
				]
			}
		}
	}`)

	review, err := sanitizer.SanitizeScopeFile(raw, "public_suffix.json")
	if err != nil {
		t.Fatalf("sanitization failed: %v", err)
	}

	expectedRoots := map[string]bool{
		"example.co.uk":  false,
		"example.com.au": false,
		"example.com":    false,
	}

	for _, cand := range review.RootDomains {
		if _, ok := expectedRoots[cand.NormalizedDomain]; ok {
			expectedRoots[cand.NormalizedDomain] = true
		} else {
			t.Errorf("unexpected root domain discovered: %s", cand.NormalizedDomain)
		}
	}

	for domain, found := range expectedRoots {
		if !found {
			t.Errorf("expected public-suffix-aware registrable domain '%s' was not extracted", domain)
		}
	}
}

// Requirement 11: Normalization Collision Test
func TestScopeImportSanitizer_NormalizationCollision(t *testing.T) {
	sanitizer := NewScopeImportSanitizer()

	// Keys "host" and "host " normalize to identical key "host"
	raw := []byte(`{
		"target": {
			"scope": {
				"include": [
					{
						"host": "^.*\\.example\\.com$",
						"host ": "^.*\\.example\\.net$"
					}
				]
			}
		}
	}`)

	_, err := sanitizer.SanitizeScopeFile(raw, "collision.json")
	if err == nil {
		t.Fatalf("expected error on normalization collision, got nil")
	}
	if !errors.Is(err, ErrNormalizationCollision) {
		t.Errorf("expected ErrNormalizationCollision, got: %v", err)
	}
}

// Requirement 12: Empty Host Rule Test (Fail closed)
func TestScopeImportSanitizer_EmptyHostRuleRejected(t *testing.T) {
	sanitizer := NewScopeImportSanitizer()

	testCases := []struct {
		name string
		raw  []byte
	}{
		{
			name: "empty host string",
			raw: []byte(`{
				"target": {
					"scope": {
						"include": [
							{ "enabled": true, "host": "   " }
						]
					}
				}
			}`),
		},
		{
			name: "missing host field",
			raw: []byte(`{
				"target": {
					"scope": {
						"include": [
							{ "enabled": true, "protocol": "https" }
						]
					}
				}
			}`),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sanitizer.SanitizeScopeFile(tc.raw, "empty_host.json")
			if err == nil {
				t.Fatalf("expected error on empty host rule, got nil")
			}
			if !errors.Is(err, ErrEmptyHostRule) {
				t.Errorf("expected ErrEmptyHostRule, got: %v", err)
			}
		})
	}
}

// Requirement 14: Deterministic Canonicalization Test (100 iterations)
func TestScopeImportSanitizer_DeterministicCanonicalization(t *testing.T) {
	sanitizer := NewScopeImportSanitizer()

	raw := []byte(`{
		"target": {
			"scope": {
				"include": [
					{ "enabled": true, "host": "^z\\.example\\.com$", "port": "443" },
					{ "enabled": true, "host": "^a\\.example\\.com$", "port": "80" },
					{ "enabled": true, "host": "^m\\.example\\.com$", "port": "8080" }
				],
				"exclude": [
					{ "enabled": true, "host": "^z-admin\\.example\\.com$" },
					{ "enabled": true, "host": "^a-admin\\.example\\.com$" }
				]
			}
		}
	}`)

	firstReview, err := sanitizer.SanitizeScopeFile(raw, "determ.json")
	if err != nil {
		t.Fatalf("initial run failed: %v", err)
	}

	for i := 0; i < 100; i++ {
		rev, err := sanitizer.SanitizeScopeFile(raw, "determ.json")
		if err != nil {
			t.Fatalf("run %d failed: %v", i, err)
		}
		if rev.CanonicalScopeSHA256 != firstReview.CanonicalScopeSHA256 {
			t.Fatalf("run %d produced divergent CanonicalScopeSHA256: %s != %s",
				i, rev.CanonicalScopeSHA256, firstReview.CanonicalScopeSHA256)
		}
		if rev.NormalizationManifestSHA256 != firstReview.NormalizationManifestSHA256 {
			t.Fatalf("run %d produced divergent NormalizationManifestSHA256: %s != %s",
				i, rev.NormalizationManifestSHA256, firstReview.NormalizationManifestSHA256)
		}
	}
}

// Authorization-Preservation Property Test
func TestScopeImportSanitizer_AuthorizationPreservationProperty(t *testing.T) {
	sanitizer := NewScopeImportSanitizer()

	rawBurp := []byte(`{
		"target": {
			"scope": {
				"advanced_mode": true,
				"include": [
					{ "enabled": true, "host": "^.*\\.example\\.com$" }
				],
				"exclude": [
					{ "enabled": true, "host": "^admin\\.example\\.com$" },
					{ "enabled": true, "host": "^internal\\.example\\.com$" }
				]
			}
		}
	}`)

	review, err := sanitizer.SanitizeScopeFile(rawBurp, "burp_auth_test.json")
	if err != nil {
		t.Fatalf("sanitization failed: %v", err)
	}

	validator := NewValidator()
	target := &models.Target{
		ID:         "target-prop-test",
		Name:       "Property Test Target",
		RootDomain: "example.com",
		Status:     models.TargetStatusActive,
		ScopeConfig: &models.AdvancedScopeConfig{
			AdvancedMode: true,
			Include:      review.CanonicalScope.IncludeHosts,
			Exclude:      review.CanonicalScope.ExcludeHosts,
		},
	}

	testUniverse := []struct {
		hostname string
		url      string
		expected bool
	}{
		{"api.example.com", "https://api.example.com/v1/data", true},
		{"shop.example.com", "https://shop.example.com/", true},
		{"example.com", "https://example.com/", true},
		{"admin.example.com", "https://admin.example.com/secret", false},
		{"internal.example.com", "https://internal.example.com/", false},
		{"evil-example.com", "https://evil-example.com/", false},
		{"example.com.attacker.com", "https://example.com.attacker.com/", false},
		{"attacker.com", "https://attacker.com/", false},
		{"notexample.com", "https://notexample.com/", false},
		{"example.org", "https://example.org/", false},
	}

	newlyAuthorized := make([]string, 0)
	for _, tc := range testUniverse {
		decision := validator.Evaluate(target, tc.hostname, tc.url)
		if decision.InScope != tc.expected {
			if decision.InScope && !tc.expected {
				newlyAuthorized = append(newlyAuthorized, tc.hostname)
			}
			t.Errorf("hostname %s: expected inScope=%v, got=%v (reason: %s)", tc.hostname, tc.expected, decision.InScope, decision.Reason)
		}
	}

	// Critical Invariant: NEWLY_AUTHORIZED must be strictly empty
	if len(newlyAuthorized) > 0 {
		t.Fatalf("AUTHORIZATION VIOLATION: canonical scope newly authorized out-of-scope targets: %v", newlyAuthorized)
	}
}

func TestScopeImportSanitizer_HashesIntegrity(t *testing.T) {
	sanitizer := NewScopeImportSanitizer()

	raw := []byte(`{
		"scope": [
			{ "asset_identifier": "*.target.com", "eligible_for_bounty": true }
		]
	}`)

	review, err := sanitizer.SanitizeScopeFile(raw, "integrity_test.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(review.OriginalFileSHA256) != 64 {
		t.Errorf("expected 64-char OriginalFileSHA256, got: '%s'", review.OriginalFileSHA256)
	}
	if len(review.CanonicalScopeSHA256) != 64 {
		t.Errorf("expected 64-char CanonicalScopeSHA256, got: '%s'", review.CanonicalScopeSHA256)
	}
	if len(review.NormalizationManifestSHA256) != 64 {
		t.Errorf("expected 64-char NormalizationManifestSHA256, got: '%s'", review.NormalizationManifestSHA256)
	}
}
