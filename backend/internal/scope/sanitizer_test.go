package scope

import (
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

	if review.SelectedRootDomain != "shopify.com" {
		t.Errorf("expected selected root domain 'shopify.com', got '%s'", review.SelectedRootDomain)
	}

	if len(review.Normalizations) == 0 {
		t.Errorf("expected recorded normalizations for trimmed keys and values")
	}

	// Verify fail-closed evaluation with the canonical scope
	validator := NewValidator()
	target := &models.Target{
		ID:         "tgt-test",
		Name:       "Shopify Program",
		RootDomain: review.SelectedRootDomain,
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

	if review.SelectedRootDomain != "rei.com" {
		t.Errorf("expected root domain 'rei.com', got '%s'", review.SelectedRootDomain)
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

func TestScopeImportSanitizer_RejectOverlyBroadUniversalPatterns(t *testing.T) {
	sanitizer := NewScopeImportSanitizer()

	dangerousInputs := []string{
		`{ "target": { "scope": { "include": [ { "enabled": true, "host": ".*" } ] } } }`,
		`{ "target": { "scope": { "include": [ { "enabled": true, "host": "^.*$" } ] } } }`,
		`{ "target": { "scope": { "include": [ { "enabled": true, "host": " .+" } ] } } }`,
	}

	for _, input := range dangerousInputs {
		review, err := sanitizer.SanitizeScopeFile([]byte(input), "dangerous.json")
		// The rule should either fail the file or record a critical rejection without admitting the dangerous rule
		if err == nil && review != nil {
			if len(review.CanonicalScope.IncludeHosts) > 0 {
				t.Errorf("expected universal broad regex to be rejected, but it was included: %v", review.CanonicalScope.IncludeHosts)
			}
		}
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

	if len(review.RootDomains) != 3 {
		t.Errorf("expected 3 root domain candidates, got %d", len(review.RootDomains))
	}

	domainsMap := make(map[string]bool)
	for _, d := range review.RootDomains {
		domainsMap[d.NormalizedDomain] = true
	}

	if !domainsMap["shopify.com"] || !domainsMap["shopify.io"] || !domainsMap["shopifycloud.com"] {
		t.Errorf("expected shopify.com, shopify.io, and shopifycloud.com to be discovered, got: %v", domainsMap)
	}

	// Section 8 Invariant: When multiple root domains exist, NO silent default selection is permitted!
	if review.SelectedRootDomain != "" {
		t.Errorf("expected SelectedRootDomain to be empty when multiple roots exist (got '%s')", review.SelectedRootDomain)
	}
}

// Section 6: Authorization-Preservation Property Test
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

// Section 9: Scope Integrity Hashes Test
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
