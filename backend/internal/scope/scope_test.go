package scope

import (
	"testing"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

func sampleTarget() *models.Target {
	return &models.Target{
		ID:                 "target-test-1",
		Name:               "Example Bounty Program",
		RootDomain:         "example.com",
		AllowedDomains:     []string{"example.com", "*.example.com", "partner-service.net"},
		AllowedURLPatterns: []string{"/api/*", "/v1/*", "/auth"},
		ExcludedPatterns:   []string{"admin.example.com", "*.internal.example.com", "/api/destructive"},
		Status:             models.TargetStatusActive,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
}

func TestScopeValidator_ExactDomain(t *testing.T) {
	v := NewValidator()
	target := sampleTarget()

	// Exact root domain
	inScope, err := v.IsInScope(target, "example.com", "https://example.com/api/v1/users")
	if !inScope || err != nil {
		t.Fatalf("expected exact domain to be in scope, got inScope=%v, err=%v", inScope, err)
	}

	// Exact secondary allowed domain without wildcard
	inScope, err = v.IsInScope(target, "partner-service.net", "https://partner-service.net/api/status")
	if !inScope || err != nil {
		t.Fatalf("expected partner-service.net to be in scope, got inScope=%v, err=%v", inScope, err)
	}
}

func TestScopeValidator_Subdomain(t *testing.T) {
	v := NewValidator()
	target := sampleTarget()

	// Allowed wildcard subdomain
	inScope, err := v.IsInScope(target, "api.example.com", "https://api.example.com/api/v1/ping")
	if !inScope || err != nil {
		t.Fatalf("expected api.example.com to be in scope via wildcard, got inScope=%v, err=%v", inScope, err)
	}

	// Deep subdomain under *.example.com
	inScope, err = v.IsInScope(target, "staging.api.example.com", "https://staging.api.example.com/auth")
	if !inScope || err != nil {
		t.Fatalf("expected staging.api.example.com to be in scope, got inScope=%v, err=%v", inScope, err)
	}

	// Subdomain on partner-service.net where wildcard was NOT specified
	inScope, err = v.IsInScope(target, "sub.partner-service.net", "https://sub.partner-service.net/api/v1")
	if inScope || err == nil {
		t.Fatalf("expected sub.partner-service.net to fail closed since no wildcard was allowed")
	}
}

func TestScopeValidator_UnrelatedDomain(t *testing.T) {
	v := NewValidator()
	target := sampleTarget()

	tests := []struct {
		host string
		url  string
	}{
		{"google.com", "https://google.com"},
		{"evil-example.com", "https://evil-example.com/api/test"},
		{"example.com.attacker.com", "https://example.com.attacker.com"},
		{"notexample.com", "https://notexample.com/api"},
	}

	for _, tt := range tests {
		inScope, err := v.IsInScope(target, tt.host, tt.url)
		if inScope || err == nil {
			t.Errorf("expected host %s to be out of scope, got inScope=true", tt.host)
		}
	}
}

func TestScopeValidator_ExcludedHost(t *testing.T) {
	v := NewValidator()
	target := sampleTarget()

	// Exact excluded host
	inScope, err := v.IsInScope(target, "admin.example.com", "https://admin.example.com/api/test")
	if inScope || err == nil {
		t.Fatalf("expected admin.example.com to be excluded, got inScope=%v", inScope)
	}

	// Wildcard excluded host (*.internal.example.com)
	inScope, err = v.IsInScope(target, "corp.internal.example.com", "https://corp.internal.example.com/api")
	if inScope || err == nil {
		t.Fatalf("expected corp.internal.example.com to be excluded, got inScope=%v", inScope)
	}

	// Excluded URL pattern (/api/destructive)
	inScope, err = v.IsInScope(target, "api.example.com", "https://api.example.com/api/destructive/test")
	if inScope || err == nil {
		t.Fatalf("expected /api/destructive to be excluded by pattern, got inScope=%v", inScope)
	}
}

func TestScopeValidator_MalformedHostname(t *testing.T) {
	v := NewValidator()
	target := sampleTarget()

	malformedHosts := []string{
		"",
		"   ",
		"http://example.com",
		"example..com",
		"-example.com",
		"example.com-",
		"example.com/path",
		"example.com:8080",
		"*.com",
		"test@example.com",
		"bad host name.com",
		"<script>alert(1)</script>",
	}

	for _, badHost := range malformedHosts {
		inScope, err := v.IsInScope(target, badHost, "")
		if inScope || err == nil {
			t.Errorf("expected malformed host '%s' to fail closed, got inScope=true", badHost)
		}
	}
}

func TestScopeValidator_EmptyScope(t *testing.T) {
	v := NewValidator()

	// Target with empty scope
	emptyTarget := &models.Target{
		ID:                 "empty-1",
		Name:               "Empty Target",
		RootDomain:         "",
		AllowedDomains:     []string{},
		AllowedURLPatterns: []string{},
		Status:             models.TargetStatusActive,
	}

	inScope, err := v.IsInScope(emptyTarget, "example.com", "https://example.com")
	if inScope || err == nil {
		t.Fatalf("expected empty scope to fail closed, got inScope=%v", inScope)
	}

	// Nil target
	inScope, err = v.IsInScope(nil, "example.com", "https://example.com")
	if inScope || err == nil {
		t.Fatalf("expected nil target to fail closed, got inScope=%v", inScope)
	}

	// Inactive target
	inactiveTarget := sampleTarget()
	inactiveTarget.Status = models.TargetStatusInactive
	inScope, err = v.IsInScope(inactiveTarget, "example.com", "https://example.com/api/users")
	if inScope || err == nil {
		t.Fatalf("expected inactive target to fail closed, got inScope=%v", inScope)
	}
}

func TestScopeValidator_URLPathRestrictions(t *testing.T) {
	v := NewValidator()
	target := sampleTarget()

	// Allowed path matching /api/*
	inScope, err := v.IsInScope(target, "example.com", "https://example.com/api/v2/items")
	if !inScope || err != nil {
		t.Fatalf("expected /api/v2/items to be allowed, got inScope=%v, err=%v", inScope, err)
	}

	// Allowed path matching exact /auth
	inScope, err = v.IsInScope(target, "example.com", "https://example.com/auth")
	if !inScope || err != nil {
		t.Fatalf("expected /auth to be allowed, got inScope=%v, err=%v", inScope, err)
	}

	// Disallowed path (/blog or /admin)
	inScope, err = v.IsInScope(target, "example.com", "https://example.com/blog/article")
	if inScope || err == nil {
		t.Fatalf("expected /blog/article to fail path restriction, got inScope=%v", inScope)
	}

	// Missing URL when path restrictions exist
	inScope, err = v.IsInScope(target, "example.com", "")
	if inScope || err == nil {
		t.Fatalf("expected empty URL to fail when path restrictions are enforced")
	}

	// Malformed scheme (ftp:// or file://)
	inScope, err = v.IsInScope(target, "example.com", "ftp://example.com/api/test")
	if inScope || err == nil {
		t.Fatalf("expected non-http(s) scheme to fail, got inScope=%v", inScope)
	}
}

func TestScopeValidator_TargetValidation(t *testing.T) {
	v := NewValidator()

	// Valid target
	if err := v.ValidateTarget(sampleTarget()); err != nil {
		t.Fatalf("expected sampleTarget to be valid, got err=%v", err)
	}

	// Target without name
	badTarget := sampleTarget()
	badTarget.Name = ""
	if err := v.ValidateTarget(badTarget); err == nil {
		t.Fatalf("expected error on empty target name")
	}

	// Broad wildcard
	badWildcard := sampleTarget()
	badWildcard.AllowedDomains = []string{"*"}
	if err := v.ValidateTarget(badWildcard); err == nil {
		t.Fatalf("expected error on broad wildcard '*'")
	}
}

func TestScopeValidator_BugBountyScopeJSON_And_ExplicitExclusionOverride(t *testing.T) {
	v := NewValidator()

	// Burp Suite style bug-bounty JSON scope format:
	// *.arc.io included, but community.arc.io, explorer.arc.io, help.arc.io explicitly excluded
	burpJSON := []byte(`{
		"target": {
			"scope": {
				"advanced_mode": true,
				"include": [
					{
						"enabled": true,
						"host": "^.*\\.arc\\.io$",
						"port": "^.*$",
						"protocol": "any",
						"file": "^/.*$"
					}
				],
				"exclude": [
					{
						"enabled": true,
						"host": "^community\\.arc\\.io$",
						"port": "^.*$",
						"protocol": "any",
						"file": "^/.*$"
					},
					{
						"enabled": true,
						"host": "^explorer\\.arc\\.io$",
						"port": "^.*$",
						"protocol": "any",
						"file": "^/.*$"
					},
					{
						"enabled": true,
						"host": "^help\\.arc\\.io$",
						"port": "^.*$",
						"protocol": "any",
						"file": "^/.*$"
					}
				]
			}
		}
	}`)

	cfg, err := ParseBugBountyScopeJSON(burpJSON)
	if err != nil {
		t.Fatalf("failed to parse Burp Suite scope JSON: %v", err)
	}

	target := &models.Target{
		ID:          "tgt-arc-io",
		Name:        "Arc.io Bug Bounty",
		RootDomain:  "arc.io",
		ScopeConfig: cfg,
		Status:      models.TargetStatusActive,
	}

	// 1. In-scope subdomains under *.arc.io MUST be authorized
	authorizedCases := []string{
		"https://api.arc.io/v1/health",
		"https://test.arc.io/login",
		"https://app.arc.io/dashboard",
	}
	for _, rawURL := range authorizedCases {
		decision := v.Evaluate(target, "", rawURL)
		if !decision.InScope {
			t.Errorf("expected %s to be authorized under *.arc.io, got in_scope=false, reason=%s", rawURL, decision.Reason)
		}
	}

	// 2. Explicitly excluded subdomains MUST be blocked (explicit exclude overrides broad include)
	excludedCases := []string{
		"https://community.arc.io/forums",
		"https://explorer.arc.io/blocks",
		"https://help.arc.io/articles",
	}
	for _, rawURL := range excludedCases {
		decision := v.Evaluate(target, "", rawURL)
		if decision.InScope {
			t.Errorf("expected %s to be BLOCKED due to explicit exclusion, but got in_scope=true", rawURL)
		}
	}

	// 3. Completely unrelated domains MUST be blocked
	unrelatedCases := []string{
		"https://evil.com/payload",
		"https://attacker-arc.io/test",
		"https://google.com",
	}
	for _, rawURL := range unrelatedCases {
		decision := v.Evaluate(target, "", rawURL)
		if decision.InScope {
			t.Errorf("expected %s to be out of scope, but got in_scope=true", rawURL)
		}
	}
}

