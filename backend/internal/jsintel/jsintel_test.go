package jsintel

import (
	"context"
	"strings"
	"testing"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
)

func TestJSIntel_ScriptDiscoveryAndScope(t *testing.T) {
	validator := scope.NewValidator()
	target := &models.Target{
		ID:         "tgt-1",
		RootDomain: "example.com",
		AllowedDomains: []string{"example.com"},
		ScopeConfig: &models.AdvancedScopeConfig{
			AdvancedMode: true,
			Include: []models.AdvancedScopeRule{
				{Enabled: true, Host: `^.*\.example\.com$`},
			},
		},
	}

	service := NewService(validator, DefaultLimits())

	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<script src="/static/js/bundle.js"></script>
		<script src="https://cdn.example.com/assets/app.js"></script>
		<script src="https://thirdparty-analytics.com/tag.js"></script>
	</head>
	<body><h1>Test</h1></body>
	</html>`

	assets, err := service.DiscoverScriptsFromHTML(context.Background(), target, "asset-1", "https://app.example.com/login", html)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(assets) != 3 {
		t.Fatalf("expected 3 discovered scripts, got %d", len(assets))
	}

	var inScopeCount, outOfScopeCount int
	for _, a := range assets {
		if a.ScopeDecision.InScope {
			inScopeCount++
			if a.FetchStatus != "DISCOVERED" {
				t.Errorf("in-scope asset should be DISCOVERED, got %s", a.FetchStatus)
			}
		} else {
			outOfScopeCount++
			if a.FetchStatus != "SKIPPED_OUT_OF_SCOPE" {
				t.Errorf("third-party script should be SKIPPED_OUT_OF_SCOPE, got %s", a.FetchStatus)
			}
		}
	}

	if inScopeCount != 2 || outOfScopeCount != 1 {
		t.Errorf("expected 2 in-scope and 1 out-of-scope, got %d in-scope / %d out-of-scope", inScopeCount, outOfScopeCount)
	}
}

func TestJSIntel_AnalyzeContentAndRedaction(t *testing.T) {
	validator := scope.NewValidator()
	target := &models.Target{
		ID:         "tgt-1",
		RootDomain: "example.com",
		ScopeConfig: &models.AdvancedScopeConfig{
			AdvancedMode: true,
			Include: []models.AdvancedScopeRule{
				{Enabled: true, Host: `^.*\.example\.com$`},
			},
		},
	}

	service := NewService(validator, DefaultLimits())
	jsAsset := &models.JSAsset{
		ID:            "js-test-1",
		TargetID:      target.ID,
		AssetID:       "asset-1",
		URL:           "https://app.example.com/static/bundle.js",
		ContentSHA256: "aabbcc112233",
	}

	rawJS := `
		const API_BASE = "/api/v1/users";
		const GRAPHQL = "/graphql";
		const BUCKET_URL = "https://my-internal-bucket.s3.amazonaws.com/uploads/";
		const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
		const CONFIG = { API_BASE_URL: "https://api.example.com" };
	`

	refs, secrets, err := service.AnalyzeContent(context.Background(), target, jsAsset, rawJS)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify API route extraction
	var foundUserRoute, foundGraphQL, foundCloud bool
	for _, r := range refs {
		if r.Category == "API_ROUTE" && r.NormalizedValue == "/api/v1/users" {
			foundUserRoute = true
		}
		if r.Category == "API_ROUTE" && r.NormalizedValue == "/graphql" {
			foundGraphQL = true
		}
		if r.Category == "CLOUD_REFERENCE" && strings.Contains(r.ExtractedValue, "s3.amazonaws.com") {
			foundCloud = true
		}
	}

	if !foundUserRoute || !foundGraphQL {
		t.Errorf("failed to extract expected API routes from JS content")
	}
	if !foundCloud {
		t.Errorf("failed to extract cloud reference from JS content")
	}

	// Verify secret redaction (CRITICAL SECURITY PROPERTY)
	if len(secrets) != 1 {
		t.Fatalf("expected 1 detected secret indicator, got %d", len(secrets))
	}

	sec := secrets[0]
	if sec.SecretType != "AWS_ACCESS_KEY" {
		t.Errorf("expected secret type AWS_ACCESS_KEY, got %s", sec.SecretType)
	}

	if sec.MaskedPreview == "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("CRITICAL DEFECT: raw secret was NOT masked in preview! Got: %s", sec.MaskedPreview)
	}

	if !strings.HasPrefix(sec.MaskedPreview, "AKIA") || !strings.HasSuffix(sec.MaskedPreview, "PLE") {
		t.Errorf("expected masked preview format 'AKIA****...PLE', got '%s'", sec.MaskedPreview)
	}

	if sec.SHA256 == "" {
		t.Errorf("expected SHA256 checksum of secret to be computed")
	}
}
