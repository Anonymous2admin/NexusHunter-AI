package cloudintel

import (
	"context"
	"testing"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
)

func TestCloudIntel_PassiveExtraction(t *testing.T) {
	validator := scope.NewValidator()
	target := &models.Target{
		ID:         "tgt-cloud",
		RootDomain: "target.com",
		ScopeConfig: &models.AdvancedScopeConfig{
			AdvancedMode: true,
			Include: []models.AdvancedScopeRule{
				{Enabled: true, Host: `^.*\.target\.com$`},
			},
		},
	}

	service := NewService(validator, 5*time.Second)

	samplePayload := `
		<!-- Sample response containing cloud references -->
		<img src="https://media-assets.s3.amazonaws.com/logo.png" />
		<link rel="stylesheet" href="https://d111111abcdef8.cloudfront.net/styles.css" />
		<script>
			window.__CONFIG__ = {
				azureStorage: "https://myaccount.blob.core.windows.net/public-assets",
				gcpBucket: "https://storage.googleapis.com/target-public-data/index.json"
			};
		</script>
	`

	refs, err := service.ExtractCloudReferences(context.Background(), target, "asset-1", "HTTP_RESPONSE", "/index.html", samplePayload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(refs) < 4 {
		t.Fatalf("expected at least 4 cloud references, got %d", len(refs))
	}

	providers := make(map[string]bool)
	for _, r := range refs {
		providers[r.Provider] = true
	}

	if !providers["AWS"] || !providers["AZURE"] || !providers["GCP"] {
		t.Errorf("expected AWS, Azure, and GCP providers to be identified, got: %v", providers)
	}
}

// Section 20 Test: Verify scope boundary check prevents network probing of out-of-scope cloud resources
func TestCloudIntel_ScopeBoundaryEnforcedBeforeProbe(t *testing.T) {
	validator := scope.NewValidator()
	target := &models.Target{
		ID:         "tgt-cloud",
		RootDomain: "target.com",
		ScopeConfig: &models.AdvancedScopeConfig{
			AdvancedMode: true,
			Include: []models.AdvancedScopeRule{
				{Enabled: true, Host: `^.*\.target\.com$`},
			},
			Exclude: []models.AdvancedScopeRule{
				{Enabled: true, Host: `^.*\.amazonaws\.com$`},
			},
		},
	}

	service := NewService(validator, 2*time.Second)

	ref := &models.CloudReference{
		ID:               "cld-test-out-of-scope",
		TargetID:         target.ID,
		Provider:         "AWS",
		ResourceType:     "S3_BUCKET",
		RawReference:     "https://unauthorized-bucket.s3.amazonaws.com",
		NormalizedTarget: "unauthorized-bucket",
		ScopeStatus:      "OUT_OF_SCOPE",
		ValidationStatus: "UNCHECKED",
	}

	err := service.ProbeSafePublicStatus(context.Background(), target, ref)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Must be SKIPPED_OUT_OF_SCOPE, and StatusCode must remain 0 (no request made)
	if ref.ValidationStatus != "SKIPPED_OUT_OF_SCOPE" {
		t.Errorf("expected ValidationStatus SKIPPED_OUT_OF_SCOPE, got: %s", ref.ValidationStatus)
	}
	if ref.StatusCode != 0 {
		t.Errorf("expected 0 StatusCode (no network probe executed), got: %d", ref.StatusCode)
	}
}
