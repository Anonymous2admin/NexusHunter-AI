package cloudintel

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/safenet"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
)

// Provider definitions and regex patterns.
var (
	awsS3Regex       = regexp.MustCompile(`(?i)(?:https?://)?([a-z0-9.\-_]+)\.s3(?:[a-z0-9.\-_]*)\.amazonaws\.com`)
	awsS3PathRegex   = regexp.MustCompile(`(?i)(?:https?://)?s3(?:[a-z0-9.\-_]*)\.amazonaws\.com/([a-z0-9.\-_]+)`)
	awsCloudFrontReg = regexp.MustCompile(`(?i)(?:https?://)?([a-z0-9]+)\.cloudfront\.net`)
	azureBlobRegex   = regexp.MustCompile(`(?i)(?:https?://)?([a-z0-9]+)\.blob\.core\.windows\.net(?:/([a-z0-9\-_]+))?`)
	gcpStorageRegex  = regexp.MustCompile(`(?i)(?:https?://)?storage\.googleapis\.com/([a-z0-9.\-_]+)`)
	digitalOceanReg  = regexp.MustCompile(`(?i)(?:https?://)?([a-z0-9.\-_]+)\.([a-z0-9]+)\.digitaloceanspaces\.com`)
)

// Service defines Cloud Reference Intelligence capabilities.
type Service interface {
	ExtractCloudReferences(ctx context.Context, target *models.Target, assetID string, origin string, location string, text string) ([]*models.CloudReference, error)
	ProbeSafePublicStatus(ctx context.Context, target *models.Target, ref *models.CloudReference) error
}

type cloudService struct {
	scopeSvc   scope.ScopeService
	httpClient *http.Client
}

// NewService creates an initialized Cloud Reference Intelligence service.
func NewService(scopeSvc scope.ScopeService, timeout time.Duration) Service {
	transport := safenet.NewSafeTransportWithConfig(timeout, false)
	return &cloudService{
		scopeSvc: scopeSvc,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
	}
}

// ExtractCloudReferences passively detects cloud infrastructure identifiers in arbitrary content.
func (s *cloudService) ExtractCloudReferences(ctx context.Context, target *models.Target, assetID string, origin string, location string, text string) ([]*models.CloudReference, error) {
	if target == nil {
		return nil, scope.ErrTargetNil
	}

	results := make([]*models.CloudReference, 0)
	seen := make(map[string]bool)

	addRef := func(provider, resourceType, raw, normalized string) {
		key := fmt.Sprintf("%s:%s", provider, normalized)
		if seen[key] || normalized == "" {
			return
		}
		seen[key] = true

		scopeStatus := "UNKNOWN"
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			dec := s.scopeSvc.Evaluate(target, u.Hostname(), raw)
			if dec.InScope {
				scopeStatus = "IN_SCOPE"
			} else {
				scopeStatus = "OUT_OF_SCOPE"
			}
		}

		ref := &models.CloudReference{
			ID:               fmt.Sprintf("cld-%x", sha256.Sum256([]byte(target.ID+origin+key)))[:16],
			TargetID:         target.ID,
			AssetID:          assetID,
			Provider:         provider,
			ResourceType:     resourceType,
			RawReference:     raw,
			NormalizedTarget: normalized,
			SourceOrigin:     origin,
			SourceLocation:   location,
			ScopeStatus:      scopeStatus,
			ValidationStatus: "UNCHECKED",
			CreatedAt:        time.Now().UTC(),
		}
		results = append(results, ref)
	}

	// 1. AWS S3 Subdomain
	for _, m := range awsS3Regex.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			addRef("AWS", "S3_BUCKET", m[0], strings.ToLower(m[1]))
		}
	}
	// 2. AWS S3 Path style
	for _, m := range awsS3PathRegex.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			addRef("AWS", "S3_BUCKET", m[0], strings.ToLower(m[1]))
		}
	}
	// 3. AWS CloudFront
	for _, m := range awsCloudFrontReg.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			addRef("AWS", "CLOUDFRONT", m[0], strings.ToLower(m[1]))
		}
	}
	// 4. Azure Blob
	for _, m := range azureBlobRegex.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			addRef("AZURE", "BLOB_CONTAINER", m[0], strings.ToLower(m[1]))
		}
	}
	// 5. GCP Storage
	for _, m := range gcpStorageRegex.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			addRef("GCP", "GCS_BUCKET", m[0], strings.ToLower(m[1]))
		}
	}
	// 6. DigitalOcean Spaces
	for _, m := range digitalOceanReg.FindAllStringSubmatch(text, -1) {
		if len(m) > 1 {
			addRef("DIGITALOCEAN", "DO_SPACE", m[0], strings.ToLower(m[1]))
		}
	}

	return results, nil
}

// ProbeSafePublicStatus conducts a non-destructive, safe GET/HEAD probe on a verified public cloud resource.
// Destructive writes, credential stuffing, and brute force are STRICTLY FORBIDDEN.
func (s *cloudService) ProbeSafePublicStatus(ctx context.Context, target *models.Target, ref *models.CloudReference) error {
	var probeURL string
	if strings.HasPrefix(ref.RawReference, "http://") || strings.HasPrefix(ref.RawReference, "https://") {
		probeURL = ref.RawReference
	} else {
		switch ref.Provider {
		case "AWS":
			if ref.ResourceType == "S3_BUCKET" {
				probeURL = fmt.Sprintf("https://%s.s3.amazonaws.com", ref.NormalizedTarget)
			}
		case "GCP":
			if ref.ResourceType == "GCS_BUCKET" {
				probeURL = fmt.Sprintf("https://storage.googleapis.com/%s", ref.NormalizedTarget)
			}
		case "AZURE":
			if ref.ResourceType == "BLOB_CONTAINER" {
				probeURL = fmt.Sprintf("https://%s.blob.core.windows.net", ref.NormalizedTarget)
			}
		}
	}

	if probeURL == "" {
		ref.ValidationStatus = "UNCHECKED"
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, probeURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "NexusHunter-CloudIntel/8.0 (Security Intelligence Research)")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		ref.ValidationStatus = "SAFE_PROBED"
		return nil
	}
	defer resp.Body.Close()

	ref.StatusCode = resp.StatusCode
	ref.ValidationStatus = "SAFE_PROBED"
	if resp.StatusCode == http.StatusOK {
		ref.PublicAccessible = true
		ref.ValidationStatus = "VERIFIED_PUBLIC"
	} else if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		ref.PublicAccessible = false
		ref.ValidationStatus = "VERIFIED_PRIVATE"
	}

	return nil
}
