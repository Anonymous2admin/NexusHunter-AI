package jsintel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
)

// Regex extractors for structural patterns in JavaScript.
var (
	// API routes and path references
	apiRouteRegex = regexp.MustCompile(`["'](/(?:api|v[0-9]+|graphql|rest|oauth|auth|admin|user|v1|v2|v3)[a-zA-Z0-9_\-\./?=&#]*)["']`)

	// Absolute and WebSocket URLs
	urlRegex = regexp.MustCompile(`["']((?:https?|wss?)://[a-zA-Z0-9.\-_]+(?::[0-9]+)?(?:/[a-zA-Z0-9_\-\./?=&#]*)?)["']`)

	// Cloud storage / CDN references
	cloudStorageRegex = regexp.MustCompile(`(?i)["'](?:https?://)?([a-zA-Z0-9.\-_]+\.(?:s3[a-zA-Z0-9.\-_]*\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com|cloudfront\.net|digitaloceanspaces\.com)[a-zA-Z0-9_\-\./?=&#]*)["']`)

	// Common configuration keys
	configKeyRegex = regexp.MustCompile(`\b([A-Z0-9_]{3,30}(?:_URL|_ENDPOINT|_BASE|_KEY|_TOKEN|_SECRET|_CONFIG))\s*[:=]\s*["']([^"']{1,256})["']`)

	// Potential secret indicators
	awsKeyRegex     = regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`)
	jwtTokenRegex   = regexp.MustCompile(`\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b`)
	genericKeyRegex = regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret[_-]?token|auth[_-]?token)\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,80})["']`)

	// UUID filter regex
	uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// JSAnalyzer parses JavaScript source code into structured references.
type JSAnalyzer struct{}

// NewJSAnalyzer creates an initialized JS analyzer.
func NewJSAnalyzer() *JSAnalyzer {
	return &JSAnalyzer{}
}

// Analyze extracts categorized structural references and secret indicators with complete redaction.
func (a *JSAnalyzer) Analyze(ctx context.Context, target *models.Target, jsAsset *models.JSAsset, content string, scopeSvc scope.ScopeService) ([]*models.JSReference, []*models.JSSecretIndicator, error) {
	references := make([]*models.JSReference, 0)
	secrets := make([]*models.JSSecretIndicator, 0)
	seenRefs := make(map[string]bool)
	seenSecrets := make(map[string]bool)

	lines := strings.Split(content, "\n")

	// 1. API Route references
	routeMatches := apiRouteRegex.FindAllStringSubmatchIndex(content, -1)
	for _, loc := range routeMatches {
		if len(loc) >= 4 {
			val := content[loc[2]:loc[3]]
			normVal := cleanExtractedRoute(val)
			if normVal == "" || seenRefs[normVal] {
				continue
			}
			seenRefs[normVal] = true

			lineNum, offset := calculateLineAndOffset(loc[2], content)
			ref := &models.JSReference{
				ID:              fmt.Sprintf("ref-%x", sha256.Sum256([]byte(jsAsset.ID+val)))[:16],
				TargetID:        target.ID,
				AssetID:         jsAsset.AssetID,
				JSAssetID:       jsAsset.ID,
				SourceURL:       jsAsset.URL,
				Category:        "API_ROUTE",
				ExtractedValue:  val,
				NormalizedValue: normVal,
				LineNumber:      lineNum,
				ByteOffset:      offset,
				SourceFragment:  safeFragment(content, loc[2], loc[3]),
				ScopeStatus:     "IN_SCOPE",
				Confidence:      "HIGH",
				ProvenanceSHA:   jsAsset.ContentSHA256,
				CreatedAt:       time.Now().UTC(),
			}
			references = append(references, ref)
		}
	}

	// 2. Absolute URL references
	urlMatches := urlRegex.FindAllStringSubmatchIndex(content, -1)
	for _, loc := range urlMatches {
		if len(loc) >= 4 {
			rawURL := content[loc[2]:loc[3]]
			if seenRefs[rawURL] {
				continue
			}
			seenRefs[rawURL] = true

			lineNum, offset := calculateLineAndOffset(loc[2], content)
			scopeStatus := "UNKNOWN"
			if u, err := url.Parse(rawURL); err == nil && scopeSvc != nil && target != nil {
				dec := scopeSvc.Evaluate(target, u.Hostname(), rawURL)
				if dec.InScope {
					scopeStatus = "IN_SCOPE"
				} else {
					scopeStatus = "OUT_OF_SCOPE"
				}
			}

			category := "URL"
			if isCloudReference(rawURL) {
				category = "CLOUD_REFERENCE"
			}

			ref := &models.JSReference{
				ID:              fmt.Sprintf("ref-%x", sha256.Sum256([]byte(jsAsset.ID+rawURL)))[:16],
				TargetID:        target.ID,
				AssetID:         jsAsset.AssetID,
				JSAssetID:       jsAsset.ID,
				SourceURL:       jsAsset.URL,
				Category:        category,
				ExtractedValue:  rawURL,
				NormalizedValue: rawURL,
				LineNumber:      lineNum,
				ByteOffset:      offset,
				SourceFragment:  safeFragment(content, loc[2], loc[3]),
				ScopeStatus:     scopeStatus,
				Confidence:      "HIGH",
				ProvenanceSHA:   jsAsset.ContentSHA256,
				CreatedAt:       time.Now().UTC(),
			}
			references = append(references, ref)

		}
	}

	// 3. Cloud reference discovery
	cloudMatches := cloudStorageRegex.FindAllStringSubmatchIndex(content, -1)
	for _, loc := range cloudMatches {
		if len(loc) >= 4 {
			val := content[loc[2]:loc[3]]
			if seenRefs[val] {
				continue
			}
			seenRefs[val] = true

			lineNum, offset := calculateLineAndOffset(loc[2], content)
			ref := &models.JSReference{
				ID:              fmt.Sprintf("ref-cloud-%x", sha256.Sum256([]byte(jsAsset.ID+val)))[:16],
				TargetID:        target.ID,
				AssetID:         jsAsset.AssetID,
				JSAssetID:       jsAsset.ID,
				SourceURL:       jsAsset.URL,
				Category:        "CLOUD_REFERENCE",
				ExtractedValue:  val,
				NormalizedValue: strings.ToLower(val),
				LineNumber:      lineNum,
				ByteOffset:      offset,
				SourceFragment:  safeFragment(content, loc[2], loc[3]),
				ScopeStatus:     "UNKNOWN",
				Confidence:      "HIGH",
				ProvenanceSHA:   jsAsset.ContentSHA256,
				CreatedAt:       time.Now().UTC(),
			}
			references = append(references, ref)
		}
	}

	// 4. Configuration references
	configMatches := configKeyRegex.FindAllStringSubmatchIndex(content, -1)
	for _, loc := range configMatches {
		if len(loc) >= 6 {
			key := content[loc[2]:loc[3]]
			val := content[loc[4]:loc[5]]
			comb := fmt.Sprintf("%s=%s", key, val)
			if seenRefs[comb] {
				continue
			}
			seenRefs[comb] = true

			lineNum, offset := calculateLineAndOffset(loc[2], content)
			ref := &models.JSReference{
				ID:              fmt.Sprintf("ref-cfg-%x", sha256.Sum256([]byte(jsAsset.ID+comb)))[:16],
				TargetID:        target.ID,
				AssetID:         jsAsset.AssetID,
				JSAssetID:       jsAsset.ID,
				SourceURL:       jsAsset.URL,
				Category:        "CONFIG_REFERENCE",
				ExtractedValue:  comb,
				NormalizedValue: key,
				LineNumber:      lineNum,
				ByteOffset:      offset,
				SourceFragment:  safeFragment(content, loc[2], loc[5]),
				ScopeStatus:     "IN_SCOPE",
				Confidence:      "MEDIUM",
				ProvenanceSHA:   jsAsset.ContentSHA256,
				CreatedAt:       time.Now().UTC(),
			}
			references = append(references, ref)
		}
	}

	// 5. Source Map references (OBSERVED category)
	sourceMapMatches := sourceMapRegex.FindAllStringSubmatchIndex(content, -1)
	for _, loc := range sourceMapMatches {
		var mapURL string
		var start, end int
		if len(loc) >= 4 && loc[2] != -1 && loc[3] != -1 {
			mapURL = content[loc[2]:loc[3]]
			start, end = loc[2], loc[3]
		} else if len(loc) >= 6 && loc[4] != -1 && loc[5] != -1 {
			mapURL = content[loc[4]:loc[5]]
			start, end = loc[4], loc[5]
		}
		if mapURL != "" && !seenRefs[mapURL] {
			seenRefs[mapURL] = true
			lineNum, offset := calculateLineAndOffset(start, content)
			ref := &models.JSReference{
				ID:              fmt.Sprintf("ref-map-%x", sha256.Sum256([]byte(jsAsset.ID+mapURL)))[:16],
				TargetID:        target.ID,
				AssetID:         jsAsset.AssetID,
				JSAssetID:       jsAsset.ID,
				SourceURL:       jsAsset.URL,
				Category:        "SOURCEMAP_REFERENCE",
				ExtractedValue:  mapURL,
				NormalizedValue: strings.TrimSpace(mapURL),
				LineNumber:      lineNum,
				ByteOffset:      offset,
				SourceFragment:  safeFragment(content, start, end),
				ScopeStatus:     "OBSERVED",
				Confidence:      "HIGH",
				ProvenanceSHA:   jsAsset.ContentSHA256,
				CreatedAt:       time.Now().UTC(),
			}
			references = append(references, ref)
		}
	}

	// 6. Secret Indicators (strictly REDACTED and false-positive filtered)
	detectSecrets := func(re *regexp.Regexp, secretType string, confidence string) {
		matches := re.FindAllStringSubmatchIndex(content, -1)
		for _, loc := range matches {
			if len(loc) >= 4 {
				rawSecret := content[loc[2]:loc[3]]
				if isFalsePositiveSecret(rawSecret) {
					continue
				}
				secHash := hex.EncodeToString(sha256Sum([]byte(rawSecret)))
				if seenSecrets[secHash] {
					continue
				}
				seenSecrets[secHash] = true

				lineNum, _ := calculateLineAndOffset(loc[2], content)
				preview := maskSecret(rawSecret)

				secrets = append(secrets, &models.JSSecretIndicator{
					ID:            fmt.Sprintf("sec-%s", secHash[:16]),
					TargetID:      target.ID,
					AssetID:       jsAsset.AssetID,
					JSAssetID:     jsAsset.ID,
					SecretType:    secretType,
					Location:      fmt.Sprintf("line %d", lineNum),
					MaskedPreview: preview,
					SHA256:        secHash,
					Confidence:    confidence,
					SourceJSAsset: jsAsset.URL,
					CreatedAt:     time.Now().UTC(),
				})
			}
		}
	}

	detectSecrets(awsKeyRegex, "LIKELY_SECRET:AWS_ACCESS_KEY", "HIGH")
	detectSecrets(jwtTokenRegex, "POTENTIAL_SECRET:JWT_BEARER_TOKEN", "MEDIUM")
	detectSecrets(genericKeyRegex, "UNVERIFIED_SECRET:GENERIC_API_KEY", "LOW")

	_ = lines
	return references, secrets, nil
}

func isFalsePositiveSecret(s string) bool {
	lower := strings.ToLower(s)
	indicators := []string{
		"example", "sample", "placeholder", "dummy", "test", "demo",
		"your_api_key", "your-api-key", "00000000", "123456", "deadbeef",
		"xxxx", "yyyy", "foobar",
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	if uuidRegex.MatchString(s) {
		return true
	}
	allSame := true
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			allSame = false
			break
		}
	}
	return allSame
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "********"
	}
	prefixLen := 4
	suffixLen := 3
	if len(s) < 12 {
		prefixLen = 2
		suffixLen = 2
	}
	return fmt.Sprintf("%s%s%s", s[:prefixLen], strings.Repeat("*", len(s)-(prefixLen+suffixLen)), s[len(s)-suffixLen:])
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func cleanExtractedRoute(route string) string {
	r := strings.TrimSpace(route)
	if idx := strings.Index(r, "?"); idx != -1 {
		r = r[:idx]
	}
	if idx := strings.Index(r, "#"); idx != -1 {
		r = r[:idx]
	}
	return r
}

func calculateLineAndOffset(offset int, fullText string) (int, int64) {
	if offset > len(fullText) {
		offset = len(fullText)
	}
	line := strings.Count(fullText[:offset], "\n") + 1
	return line, int64(offset)
}

func safeFragment(fullText string, start, end int) string {
	fragStart := start - 20
	if fragStart < 0 {
		fragStart = 0
	}
	fragEnd := end + 20
	if fragEnd > len(fullText) {
		fragEnd = len(fullText)
	}
	frag := strings.ReplaceAll(fullText[fragStart:fragEnd], "\n", " ")
	return strings.TrimSpace(frag)
}

func isCloudReference(u string) bool {
	lower := strings.ToLower(u)
	return strings.Contains(lower, "s3.amazonaws.com") ||
		strings.Contains(lower, "s3-") ||
		strings.Contains(lower, "blob.core.windows.net") ||
		strings.Contains(lower, "storage.googleapis.com") ||
		strings.Contains(lower, "cloudfront.net") ||
		strings.Contains(lower, "digitaloceanspaces.com")
}

