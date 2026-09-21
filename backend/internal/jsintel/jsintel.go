package jsintel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/safenet"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
)

var (
	ErrJSSizeExceeded       = errors.New("javascript resource exceeds maximum allowed file size")
	ErrJSTargetBudgetExceed = errors.New("maximum javascript asset limit exceeded for target")
	ErrJSOutOfScope         = errors.New("javascript resource origin is out of authorized scope")
)

// JSFetchLimits enforces strict resource bounds during collection.
type JSFetchLimits struct {
	MaxFileSizeBytes   int64
	MaxFilesPerTarget  int
	MaxConcurrent      int
	RequestTimeout     time.Duration
	AllowLocalFallback bool
}

// DefaultLimits provides fail-safe defaults for JS collection.
func DefaultLimits() JSFetchLimits {
	return JSFetchLimits{
		MaxFileSizeBytes:   5 * 1024 * 1024, // 5 MB cap
		MaxFilesPerTarget:  100,
		MaxConcurrent:      4,
		RequestTimeout:     10 * time.Second,
		AllowLocalFallback: false,
	}
}

// Service defines the JavaScript Asset Intelligence interface.
type Service interface {
	DiscoverScriptsFromHTML(ctx context.Context, target *models.Target, assetID string, parentURL string, htmlBody string) ([]*models.JSAsset, error)
	FetchAndAnalyze(ctx context.Context, target *models.Target, asset *models.JSAsset) ([]*models.JSReference, []*models.JSSecretIndicator, error)
	AnalyzeContent(ctx context.Context, target *models.Target, jsAsset *models.JSAsset, content string) ([]*models.JSReference, []*models.JSSecretIndicator, error)
}

type jsService struct {
	scopeSvc   scope.ScopeService
	limits     JSFetchLimits
	httpClient *http.Client
	analyzer   *JSAnalyzer
}

// NewService creates an initialized JS Intelligence service.
func NewService(scopeSvc scope.ScopeService, limits JSFetchLimits) Service {
	transport := safenet.NewSafeTransportWithConfig(limits.RequestTimeout, limits.AllowLocalFallback)
	return &jsService{
		scopeSvc: scopeSvc,
		limits:   limits,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   limits.RequestTimeout,
		},
		analyzer: NewJSAnalyzer(),
	}
}

// Regular expressions for script tags and source map discovery.
var (
	scriptSrcRegex = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"'>\s]+)["']`)
	sourceMapRegex = regexp.MustCompile(`(?i)//[#@]\s*sourceMappingURL\s*=\s*(\S+)`)
)

// DiscoverScriptsFromHTML extracts JavaScript references from authorized HTML responses.
func (s *jsService) DiscoverScriptsFromHTML(ctx context.Context, target *models.Target, assetID string, parentURL string, htmlBody string) ([]*models.JSAsset, error) {
	if target == nil {
		return nil, scope.ErrTargetNil
	}

	parentParsed, err := url.Parse(parentURL)
	if err != nil {
		return nil, fmt.Errorf("invalid parent URL: %w", err)
	}

	matches := scriptSrcRegex.FindAllStringSubmatch(htmlBody, -1)
	assets := make([]*models.JSAsset, 0, len(matches))
	seenURLs := make(map[string]bool)

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		rawSrc := strings.TrimSpace(m[1])
		if rawSrc == "" {
			continue
		}

		resolvedURL := resolveURL(parentParsed, rawSrc)
		if resolvedURL == "" || seenURLs[resolvedURL] {
			continue
		}
		seenURLs[resolvedURL] = true

		u, err := url.Parse(resolvedURL)
		if err != nil {
			continue
		}

		// Evaluate scope for JS asset
		decision := s.scopeSvc.Evaluate(target, u.Hostname(), resolvedURL)
		isThirdParty := !decision.InScope

		jsAsset := &models.JSAsset{
			ID:           fmt.Sprintf("js-%x", sha256.Sum256([]byte(resolvedURL)))[:16],
			TargetID:     target.ID,
			AssetID:      assetID,
			URL:          resolvedURL,
			ParentURL:    parentURL,
			DiscoveredAt: time.Now().UTC(),
			ScopeDecision: struct {
				InScope bool   `json:"in_scope"`
				Reason  string `json:"reason"`
			}{
				InScope: decision.InScope,
				Reason:  decision.Reason,
			},
			IsThirdParty: isThirdParty,
			FetchStatus:  "DISCOVERED",
			CreatedAt:    time.Now().UTC(),
		}

		if isThirdParty {
			jsAsset.FetchStatus = "SKIPPED_OUT_OF_SCOPE"
		}

		assets = append(assets, jsAsset)
	}

	return assets, nil
}

// FetchAndAnalyze safely fetches in-scope JavaScript and executes AST+Regex content extraction.
func (s *jsService) FetchAndAnalyze(ctx context.Context, target *models.Target, asset *models.JSAsset) ([]*models.JSReference, []*models.JSSecretIndicator, error) {
	if !asset.ScopeDecision.InScope {
		asset.FetchStatus = "SKIPPED_OUT_OF_SCOPE"
		return nil, nil, ErrJSOutOfScope
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		asset.FetchStatus = "FAILED"
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "NexusHunter-JSIntel/8.0 (Security Intelligence Research)")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		asset.FetchStatus = "FAILED"
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		asset.FetchStatus = "FAILED"
		return nil, nil, fmt.Errorf("HTTP status %d when fetching JS", resp.StatusCode)
	}

	// Limit reader to prevent memory exhaustion
	limitReader := io.LimitReader(resp.Body, s.limits.MaxFileSizeBytes+1)
	body, err := io.ReadAll(limitReader)
	if err != nil {
		asset.FetchStatus = "FAILED"
		return nil, nil, err
	}

	if int64(len(body)) > s.limits.MaxFileSizeBytes {
		asset.FetchStatus = "SIZE_EXCEEDED"
		return nil, nil, ErrJSSizeExceeded
	}

	h := sha256.Sum256(body)
	asset.ContentSHA256 = hex.EncodeToString(h[:])
	asset.ByteSize = int64(len(body))
	asset.FetchStatus = "FETCHED"
	asset.LineCount = strings.Count(string(body), "\n") + 1

	return s.AnalyzeContent(ctx, target, asset, string(body))
}

// AnalyzeContent executes structural parsing on JavaScript content.
func (s *jsService) AnalyzeContent(ctx context.Context, target *models.Target, jsAsset *models.JSAsset, content string) ([]*models.JSReference, []*models.JSSecretIndicator, error) {
	return s.analyzer.Analyze(ctx, target, jsAsset, content, s.scopeSvc)
}

func resolveURL(base *url.URL, ref string) string {
	parsedRef, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(parsedRef).String()
}
