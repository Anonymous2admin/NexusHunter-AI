package recon

import (
	"bufio"
	"context"
	"encoding/xml"
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

// Regex patterns for HTML attribute link extraction
var (
	hrefRegex   = regexp.MustCompile(`(?i)\bhref\s*=\s*["']([^"'>\s]+)["']`)
	srcRegex    = regexp.MustCompile(`(?i)\bsrc\s*=\s*["']([^"'>\s]+)["']`)
	actionRegex = regexp.MustCompile(`(?i)\baction\s*=\s*["']([^"'>\s]+)["']`)
	urlTextRegex = regexp.MustCompile(`https?://[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s"'<>]*)?`)
)

// Crawler crawls web endpoints up to a configured depth and limit per host, strictly enforcing scope.
type Crawler struct {
	config     EngineConfig
	scopeSvc   scope.ScopeService
	httpClient *http.Client
}

// NewCrawler creates an initialized Crawler instance with safe transport.
func NewCrawler(cfg EngineConfig, scopeSvc scope.ScopeService) *Crawler {
	transport := safenet.NewSafeTransportWithConfig(cfg.RequestTimeout, cfg.AllowLocalAddresses)
	return &Crawler{
		config:   cfg,
		scopeSvc: scopeSvc,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   cfg.RequestTimeout,
		},
	}
}

// getScopedClient constructs an HTTP client that validates scope and SSRF boundaries across all redirects.
func (c *Crawler) getScopedClient(target *models.Target, onSkip func(SkipEvent)) *http.Client {
	transport := safenet.NewSafeTransportWithConfig(c.config.RequestTimeout, c.config.AllowLocalAddresses)
	return &http.Client{
		Transport: transport,
		Timeout:   c.config.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= c.config.MaxRedirects {
				return ErrMaxRedirects
			}

			// 1. SSRF boundary enforcement on redirect host
			if !c.config.AllowLocalAddresses {
				if restricted, reason := safenet.IsRestrictedHost(req.Context(), req.URL.Hostname()); restricted {
					if onSkip != nil {
						onSkip(SkipEvent{
							Item:      req.URL.String(),
							TargetID:  target.ID,
							Reason:    fmt.Sprintf("SSRF_VIOLATION: redirect targets %s", reason),
							Stage:     "CRAWLER_REDIRECT",
							Timestamp: time.Now().UTC(),
						})
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
			decision := c.scopeSvc.Evaluate(target, redirectHost, req.URL.String())
			if !decision.InScope {
				if onSkip != nil {
					onSkip(SkipEvent{
						Item:      req.URL.String(),
						TargetID:  target.ID,
						Reason:    fmt.Sprintf("Redirect destination out of scope: %s", decision.Reason),
						Stage:     "CRAWLER_REDIRECT",
						Timestamp: time.Now().UTC(),
					})
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

			return nil
		},
	}
}

// CrawlSeed initiates crawling of an asset from a seed URL.
// It parses robots.txt, sitemap.xml, and crawls HTML links up to MaxDepth.
func (c *Crawler) CrawlSeed(ctx context.Context, target *models.Target, assetID, seedURL string, dedup *Deduplicator, onURL func(CrawledURL), onSkip func(SkipEvent)) error {
	baseParsed, err := url.Parse(seedURL)
	if err != nil {
		return err
	}
	host := baseParsed.Hostname()

	// 1. Fetch and parse robots.txt
	robotsURL := fmt.Sprintf("%s://%s/robots.txt", baseParsed.Scheme, baseParsed.Host)
	c.crawlRobotsTXT(ctx, target, assetID, host, robotsURL, dedup, onURL, onSkip)

	// 2. Fetch and parse sitemap.xml
	sitemapURL := fmt.Sprintf("%s://%s/sitemap.xml", baseParsed.Scheme, baseParsed.Host)
	c.crawlSitemapXML(ctx, target, assetID, host, sitemapURL, dedup, onURL, onSkip)

	// 3. BFS crawl queue
	type queueItem struct {
		rawURL string
		depth  int
	}

	queue := []queueItem{{rawURL: seedURL, depth: 0}}
	hostURLCount := 0

	for len(queue) > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if hostURLCount >= c.config.MaxURLsPerHost {
			break
		}

		item := queue[0]
		queue = queue[1:]

		normURL, err := NormalizeURL(item.rawURL)
		if err != nil {
			continue
		}

		itemHost, err := ExtractHostnameFromURL(normURL)
		if err != nil {
			continue
		}

		// Scope Validation
		decision := c.scopeSvc.Evaluate(target, itemHost, normURL)
		if !decision.InScope {
			onSkip(SkipEvent{
				Item:      normURL,
				TargetID:  target.ID,
				Reason:    decision.Reason,
				Stage:     "CRAWLER",
				Timestamp: time.Now().UTC(),
			})
			continue
		}

		if !dedup.CheckAndAddURL(normURL) {
			continue
		}

		hostURLCount++
		onURL(CrawledURL{
			AssetID:   assetID,
			Hostname:  itemHost,
			URL:       normURL,
			Source:    "CRAWLER",
			Depth:     item.depth,
			Timestamp: time.Now().UTC(),
		})

		// If depth limit reached, do not fetch children
		if item.depth >= c.config.MaxDepth {
			continue
		}

		// Fetch page body to discover links
		links := c.fetchAndExtractLinks(ctx, target, normURL, onSkip)
		for _, link := range links {
			queue = append(queue, queueItem{
				rawURL: link,
				depth:  item.depth + 1,
			})
		}
	}

	return nil
}

func (c *Crawler) fetchAndExtractLinks(ctx context.Context, target *models.Target, pageURL string, onSkip func(SkipEvent)) []string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", c.config.UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	client := c.getScopedClient(target, onSkip)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(contentType, "text/html") && !strings.Contains(contentType, "application/xhtml") {
		return nil
	}

	limitReader := io.LimitReader(resp.Body, c.config.MaxResponseBody)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return nil
	}

	return c.extractLinks(string(bodyBytes), pageURL)
}

func (c *Crawler) extractLinks(htmlContent, baseURL string) []string {
	baseParsed, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	var rawCandidates []string

	for _, m := range hrefRegex.FindAllStringSubmatch(htmlContent, -1) {
		if len(m) > 1 {
			rawCandidates = append(rawCandidates, m[1])
		}
	}
	for _, m := range srcRegex.FindAllStringSubmatch(htmlContent, -1) {
		if len(m) > 1 {
			rawCandidates = append(rawCandidates, m[1])
		}
	}
	for _, m := range actionRegex.FindAllStringSubmatch(htmlContent, -1) {
		if len(m) > 1 {
			rawCandidates = append(rawCandidates, m[1])
		}
	}

	resolved := make([]string, 0, len(rawCandidates))
	for _, cand := range rawCandidates {
		cand = strings.TrimSpace(cand)
		if cand == "" || strings.HasPrefix(cand, "#") || strings.HasPrefix(cand, "javascript:") || strings.HasPrefix(cand, "mailto:") || strings.HasPrefix(cand, "tel:") {
			continue
		}

		u, err := url.Parse(cand)
		if err != nil {
			continue
		}

		absURL := baseParsed.ResolveReference(u).String()
		resolved = append(resolved, absURL)
	}

	return resolved
}

func (c *Crawler) crawlRobotsTXT(ctx context.Context, target *models.Target, assetID, host, robotsURL string, dedup *Deduplicator, onURL func(CrawledURL), onSkip func(SkipEvent)) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, robotsURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", c.config.UserAgent)

	client := c.getScopedClient(target, onSkip)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 1024*1024))
	baseParsed, _ := url.Parse(robotsURL)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}

		var pathStr string
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			pathStr = strings.TrimSpace(line[9:])
		} else if strings.HasPrefix(strings.ToLower(line), "allow:") {
			pathStr = strings.TrimSpace(line[6:])
		} else if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
			sitemapURL := strings.TrimSpace(line[8:])
			c.crawlSitemapXML(ctx, target, assetID, host, sitemapURL, dedup, onURL, onSkip)
			continue
		}

		if pathStr == "" || pathStr == "/" || strings.Contains(pathStr, "*") {
			continue
		}

		u, err := url.Parse(pathStr)
		if err != nil {
			continue
		}
		absURL := baseParsed.ResolveReference(u).String()

		normURL, err := NormalizeURL(absURL)
		if err != nil {
			continue
		}

		h, err := ExtractHostnameFromURL(normURL)
		if err != nil {
			continue
		}

		decision := c.scopeSvc.Evaluate(target, h, normURL)
		if !decision.InScope {
			onSkip(SkipEvent{
				Item:      normURL,
				TargetID:  target.ID,
				Reason:    decision.Reason,
				Stage:     "ROBOTS",
				Timestamp: time.Now().UTC(),
			})
			continue
		}

		if dedup.CheckAndAddURL(normURL) {
			onURL(CrawledURL{
				AssetID:   assetID,
				Hostname:  h,
				URL:       normURL,
				Source:    "ROBOTS",
				Depth:     1,
				Timestamp: time.Now().UTC(),
			})
		}
	}
}

func (c *Crawler) crawlSitemapXML(ctx context.Context, target *models.Target, assetID, host, sitemapURL string, dedup *Deduplicator, onURL func(CrawledURL), onSkip func(SkipEvent)) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sitemapURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", c.config.UserAgent)

	client := c.getScopedClient(target, onSkip)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		return
	}
	defer resp.Body.Close()

	type URLTag struct {
		Loc string `xml:"loc"`
	}
	type URLSet struct {
		URLs []URLTag `xml:"url"`
	}

	decoder := xml.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024))
	var urlset URLSet
	if err := decoder.Decode(&urlset); err != nil {
		return
	}

	for _, entry := range urlset.URLs {
		rawLoc := strings.TrimSpace(entry.Loc)
		if rawLoc == "" {
			continue
		}

		normURL, err := NormalizeURL(rawLoc)
		if err != nil {
			continue
		}

		h, err := ExtractHostnameFromURL(normURL)
		if err != nil {
			continue
		}

		decision := c.scopeSvc.Evaluate(target, h, normURL)
		if !decision.InScope {
			onSkip(SkipEvent{
				Item:      normURL,
				TargetID:  target.ID,
				Reason:    decision.Reason,
				Stage:     "SITEMAP",
				Timestamp: time.Now().UTC(),
			})
			continue
		}

		if dedup.CheckAndAddURL(normURL) {
			onURL(CrawledURL{
				AssetID:   assetID,
				Hostname:  h,
				URL:       normURL,
				Source:    "SITEMAP",
				Depth:     1,
				Timestamp: time.Now().UTC(),
			})
		}
	}
}
