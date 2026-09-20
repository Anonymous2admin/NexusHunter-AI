package recon

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

var (
	ErrEmptyInput    = errors.New("input string is empty")
	ErrInvalidScheme = errors.New("scheme must be http or https")
	ErrInvalidHost   = errors.New("hostname is invalid RFC 1123 or IP")
)

// hostnameRegex checks RFC 1123 compliant hostname labels.
var hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

// NormalizeHostname converts hostnames into canonical form:
// - strips whitespace
// - strips trailing dot (FQDN dot)
// - converts to lowercase
// - verifies RFC 1123 compliance or IP validity
func NormalizeHostname(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", ErrEmptyInput
	}

	// Remove trailing dots from root domain notation (e.g. "example.com.")
	trimmed = strings.TrimSuffix(trimmed, ".")
	lowered := strings.ToLower(trimmed)

	// If contains scheme, extract hostname
	if strings.HasPrefix(lowered, "http://") || strings.HasPrefix(lowered, "https://") {
		u, err := url.Parse(lowered)
		if err == nil && u.Hostname() != "" {
			lowered = u.Hostname()
		}
	}

	// If port is present, strip it for pure hostname normalization
	if host, _, err := net.SplitHostPort(lowered); err == nil {
		lowered = host
	}

	if lowered == "" || len(lowered) > 253 {
		return "", ErrInvalidHost
	}

	// Check if IP or valid hostname
	if ip := net.ParseIP(lowered); ip != nil {
		return lowered, nil
	}

	if !hostnameRegex.MatchString(lowered) {
		return "", fmt.Errorf("%w: '%s'", ErrInvalidHost, lowered)
	}

	return lowered, nil
}

// NormalizeURL canonicalizes a raw URL:
// - ensures http/https scheme (lowercase)
// - lowers hostname
// - removes default ports (:80 for http, :443 for https)
// - cleans path (deduplicates slashes, resolves . and .., preserves root /)
// - removes fragment (#section)
// - sorts query parameters deterministically without merging distinct resources
func NormalizeURL(rawURL string) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", ErrEmptyInput
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("failed to parse url: %w", err)
	}

	// 1. Normalize Scheme
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "" {
		// Default to https if omitted
		scheme = "https"
	}
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("%w: got '%s'", ErrInvalidScheme, scheme)
	}

	// 2. Normalize Host and Port
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", ErrInvalidHost
	}
	// Strip trailing dot
	host = strings.TrimSuffix(host, ".")

	port := parsed.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}

	var hostPort string
	if port != "" {
		hostPort = net.JoinHostPort(host, port)
	} else {
		hostPort = host
	}

	// 3. Normalize Path
	p := parsed.Path
	if p == "" {
		p = "/"
	} else {
		hasTrailingSlash := strings.HasSuffix(p, "/")
		p = path.Clean(p)
		if hasTrailingSlash && p != "/" && !strings.HasSuffix(p, "/") {
			p += "/"
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
	}

	// 4. Strip Fragment (never scan separate targets based purely on anchors)
	// (Fragment is ignored by omitting parsed.Fragment)

	// 5. Normalize Query Parameters deterministically
	var queryStr string
	if parsed.RawQuery != "" {
		values, err := url.ParseQuery(parsed.RawQuery)
		if err == nil && len(values) > 0 {
			keys := make([]string, 0, len(values))
			for k := range values {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			var qParts []string
			for _, k := range keys {
				vals := values[k]
				sort.Strings(vals)
				for _, v := range vals {
					qParts = append(qParts, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(v)))
				}
			}
			queryStr = strings.Join(qParts, "&")
		}
	}

	// Construct canonical URL
	var b strings.Builder
	b.WriteString(scheme)
	b.WriteString("://")
	b.WriteString(hostPort)
	b.WriteString(p)
	if queryStr != "" {
		b.WriteString("?")
		b.WriteString(queryStr)
	}

	return b.String(), nil
}

// ExtractHostnameFromURL returns the clean lowercase hostname from a raw URL.
func ExtractHostnameFromURL(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", err
	}
	h := strings.ToLower(u.Hostname())
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", ErrInvalidHost
	}
	return h, nil
}
