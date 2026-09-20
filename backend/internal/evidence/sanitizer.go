package evidence

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

var (
	sensitiveHeaderKeys = map[string]bool{
		"authorization":       true,
		"proxy-authorization": true,
		"cookie":              true,
		"set-cookie":          true,
		"x-api-key":           true,
		"x-auth-token":        true,
		"x-csrf-token":        true,
		"x-xsrf-token":        true,
		"x-session-id":        true,
		"x-token":             true,
		"x-secret":            true,
		"api-key":             true,
		"apikey":              true,
		"token":               true,
		"secret":              true,
		"session":             true,
	}

	sensitiveQueryKeys = map[string]bool{
		"token":         true,
		"access_token":  true,
		"auth":          true,
		"key":           true,
		"api_key":       true,
		"apikey":        true,
		"secret":        true,
		"client_secret": true,
		"password":      true,
		"pwd":           true,
		"session":       true,
		"session_id":    true,
		"jwt":           true,
	}

	jwtRegex    = regexp.MustCompile(`eyJh[a-zA-Z0-9_-]+\.eyJh[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`)
	bearerRegex = regexp.MustCompile(`(?i)Bearer\s+([a-zA-Z0-9._~+/-]+=*)`)
	apiKeyRegex = regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password|auth)["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]{12,})["']?`)
)

// Sanitizer provides a centralized, reusable security boundary for redacting sensitive credentials.
type Sanitizer struct{}

// NewSanitizer constructs an evidence sanitizer.
func NewSanitizer() *Sanitizer {
	return &Sanitizer{}
}

// Sanitize deep-copies and redacts sensitive credentials from the evidence object.
// Returns the sanitized evidence and records the redaction status.
func (s *Sanitizer) Sanitize(ev *models.Evidence) *models.Evidence {
	if ev == nil {
		return nil
	}

	// Create a shallow copy first
	sanitized := *ev
	var redactedFields []string

	// 1. Sanitize Request
	if ev.Request != nil {
		reqCopy := *ev.Request
		reqCopy.Headers, redactedFields = s.sanitizeHeaders(ev.Request.Headers, "request.headers", redactedFields)
		reqCopy.URL, redactedFields = s.sanitizeURL(ev.Request.URL, "request.url", redactedFields)
		reqCopy.BodySummary, redactedFields = s.sanitizeBody(ev.Request.BodySummary, "request.body", redactedFields)
		sanitized.Request = &reqCopy
	}

	// 2. Sanitize Response
	if ev.Response != nil {
		respCopy := *ev.Response
		respCopy.Headers, redactedFields = s.sanitizeHeaders(ev.Response.Headers, "response.headers", redactedFields)
		respCopy.BodySnippet, redactedFields = s.sanitizeBody(ev.Response.BodySnippet, "response.body", redactedFields)
		sanitized.Response = &respCopy
	}

	// 3. Sanitize RelevantHeaders
	if len(ev.RelevantHeaders) > 0 {
		var rhRedacted []string
		sanitized.RelevantHeaders, rhRedacted = s.sanitizeHeaders(ev.RelevantHeaders, "relevant_headers", nil)
		redactedFields = append(redactedFields, rhRedacted...)
	}

	// 4. Sanitize RedirectChain
	if len(ev.RedirectChain) > 0 {
		chainCopy := make([]string, len(ev.RedirectChain))
		for i, redURL := range ev.RedirectChain {
			var red []string
			chainCopy[i], red = s.sanitizeURL(redURL, fmt.Sprintf("redirect_chain[%d]", i), nil)
			redactedFields = append(redactedFields, red...)
		}
		sanitized.RedirectChain = chainCopy
	}

	// 5. Populate RedactionStatus
	sanitized.RedactionStatus = models.RedactionStatusRecord{
		IsRedacted:     len(redactedFields) > 0,
		RedactedFields: deduplicateStrings(redactedFields),
		SanitizedAt:    time.Now().UTC(),
	}

	return &sanitized
}

func (s *Sanitizer) sanitizeHeaders(headers map[string]string, prefix string, currentRedacted []string) (map[string]string, []string) {
	if len(headers) == 0 {
		return headers, currentRedacted
	}

	sanitized := make(map[string]string, len(headers))
	redacted := append([]string{}, currentRedacted...)

	for k, v := range headers {
		lowerK := strings.ToLower(strings.TrimSpace(k))
		if sensitiveHeaderKeys[lowerK] {
			redacted = append(redacted, fmt.Sprintf("%s.%s", prefix, k))
			sanitized[k] = s.maskValue(lowerK, v)
			continue
		}

		// Also check if the header value contains a JWT or Bearer token
		if bearerRegex.MatchString(v) {
			redacted = append(redacted, fmt.Sprintf("%s.%s", prefix, k))
			sanitized[k] = bearerRegex.ReplaceAllString(v, "Bearer [REDACTED]")
			continue
		}

		if jwtRegex.MatchString(v) {
			redacted = append(redacted, fmt.Sprintf("%s.%s", prefix, k))
			sanitized[k] = jwtRegex.ReplaceAllString(v, "[REDACTED_JWT]")
			continue
		}

		sanitized[k] = v
	}

	return sanitized, redacted
}

func (s *Sanitizer) sanitizeURL(rawURL string, prefix string, currentRedacted []string) (string, []string) {
	if rawURL == "" {
		return rawURL, currentRedacted
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		// If unparseable, perform regex mask
		return rawURL, currentRedacted
	}

	redacted := append([]string{}, currentRedacted...)
	query := parsed.Query()
	changed := false

	for qk := range query {
		if sensitiveQueryKeys[strings.ToLower(qk)] {
			query.Set(qk, "[REDACTED]")
			redacted = append(redacted, fmt.Sprintf("%s?%s", prefix, qk))
			changed = true
		}
	}

	if changed {
		parsed.RawQuery = query.Encode()
		return parsed.String(), redacted
	}

	return rawURL, currentRedacted
}

func (s *Sanitizer) sanitizeBody(body string, prefix string, currentRedacted []string) (string, []string) {
	if body == "" {
		return body, currentRedacted
	}

	redacted := append([]string{}, currentRedacted...)
	modifiedBody := body

	// If valid JSON, redact sensitive fields structurally
	var jsonMap map[string]interface{}
	if err := json.Unmarshal([]byte(body), &jsonMap); err == nil {
		modifiedMap, subRedacted := s.sanitizeJSONMap(jsonMap, prefix)
		if len(subRedacted) > 0 {
			redacted = append(redacted, subRedacted...)
			if marshaled, err := json.Marshal(modifiedMap); err == nil {
				return string(marshaled), redacted
			}
		}
	}

	// Perform regex-based redaction on plain text or snippet
	if jwtRegex.MatchString(modifiedBody) {
		redacted = append(redacted, prefix+".jwt")
		modifiedBody = jwtRegex.ReplaceAllString(modifiedBody, "[REDACTED_JWT]")
	}

	if bearerRegex.MatchString(modifiedBody) {
		redacted = append(redacted, prefix+".bearer")
		modifiedBody = bearerRegex.ReplaceAllString(modifiedBody, "Bearer [REDACTED]")
	}

	if apiKeyRegex.MatchString(modifiedBody) {
		redacted = append(redacted, prefix+".secret_pattern")
		modifiedBody = apiKeyRegex.ReplaceAllString(modifiedBody, `$1: "[REDACTED]"`)
	}

	return modifiedBody, redacted
}

func (s *Sanitizer) sanitizeJSONMap(m map[string]interface{}, prefix string) (map[string]interface{}, []string) {
	result := make(map[string]interface{}, len(m))
	var redacted []string

	for k, v := range m {
		lowerK := strings.ToLower(k)
		path := fmt.Sprintf("%s.%s", prefix, k)

		if sensitiveQueryKeys[lowerK] || sensitiveHeaderKeys[lowerK] {
			result[k] = "[REDACTED]"
			redacted = append(redacted, path)
			continue
		}

		switch val := v.(type) {
		case map[string]interface{}:
			subMap, subRedacted := s.sanitizeJSONMap(val, path)
			result[k] = subMap
			redacted = append(redacted, subRedacted...)
		case []interface{}:
			subSlice, subRedacted := s.sanitizeJSONSlice(val, path)
			result[k] = subSlice
			redacted = append(redacted, subRedacted...)
		case string:
			if jwtRegex.MatchString(val) {
				result[k] = "[REDACTED_JWT]"
				redacted = append(redacted, path)
			} else if bearerRegex.MatchString(val) {
				result[k] = "Bearer [REDACTED]"
				redacted = append(redacted, path)
			} else {
				result[k] = val
			}
		default:
			result[k] = v
		}
	}

	return result, redacted
}

func (s *Sanitizer) sanitizeJSONSlice(slice []interface{}, prefix string) ([]interface{}, []string) {
	result := make([]interface{}, len(slice))
	var redacted []string

	for i, v := range slice {
		path := fmt.Sprintf("%s[%d]", prefix, i)
		switch val := v.(type) {
		case map[string]interface{}:
			subMap, subRedacted := s.sanitizeJSONMap(val, path)
			result[i] = subMap
			redacted = append(redacted, subRedacted...)
		case string:
			if jwtRegex.MatchString(val) {
				result[i] = "[REDACTED_JWT]"
				redacted = append(redacted, path)
			} else {
				result[i] = val
			}
		default:
			result[i] = v
		}
	}

	return result, redacted
}

func (s *Sanitizer) maskValue(key, val string) string {
	if strings.Contains(key, "cookie") {
		// Redact cookie assignments e.g. session=abc12345; user=admin -> session=[REDACTED]; user=admin
		parts := strings.Split(val, ";")
		for i, part := range parts {
			trimmed := strings.TrimSpace(part)
			kv := strings.SplitN(trimmed, "=", 2)
			if len(kv) == 2 {
				cookieName := strings.ToLower(strings.TrimSpace(kv[0]))
				if sensitiveQueryKeys[cookieName] || strings.Contains(cookieName, "sess") || strings.Contains(cookieName, "auth") || strings.Contains(cookieName, "token") {
					parts[i] = fmt.Sprintf("%s=[REDACTED]", kv[0])
				}
			}
		}
		return strings.Join(parts, "; ")
	}

	if strings.HasPrefix(strings.ToLower(val), "bearer ") {
		return "Bearer [REDACTED]"
	}

	return "[REDACTED]"
}

func deduplicateStrings(items []string) []string {
	if len(items) == 0 {
		return []string{}
	}
	seen := make(map[string]bool, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
