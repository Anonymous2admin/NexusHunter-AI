package intel

import (
	"strings"
)

// FindHeaderCaseInsensitive searches for a header key without case sensitivity.
func FindHeaderCaseInsensitive(headers map[string]string, targetKey string) (string, bool) {
	for k, v := range headers {
		if strings.EqualFold(k, targetKey) {
			return v, true
		}
	}
	return "", false
}

// ExtractHeadersSummary parses the response headers into a normalized key-value map.
func ExtractHeadersSummary(headers map[string]string) map[string]string {
	normalized := make(map[string]string)
	for k, v := range headers {
		normalized[strings.ToLower(k)] = v
	}
	return normalized
}
