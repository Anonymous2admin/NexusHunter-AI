package intel

import (
	"fmt"
	"strings"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// EvaluateSecurityObservations analyzes response headers and cookies to passively record security properties.
// IMPORTANT: These are purely passive security property observations and are NOT classified as vulnerabilities.
func EvaluateSecurityObservations(assetID, targetID, serviceID, scheme string, headers map[string]string, cookies []string) []*models.SecurityObservation {
	var observations []*models.SecurityObservation
	now := time.Now().UTC()

	addObs := func(propName string, isPresent bool, details, raw string) {
		observations = append(observations, &models.SecurityObservation{
			ID:           newID("sec"),
			AssetID:      assetID,
			TargetID:     targetID,
			ServiceID:    serviceID,
			PropertyName: propName,
			IsPresent:    isPresent,
			Details:      details,
			RawValue:     raw,
			ObservedAt:   now,
		})
	}

	// 1. Strict-Transport-Security (HSTS) - relevant for HTTPS
	if strings.EqualFold(scheme, "https") {
		if val, ok := FindHeaderCaseInsensitive(headers, "Strict-Transport-Security"); ok && strings.TrimSpace(val) != "" {
			addObs("Strict-Transport-Security", true, fmt.Sprintf("HSTS header observed: %s", val), val)
		} else {
			addObs("Strict-Transport-Security", false, "HSTS header not observed on HTTPS service (informational observation)", "")
		}
	}

	// 2. Content-Security-Policy (CSP)
	if val, ok := FindHeaderCaseInsensitive(headers, "Content-Security-Policy"); ok && strings.TrimSpace(val) != "" {
		addObs("Content-Security-Policy", true, fmt.Sprintf("CSP policy observed (%d bytes)", len(val)), val)
	} else {
		addObs("Content-Security-Policy", false, "Content-Security-Policy header not observed (informational observation)", "")
	}

	// 3. X-Content-Type-Options
	if val, ok := FindHeaderCaseInsensitive(headers, "X-Content-Type-Options"); ok && strings.TrimSpace(val) != "" {
		addObs("X-Content-Type-Options", true, fmt.Sprintf("Observed: %s", val), val)
	} else {
		addObs("X-Content-Type-Options", false, "X-Content-Type-Options header not observed (informational observation)", "")
	}

	// 4. X-Frame-Options
	if val, ok := FindHeaderCaseInsensitive(headers, "X-Frame-Options"); ok && strings.TrimSpace(val) != "" {
		addObs("X-Frame-Options", true, fmt.Sprintf("Observed: %s", val), val)
	} else {
		addObs("X-Frame-Options", false, "X-Frame-Options header not observed (informational observation)", "")
	}

	// 5. Referrer-Policy
	if val, ok := FindHeaderCaseInsensitive(headers, "Referrer-Policy"); ok && strings.TrimSpace(val) != "" {
		addObs("Referrer-Policy", true, fmt.Sprintf("Observed: %s", val), val)
	} else {
		addObs("Referrer-Policy", false, "Referrer-Policy header not observed (informational observation)", "")
	}

	// 6. Permissions-Policy
	if val, ok := FindHeaderCaseInsensitive(headers, "Permissions-Policy"); ok && strings.TrimSpace(val) != "" {
		addObs("Permissions-Policy", true, fmt.Sprintf("Observed: %s", val), val)
	} else {
		addObs("Permissions-Policy", false, "Permissions-Policy header not observed (informational observation)", "")
	}

	// 7. Cookie Security Flags
	parsedCookies := ParseCookies(cookies)
	if len(parsedCookies) > 0 {
		secureCount := 0
		httpOnlyCount := 0
		sameSiteCount := 0
		for _, c := range parsedCookies {
			if c.Secure {
				secureCount++
			}
			if c.HttpOnly {
				httpOnlyCount++
			}
			if c.SameSite != "None" && c.SameSite != "Unknown" {
				sameSiteCount++
			}
		}

		cookiesDetail := fmt.Sprintf("%d total cookies. Secure: %d/%d, HttpOnly: %d/%d, SameSite: %d/%d",
			len(parsedCookies), secureCount, len(parsedCookies), httpOnlyCount, len(parsedCookies), sameSiteCount, len(parsedCookies))

		allSecure := secureCount == len(parsedCookies)
		addObs("Cookie-Security-Flags", allSecure, cookiesDetail, fmt.Sprintf("total=%d;secure=%d;httponly=%d;samesite=%d", len(parsedCookies), secureCount, httpOnlyCount, sameSiteCount))
	}

	return observations
}
