package intel

import (
	"strings"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// InferAssetTags evaluates an asset's hostname and services to infer operational categories.
func InferAssetTags(assetID, targetID, hostname string, ports []int) []*models.AssetTag {
	lowerHost := strings.ToLower(hostname)
	tagSet := make(map[string]bool)
	now := time.Now().UTC()

	// 1. Hostname prefix/infix heuristics
	parts := strings.Split(lowerHost, ".")
	first := ""
	if len(parts) > 0 {
		first = parts[0]
	}

	switch {
	case strings.HasPrefix(first, "api") || strings.Contains(lowerHost, "-api.") || strings.Contains(lowerHost, ".api."):
		tagSet["api"] = true
	case strings.HasPrefix(first, "dev") || strings.HasPrefix(first, "stage") || strings.HasPrefix(first, "staging") ||
		strings.HasPrefix(first, "test") || strings.HasPrefix(first, "qa") || strings.HasPrefix(first, "uat"):
		tagSet["staging"] = true
	case strings.HasPrefix(first, "admin") || strings.HasPrefix(first, "portal") || strings.HasPrefix(first, "internal") ||
		strings.HasPrefix(first, "corp") || strings.HasPrefix(first, "vpn") || strings.HasPrefix(first, "sso"):
		tagSet["admin"] = true
	case strings.HasPrefix(first, "cdn") || strings.HasPrefix(first, "static") || strings.HasPrefix(first, "assets") ||
		strings.HasPrefix(first, "media") || strings.HasPrefix(first, "img"):
		tagSet["cdn"] = true
		tagSet["static"] = true
	case strings.HasPrefix(first, "mail") || strings.HasPrefix(first, "smtp") || strings.HasPrefix(first, "mx"):
		tagSet["mail"] = true
	case strings.HasPrefix(first, "auth") || strings.HasPrefix(first, "login") || strings.HasPrefix(first, "oauth"):
		tagSet["auth"] = true
	}

	// Default production if not staging/dev
	if !tagSet["staging"] && !tagSet["admin"] && len(parts) >= 2 {
		tagSet["production"] = true
	}

	// 2. Port-based heuristics
	for _, p := range ports {
		if p == 8080 || p == 8443 || p == 3000 || p == 5000 || p == 8000 {
			tagSet["alternate-port"] = true
		}
	}

	if len(tagSet) == 0 {
		tagSet["unknown"] = true
	}

	var result []*models.AssetTag
	for t := range tagSet {
		result = append(result, &models.AssetTag{
			ID:         newID("tag"),
			AssetID:    assetID,
			TargetID:   targetID,
			Tag:        t,
			IsInferred: true,
			CreatedAt:  now,
			CreatedBy:  "system:inferred",
		})
	}

	return result
}
