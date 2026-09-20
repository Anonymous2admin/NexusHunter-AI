package intel

import (
	"net/url"
	"strings"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// ClassifyAndExtractPageAssets resolves relative URLs and generates PageAsset models.
func ClassifyAndExtractPageAssets(assetID, targetID, baseURLStr string, meta ExtractedPageMeta) []*models.PageAsset {
	var assets []*models.PageAsset
	base, _ := url.Parse(baseURLStr)

	resolve := func(raw string) string {
		if base == nil {
			return raw
		}
		u, err := url.Parse(raw)
		if err != nil {
			return raw
		}
		return base.ResolveReference(u).String()
	}

	isSameDomain := func(raw string) bool {
		if base == nil {
			return true
		}
		u, err := url.Parse(raw)
		if err != nil {
			return true
		}
		return u.Host == "" || strings.EqualFold(u.Host, base.Host)
	}

	// 1. Script sources
	for _, src := range meta.ScriptSources {
		resolved := resolve(src)
		assets = append(assets, &models.PageAsset{
			ID:         newID("pa"),
			AssetID:    assetID,
			TargetID:   targetID,
			URL:        resolved,
			AssetType:  "script",
			SourcePage: baseURLStr,
			IsInScope:  isSameDomain(src),
		})
	}

	// 2. Stylesheet sources
	for _, href := range meta.StyleSources {
		resolved := resolve(href)
		assets = append(assets, &models.PageAsset{
			ID:         newID("pa"),
			AssetID:    assetID,
			TargetID:   targetID,
			URL:        resolved,
			AssetType:  "stylesheet",
			SourcePage: baseURLStr,
			IsInScope:  isSameDomain(href),
		})
	}

	// 3. Source maps
	for _, sm := range meta.SourceMaps {
		resolved := resolve(sm)
		assets = append(assets, &models.PageAsset{
			ID:         newID("pa"),
			AssetID:    assetID,
			TargetID:   targetID,
			URL:        resolved,
			AssetType:  "sourcemap",
			SourcePage: baseURLStr,
			IsInScope:  isSameDomain(sm),
		})
	}

	// 4. API endpoints
	for _, api := range meta.APIExtracted {
		resolved := resolve(api)
		assets = append(assets, &models.PageAsset{
			ID:         newID("pa"),
			AssetID:    assetID,
			TargetID:   targetID,
			URL:        resolved,
			AssetType:  "api_endpoint",
			SourcePage: baseURLStr,
			IsInScope:  true,
		})
	}

	return assets
}
