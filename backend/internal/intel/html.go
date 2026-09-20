package intel

import (
	"html"
	"regexp"
	"strings"
)

var (
	titleRegex      = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	metaRegex       = regexp.MustCompile(`(?is)<meta\s+[^>]*?(?:name|property)=["']([^"']+)["'][^>]*?content=["']([^"']*)["'][^>]*>|<meta\s+[^>]*?content=["']([^"']*)["'][^>]*?(?:name|property)=["']([^"']+)["'][^>]*>`)
	scriptSrcRegex  = regexp.MustCompile(`(?is)<script\s+[^>]*?src=["']([^"']+)["'][^>]*>`)
	linkCSSRegex    = regexp.MustCompile(`(?is)<link\s+[^>]*?rel=["']stylesheet["'][^>]*?href=["']([^"']+)["'][^>]*>|<link\s+[^>]*?href=["']([^"']+)["'][^>]*?rel=["']stylesheet["'][^>]*>`)
	formRegex       = regexp.MustCompile(`(?is)<form\b[^>]*>`)
	sourceMapRegex  = regexp.MustCompile(`(?m)(?:sourceMappingURL=([^\s"'>]+)|\b([a-zA-Z0-9_\-\.\/]+\.js\.map)\b)`)
	apiPatternRegex = regexp.MustCompile(`["'](/(?:api|v[0-9]+|graphql|auth|oauth|webhook)/[a-zA-Z0-9_\-\/\.]*)["']`)
)

// ExtractHTMLMetadata parses raw HTML to extract page title, metadata, scripts, stylesheets, and structure.
func ExtractHTMLMetadata(body string) ExtractedPageMeta {
	meta := ExtractedPageMeta{
		MetaTags:      make(map[string]string),
		ScriptSources: []string{},
		StyleSources:  []string{},
		SourceMaps:    []string{},
		APIExtracted:  []string{},
	}

	// 1. Page Title
	if match := titleRegex.FindStringSubmatch(body); len(match) > 1 {
		meta.Title = strings.TrimSpace(html.UnescapeString(match[1]))
	}

	// 2. Meta Tags
	metaMatches := metaRegex.FindAllStringSubmatch(body, -1)
	for _, m := range metaMatches {
		name := ""
		content := ""
		if m[1] != "" {
			name = strings.ToLower(strings.TrimSpace(m[1]))
			content = html.UnescapeString(m[2])
		} else if m[4] != "" {
			name = strings.ToLower(strings.TrimSpace(m[4]))
			content = html.UnescapeString(m[3])
		}
		if name != "" {
			meta.MetaTags[name] = content
			switch name {
			case "description":
				meta.Description = content
			case "generator":
				meta.Generator = content
			}
		}
	}

	// 3. Form count
	forms := formRegex.FindAllString(body, -1)
	meta.FormCount = len(forms)

	// 4. Scripts
	scriptMatches := scriptSrcRegex.FindAllStringSubmatch(body, -1)
	seenScripts := make(map[string]bool)
	for _, s := range scriptMatches {
		if len(s) > 1 && s[1] != "" {
			u := strings.TrimSpace(s[1])
			if !seenScripts[u] {
				seenScripts[u] = true
				meta.ScriptSources = append(meta.ScriptSources, u)
			}
		}
	}
	meta.ScriptCount = len(meta.ScriptSources)

	// 5. Stylesheets
	linkMatches := linkCSSRegex.FindAllStringSubmatch(body, -1)
	seenStyles := make(map[string]bool)
	for _, l := range linkMatches {
		href := ""
		if l[1] != "" {
			href = l[1]
		} else if len(l) > 2 && l[2] != "" {
			href = l[2]
		}
		if href != "" && !seenStyles[href] {
			seenStyles[href] = true
			meta.StyleSources = append(meta.StyleSources, href)
		}
	}
	meta.StyleCount = len(meta.StyleSources)

	// 6. Source Map references
	smMatches := sourceMapRegex.FindAllStringSubmatch(body, -1)
	seenSM := make(map[string]bool)
	for _, sm := range smMatches {
		val := ""
		if sm[1] != "" {
			val = sm[1]
		} else if len(sm) > 2 && sm[2] != "" {
			val = sm[2]
		}
		if val != "" && !seenSM[val] {
			seenSM[val] = true
			meta.SourceMaps = append(meta.SourceMaps, val)
		}
	}

	// 7. API-like patterns in HTML/Scripts
	apiMatches := apiPatternRegex.FindAllStringSubmatch(body, -1)
	seenAPIs := make(map[string]bool)
	for _, a := range apiMatches {
		if len(a) > 1 && a[1] != "" && !seenAPIs[a[1]] {
			seenAPIs[a[1]] = true
			meta.APIExtracted = append(meta.APIExtracted, a[1])
		}
	}

	return meta
}
