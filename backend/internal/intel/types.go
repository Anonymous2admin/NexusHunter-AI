package intel

import (
	"regexp"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// MatchTarget defines which part of the response or asset to examine.
type MatchTarget string

const (
	MatchHeader         MatchTarget = "HEADER"
	MatchCookie         MatchTarget = "COOKIE"
	MatchHTMLMeta       MatchTarget = "HTML_META"
	MatchHTMLBody       MatchTarget = "HTML_BODY"
	MatchScriptSrc      MatchTarget = "SCRIPT_SRC"
	MatchURLPath        MatchTarget = "URL_PATH"
	MatchCertIssuer     MatchTarget = "CERT_ISSUER"
	MatchWebServer      MatchTarget = "WEB_SERVER"
)

// FingerprintRule specifies a declarative, maintainable pattern for technology detection.
type FingerprintRule struct {
	ID             string                 `json:"id"`
	TechnologyName string                 `json:"technology_name"`
	Category       string                 `json:"category"` // "web_server", "web_framework", "js_framework", "cms", "cdn", "reverse_proxy", "analytics", "hosting", "cloud", "security"
	MatchTarget    MatchTarget            `json:"match_target"`
	HeaderKey      string                 `json:"header_key,omitempty"` // for MatchHeader
	MetaName       string                 `json:"meta_name,omitempty"`  // for MatchHTMLMeta
	Pattern        string                 `json:"pattern"`              // Regex or literal substring pattern
	VersionRegex   string                 `json:"version_regex,omitempty"` // Capture group 1 extracts version
	BaseConfidence models.ConfidenceLevel `json:"base_confidence"`

	compiledRegex        *regexp.Regexp
	compiledVersionRegex *regexp.Regexp
}

// ExtractedPageMeta holds passive metadata extracted from HTML.
type ExtractedPageMeta struct {
	Title         string            `json:"title"`
	Description   string            `json:"description"`
	Generator     string            `json:"generator"`
	CanonicalURL  string            `json:"canonical_url"`
	MetaTags      map[string]string `json:"meta_tags"`
	FormCount     int               `json:"form_count"`
	ScriptCount   int               `json:"script_count"`
	StyleCount    int               `json:"style_count"`
	ScriptSources []string          `json:"script_sources"`
	StyleSources  []string          `json:"style_sources"`
	SourceMaps    []string          `json:"source_maps"`
	APIExtracted  []string          `json:"api_extracted"`
}

// SecurityAuditObservation captures the passive evaluation of a security header/mechanism.
type SecurityAuditObservation struct {
	PropertyName string `json:"property_name"`
	IsPresent    bool   `json:"is_present"`
	Details      string `json:"details"`
	RawValue     string `json:"raw_value"`
}
