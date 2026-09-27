package scope

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

var (
	ErrOverlyBroadPattern     = errors.New("regex is overly broad or universal wildcard (e.g. '.*', '^.*$')")
	ErrInvalidRegex           = errors.New("invalid regular expression")
	ErrNoDomainsExtracted     = errors.New("zero root domains extracted from scope")
	ErrAmbiguousScope         = errors.New("scope import contains ambiguous domain rules requiring manual review")
	ErrNormalizationCollision = errors.New("NORMALIZATION_COLLISION: distinct raw keys collapsed to identical normalized key")
	ErrEmptyHostRule          = errors.New("EMPTY_HOST_RULE: scope rule has empty, missing, or invalid host; fail closed")
)

// Universal dangerous regex patterns that must fail closed.
var dangerousBroadPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\s*\.\*\s*$`),
	regexp.MustCompile(`^\s*\^\.\*\$\s*$`),
	regexp.MustCompile(`^\s*\.\+\s*$`),
	regexp.MustCompile(`^\s*\^\.\+\$\s*$`),
	regexp.MustCompile(`^\s*[\^]?\.\*[\$]?\s*$`),
}

// Known two-part public suffixes for accurate registrable domain extraction.
var knownTwoPartPublicSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "gov.uk": true, "ac.uk": true, "me.uk": true, "net.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true,
	"co.nz": true, "net.nz": true, "org.nz": true, "govt.nz": true, "ac.nz": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "go.jp": true, "ac.jp": true,
	"com.br": true, "net.br": true, "org.br": true, "gov.br": true,
	"co.in": true, "net.in": true, "org.in": true, "gen.in": true, "firm.in": true,
	"com.sg": true, "net.sg": true, "org.sg": true, "gov.sg": true, "edu.sg": true,
	"com.mx": true, "net.mx": true, "org.mx": true, "edu.mx": true, "gob.mx": true,
	"co.za": true, "org.za": true, "net.za": true, "web.za": true,
	"com.tr": true, "net.tr": true, "org.tr": true, "edu.tr": true, "gov.tr": true,
	"com.hk": true, "org.hk": true, "net.hk": true, "edu.hk": true, "gov.hk": true,
	"com.tw": true, "org.tw": true, "net.tw": true, "edu.tw": true, "gov.tw": true,
	"com.my": true, "org.my": true, "net.my": true, "edu.my": true, "gov.my": true,
	"co.kr": true, "ne.kr": true, "or.kr": true, "re.kr": true,
}

// ImportSanitizer coordinates the fail-closed scope ingestion and normalization pipeline.
type ImportSanitizer interface {
	SanitizeScopeFile(raw []byte, filename string) (*models.ScopeImportReview, error)
}

// ScopeImportSanitizer coordinates the fail-closed scope ingestion and normalization pipeline.
type ScopeImportSanitizer struct{}

// NewScopeImportSanitizer creates an initialized ScopeImportSanitizer.
func NewScopeImportSanitizer() *ScopeImportSanitizer {
	return &ScopeImportSanitizer{}
}

// NewSanitizer is an alias for NewScopeImportSanitizer.
func NewSanitizer() *ScopeImportSanitizer {
	return NewScopeImportSanitizer()
}

func randomID(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

// extractRegistrableDomain extracts the authoritative registrable domain using public-suffix-aware rules.
func extractRegistrableDomain(hostname string) string {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	hostname = strings.Trim(hostname, ".")
	if hostname == "" {
		return ""
	}
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return ""
	}
	if len(parts) >= 3 {
		suffix2 := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if knownTwoPartPublicSuffixes[suffix2] {
			return parts[len(parts)-3] + "." + suffix2
		}
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// SanitizeScopeFile processes raw uploaded scope data through the normalization pipeline.
func (s *ScopeImportSanitizer) SanitizeScopeFile(raw []byte, filename string) (*models.ScopeImportReview, error) {
	if len(raw) == 0 {
		return nil, errors.New("empty scope file")
	}

	// 1. JSON Parse
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("malformed JSON scope: %w", err)
	}

	// 2. Structural & Key Normalization (recursive key trim with collision detection)
	normalizations := make([]models.ScopeNormalization, 0)
	cleanedData, err := s.normalizeKeysRecursively(parsed, "", &normalizations)
	if err != nil {
		return nil, err
	}

	// 3. Extract into Canonical Scope Representation
	canonical, err := s.buildCanonicalScope(cleanedData, filename, &normalizations)
	if err != nil {
		return nil, err
	}

	// 4. Multi-Root Domain Discovery (authoritative roots derived ONLY from include rules)
	rootCandidates := s.discoverRootDomains(canonical, filename)
	if len(rootCandidates) == 0 {
		return nil, ErrNoDomainsExtracted
	}

	// Phase 8.2R-FINAL.4 Requirement 8:
	// CanonicalScope.PrimaryRootDomain MUST NOT be treated as authoritative before human confirmation.
	// DiscoveredRootCandidates stores discovered roots.
	// ConfirmedPrimaryRootDomain remains strictly empty.
	// review.SelectedRootDomain remains strictly empty.
	for i := range rootCandidates {
		rootCandidates[i].Status = "DISCOVERED"
	}
	canonical.PrimaryRootDomain = ""
	canonical.ConfirmedPrimaryRootDomain = ""

	// Extract unique sorted root candidates list
	uniqueRootsMap := make(map[string]bool)
	for _, c := range rootCandidates {
		uniqueRootsMap[c.NormalizedDomain] = true
	}
	uniqueRoots := make([]string, 0, len(uniqueRootsMap))
	for r := range uniqueRootsMap {
		uniqueRoots = append(uniqueRoots, r)
	}
	sort.Strings(uniqueRoots)
	canonical.RootDomains = uniqueRoots
	canonical.DiscoveredRootCandidates = uniqueRoots

	// 5. Deterministic Canonicalization (Requirement 14):
	// Sort rules, root candidates, normalizations, and canonical collections before hashing
	s.sortCanonicalScope(canonical)
	sort.Slice(rootCandidates, func(i, j int) bool {
		if rootCandidates[i].NormalizedDomain != rootCandidates[j].NormalizedDomain {
			return rootCandidates[i].NormalizedDomain < rootCandidates[j].NormalizedDomain
		}
		return rootCandidates[i].SourcePath < rootCandidates[j].SourcePath
	})
	sort.Slice(normalizations, func(i, j int) bool {
		if normalizations[i].Field != normalizations[j].Field {
			return normalizations[i].Field < normalizations[j].Field
		}
		return normalizations[i].Original < normalizations[j].Original
	})
	canonical.Normalizations = normalizations

	warningsCount := 0
	ambiguousCount := 0
	for _, n := range normalizations {
		if n.Severity == "WARNING" || n.Severity == "CRITICAL" {
			warningsCount++
		}
	}
	for _, r := range rootCandidates {
		if r.Status == "AMBIGUOUS" {
			ambiguousCount++
		}
	}

	// Compute Cryptographic Hashes for Full Provenance & Auditability (Requirement 9 & 14)
	origFileHash := sha256.Sum256(raw)
	origFileHex := hex.EncodeToString(origFileHash[:])

	canonicalJSON, err := json.Marshal(canonical)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize canonical scope: %w", err)
	}
	canonicalHash := sha256.Sum256(canonicalJSON)
	canonicalHex := hex.EncodeToString(canonicalHash[:])

	normJSON, err := json.Marshal(normalizations)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize normalization manifest: %w", err)
	}
	normHash := sha256.Sum256(normJSON)
	normHex := hex.EncodeToString(normHash[:])

	review := &models.ScopeImportReview{
		ID:                          randomID("rev"),
		FileName:                    filename,
		Status:                      "PENDING_CONFIRMATION",
		RootDomains:                 rootCandidates,
		SelectedRootDomain:          "", // Strictly empty until human confirmation
		RulesDiscovered:             len(canonical.IncludeHosts) + len(canonical.ExcludeHosts) + len(canonical.IncludeURLs) + len(canonical.ExcludeURLs),
		IncludeHostsCount:           len(canonical.IncludeHosts),
		ExcludeHostsCount:           len(canonical.ExcludeHosts),
		RegexRulesCount:             len(canonical.IncludeHosts) + len(canonical.ExcludeHosts),
		PathRulesCount:              len(canonical.PathRules),
		WarningsCount:               warningsCount,
		AmbiguousCount:              ambiguousCount,
		Normalizations:              normalizations,
		CanonicalScope:              canonical,
		OriginalFileSHA256:          origFileHex,
		CanonicalScopeSHA256:        canonicalHex,
		NormalizationManifestSHA256: normHex,
		CreatedAt:                   time.Now().UTC(),
	}

	return review, nil
}

// sortCanonicalScope applies deterministic ordering to all rules and collections in CanonicalScope.
func (s *ScopeImportSanitizer) sortCanonicalScope(c *models.CanonicalScope) {
	ruleLess := func(a, b models.AdvancedScopeRule) bool {
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.File < b.File
	}

	sort.Slice(c.IncludeHosts, func(i, j int) bool {
		return ruleLess(c.IncludeHosts[i], c.IncludeHosts[j])
	})
	sort.Slice(c.ExcludeHosts, func(i, j int) bool {
		return ruleLess(c.ExcludeHosts[i], c.ExcludeHosts[j])
	})
	sort.Slice(c.IncludeURLs, func(i, j int) bool {
		return ruleLess(c.IncludeURLs[i], c.IncludeURLs[j])
	})
	sort.Slice(c.ExcludeURLs, func(i, j int) bool {
		return ruleLess(c.ExcludeURLs[i], c.ExcludeURLs[j])
	})
	sort.Slice(c.PathRules, func(i, j int) bool {
		if c.PathRules[i].Path != c.PathRules[j].Path {
			return c.PathRules[i].Path < c.PathRules[j].Path
		}
		return c.PathRules[i].Excluded && !c.PathRules[j].Excluded
	})
}

// normalizeKeysRecursively traverses JSON structures, trimming leading and trailing whitespace from keys.
// Returns ErrNormalizationCollision if two distinct raw keys collapse to the same normalized key.
func (s *ScopeImportSanitizer) normalizeKeysRecursively(node any, currentPath string, normalizations *[]models.ScopeNormalization) (any, error) {
	switch v := node.(type) {
	case map[string]any:
		cleanedMap := make(map[string]any, len(v))
		seenNormalizedKeys := make(map[string]string) // normalizedKey -> originalKey

		// Process keys in sorted order for determinism
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			val := v[k]
			trimmedKey := strings.TrimSpace(k)
			if existingOrig, exists := seenNormalizedKeys[trimmedKey]; exists && existingOrig != k {
				return nil, fmt.Errorf("%w: keys '%s' and '%s' normalize to identical key '%s' at path '%s'",
					ErrNormalizationCollision, existingOrig, k, trimmedKey, currentPath)
			}
			seenNormalizedKeys[trimmedKey] = k

			if trimmedKey != k {
				*normalizations = append(*normalizations, models.ScopeNormalization{
					Original:   k,
					Normalized: trimmedKey,
					Field:      fmt.Sprintf("%s/%s", currentPath, k),
					TokenType:  "STRUCTURAL_KEY",
					Reason:     "trimmed leading/trailing whitespace from JSON object key",
					Severity:   "INFO",
				})
			}
			newPath := trimmedKey
			if currentPath != "" {
				newPath = fmt.Sprintf("%s/%s", currentPath, trimmedKey)
			}
			sub, err := s.normalizeKeysRecursively(val, newPath, normalizations)
			if err != nil {
				return nil, err
			}
			cleanedMap[trimmedKey] = sub
		}
		return cleanedMap, nil
	case []any:
		cleanedSlice := make([]any, len(v))
		for i, item := range v {
			itemPath := fmt.Sprintf("%s[%d]", currentPath, i)
			sub, err := s.normalizeKeysRecursively(item, itemPath, normalizations)
			if err != nil {
				return nil, err
			}
			cleanedSlice[i] = sub
		}
		return cleanedSlice, nil
	case string:
		return v, nil
	default:
		return v, nil
	}
}

// NormalizeRegex applies safe transformations to known corrupted regular expressions.
// Fails closed if pattern is empty, overly broad, or invalid.
func (s *ScopeImportSanitizer) NormalizeRegex(rawRegex string, fieldName string, normalizations *[]models.ScopeNormalization) (string, error) {
	trimmed := strings.TrimSpace(rawRegex)
	if trimmed != rawRegex {
		*normalizations = append(*normalizations, models.ScopeNormalization{
			Original:   rawRegex,
			Normalized: trimmed,
			Field:      fieldName,
			TokenType:  "REGEX",
			Reason:     "trimmed whitespace from regex pattern",
			Severity:   "INFO",
		})
	}

	if trimmed == "" {
		return "", ErrEmptyHostRule
	}

	// Check for dangerous universal wildcards first (fail closed)
	for _, dangerous := range dangerousBroadPatterns {
		if dangerous.MatchString(trimmed) {
			return "", fmt.Errorf("%w: '%s'", ErrOverlyBroadPattern, trimmed)
		}
	}

	// Detect and normalize corrupted wildcard representations:
	// Example: "^. \.rei\.com$" or "^. \\.example\.com$" -> "^.*\.example\.com$"
	corruptedWildcardRegex := regexp.MustCompile(`^\^\.\s+(\\?\.)?([a-zA-Z0-9_.\\]+)\$$`)
	if match := corruptedWildcardRegex.FindStringSubmatch(trimmed); len(match) == 3 {
		domainPart := match[2]
		domainPart = strings.TrimPrefix(domainPart, `\.`)
		domainPart = strings.TrimPrefix(domainPart, `.`)
		normalized := fmt.Sprintf(`^.*\.%s$`, domainPart)
		*normalizations = append(*normalizations, models.ScopeNormalization{
			Original:   rawRegex,
			Normalized: normalized,
			Field:      fieldName,
			TokenType:  "REGEX",
			Reason:     "recognized corrupted wildcard representation ('^. \\.domain$') normalized to canonical wildcard regex",
			Severity:   "WARNING",
		})
		trimmed = normalized
	}

	// Verify that the resulting regex compiles safely
	if _, err := regexp.Compile(trimmed); err != nil {
		return "", fmt.Errorf("%w '%s': %v", ErrInvalidRegex, trimmed, err)
	}

	return trimmed, nil
}

// buildCanonicalScope parses the normalized data structures into models.CanonicalScope.
func (s *ScopeImportSanitizer) buildCanonicalScope(data any, filename string, normalizations *[]models.ScopeNormalization) (*models.CanonicalScope, error) {
	canonical := &models.CanonicalScope{
		IncludeHosts:   make([]models.AdvancedScopeRule, 0),
		ExcludeHosts:   make([]models.AdvancedScopeRule, 0),
		IncludeURLs:    make([]models.AdvancedScopeRule, 0),
		ExcludeURLs:    make([]models.AdvancedScopeRule, 0),
		PathRules:      make([]models.PathRule, 0),
		SourceFiles:    []models.ScopeSource{{FileName: filename, Format: "GENERIC", RuleCount: 0}},
		Normalizations: make([]models.ScopeNormalization, 0),
	}

	// Check Burp Suite format: { "target": { "scope": { "include": [...], "exclude": [...] } } }
	if rootMap, ok := data.(map[string]any); ok {
		if targetObj, hasTarget := rootMap["target"].(map[string]any); hasTarget {
			if scopeObj, hasScope := targetObj["scope"].(map[string]any); hasScope {
				canonical.SourceFiles[0].Format = "BURP_SUITE"
				if err := s.parseBurpScope(scopeObj, canonical, normalizations); err != nil {
					return nil, err
				}
				return canonical, nil
			}
		}

		// Check direct include / exclude
		if _, hasInclude := rootMap["include"]; hasInclude {
			canonical.SourceFiles[0].Format = "ADVANCED_SCOPE"
			if err := s.parseBurpScope(rootMap, canonical, normalizations); err != nil {
				return nil, err
			}
			return canonical, nil
		}

		// Check HackerOne style: { "scope": [ { "asset_identifier": "...", "eligible_for_bounty": true } ] }
		if scopeList, hasList := rootMap["scope"].([]any); hasList {
			canonical.SourceFiles[0].Format = "HACKERONE"
			if err := s.parseAssetList(scopeList, canonical, normalizations); err != nil {
				return nil, err
			}
			return canonical, nil
		}
	}

	return nil, errors.New("unrecognized scope JSON structure")
}

func (s *ScopeImportSanitizer) parseBurpScope(scopeObj map[string]any, canonical *models.CanonicalScope, normalizations *[]models.ScopeNormalization) error {
	parseRuleSlice := func(items []any, isInclude bool) error {
		for i, item := range items {
			ruleMap, ok := item.(map[string]any)
			if !ok {
				continue
			}

			enabled := true
			if e, exists := ruleMap["enabled"]; exists {
				if eb, bOk := e.(bool); bOk {
					enabled = eb
				}
			}

			rawHost, hasHost := ruleMap["host"].(string)
			if !hasHost || strings.TrimSpace(rawHost) == "" {
				// Requirement 12: Empty or missing host rule must fail closed
				return fmt.Errorf("%w: rule[%d] has missing or empty host", ErrEmptyHostRule, i)
			}

			normalizedHost, err := s.NormalizeRegex(rawHost, fmt.Sprintf("rule[%d].host", i), normalizations)
			if err != nil {
				*normalizations = append(*normalizations, models.ScopeNormalization{
					Original:   rawHost,
					Normalized: "[REJECTED]",
					Field:      fmt.Sprintf("rule[%d].host", i),
					TokenType:  "REGEX",
					Reason:     fmt.Sprintf("regex safety failure: %v", err),
					Severity:   "CRITICAL",
				})
				return fmt.Errorf("%w at rule[%d]: %v", ErrEmptyHostRule, i, err)
			}

			protocol, _ := ruleMap["protocol"].(string)
			if protocol == "" {
				protocol = "any"
			}
			port, _ := ruleMap["port"].(string)
			file, _ := ruleMap["file"].(string)

			rule := models.AdvancedScopeRule{
				Enabled:  enabled,
				Host:     normalizedHost,
				Protocol: strings.TrimSpace(protocol),
				Port:     strings.TrimSpace(port),
				File:     strings.TrimSpace(file),
			}

			if file != "" {
				canonical.PathRules = append(canonical.PathRules, models.PathRule{
					Path:       file,
					MatchExact: false,
					Excluded:   !isInclude,
				})
			}

			if isInclude {
				canonical.IncludeHosts = append(canonical.IncludeHosts, rule)
			} else {
				canonical.ExcludeHosts = append(canonical.ExcludeHosts, rule)
			}
		}
		return nil
	}

	if inc, ok := scopeObj["include"].([]any); ok {
		if err := parseRuleSlice(inc, true); err != nil {
			return err
		}
	}
	if exc, ok := scopeObj["exclude"].([]any); ok {
		if err := parseRuleSlice(exc, false); err != nil {
			return err
		}
	}
	canonical.SourceFiles[0].RuleCount = len(canonical.IncludeHosts) + len(canonical.ExcludeHosts)
	return nil
}

func (s *ScopeImportSanitizer) parseAssetList(items []any, canonical *models.CanonicalScope, normalizations *[]models.ScopeNormalization) error {
	for i, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ident, hasIdent := m["asset_identifier"].(string)
		trimmed := strings.TrimSpace(ident)
		if !hasIdent || trimmed == "" {
			return fmt.Errorf("%w: asset[%d] has empty asset_identifier", ErrEmptyHostRule, i)
		}

		eligible := true
		if e, exists := m["eligible_for_bounty"].(bool); exists {
			eligible = e
		}

		// Convert wildcard domain to safe regex
		regexHost := trimmed
		if strings.HasPrefix(trimmed, "*.") {
			base := strings.TrimPrefix(trimmed, "*.")
			regexHost = fmt.Sprintf(`^.*\.%s$`, regexp.QuoteMeta(base))
		} else if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
			if u, err := url.Parse(trimmed); err == nil {
				regexHost = fmt.Sprintf(`^%s$`, regexp.QuoteMeta(u.Hostname()))
				if u.Path != "" && u.Path != "/" {
					canonical.PathRules = append(canonical.PathRules, models.PathRule{
						Path:       u.Path,
						MatchExact: false,
						Excluded:   !eligible,
					})
				}
			}
		} else if !strings.Contains(trimmed, "^") && !strings.Contains(trimmed, "$") {
			regexHost = fmt.Sprintf(`^%s$`, regexp.QuoteMeta(trimmed))
		}

		normRegex, err := s.NormalizeRegex(regexHost, fmt.Sprintf("asset[%d]", i), normalizations)
		if err != nil {
			return fmt.Errorf("%w: asset[%d] invalid host pattern '%s': %v", ErrEmptyHostRule, i, regexHost, err)
		}

		rule := models.AdvancedScopeRule{
			Enabled:  true,
			Host:     normRegex,
			Protocol: "any",
		}

		if eligible {
			canonical.IncludeHosts = append(canonical.IncludeHosts, rule)
		} else {
			canonical.ExcludeHosts = append(canonical.ExcludeHosts, rule)
		}
	}
	canonical.SourceFiles[0].RuleCount = len(canonical.IncludeHosts) + len(canonical.ExcludeHosts)
	return nil
}

// discoverRootDomains extracts all candidate root domains strictly from include rules.
// Requirement 13: Authoritative roots MUST NOT be derived from EXCLUDE-only rules.
func (s *ScopeImportSanitizer) discoverRootDomains(canonical *models.CanonicalScope, filename string) []models.RootDomainCandidate {
	discovered := make(map[string]models.RootDomainCandidate)

	for i, rule := range canonical.IncludeHosts {
		host := rule.Host
		cleaned := strings.Trim(host, "^$")
		cleaned = strings.TrimPrefix(cleaned, ".*\\.")
		cleaned = strings.TrimPrefix(cleaned, "\\.")
		cleaned = strings.ReplaceAll(cleaned, "\\.", ".")
		cleaned = strings.TrimSpace(cleaned)

		domain := extractRegistrableDomain(cleaned)
		if domain == "" {
			domainMatch := regexp.MustCompile(`([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})$`).FindString(cleaned)
			if domainMatch != "" {
				domain = extractRegistrableDomain(domainMatch)
			}
		}

		if domain != "" && isValidHostname(domain) {
			if _, exists := discovered[domain]; !exists {
				discovered[domain] = models.RootDomainCandidate{
					ID:               randomID("cand"),
					NormalizedDomain: domain,
					SourceFile:       filename,
					SourcePath:       fmt.Sprintf("include[%d].host", i),
					SourceRuleID:     fmt.Sprintf("include-%d", i),
					Evidence:         fmt.Sprintf("Discovered in include rule pattern: '%s'", rule.Host),
					Confidence:       "HIGH",
					Status:           "DISCOVERED",
				}
			}
		}
	}

	list := make([]models.RootDomainCandidate, 0, len(discovered))
	for _, c := range discovered {
		list = append(list, c)
	}

	// Deterministic ordering of candidates
	sort.Slice(list, func(i, j int) bool {
		return list[i].NormalizedDomain < list[j].NormalizedDomain
	})

	return list
}
