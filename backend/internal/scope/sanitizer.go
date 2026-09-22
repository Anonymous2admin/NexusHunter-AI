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
	"strings"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

var (
	ErrOverlyBroadPattern = errors.New("regex is overly broad or universal wildcard (e.g. '.*', '^.*$')")
	ErrInvalidRegex       = errors.New("invalid regular expression")
	ErrNoDomainsExtracted = errors.New("zero root domains extracted from scope")
	ErrAmbiguousScope     = errors.New("scope import contains ambiguous domain rules requiring manual review")
)

// Universal dangerous regex patterns that must fail closed.
var dangerousBroadPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^\s*\.\*\s*$`),
	regexp.MustCompile(`^\s*\^\.\*\$\s*$`),
	regexp.MustCompile(`^\s*\.\+\s*$`),
	regexp.MustCompile(`^\s*\^\.\+\$\s*$`),
	regexp.MustCompile(`^\s*[\^]?\.\*[\$]?\s*$`),
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

	// 2. Structural & Key Normalization (recursive key trim)
	normalizations := make([]models.ScopeNormalization, 0)
	cleanedData := s.normalizeKeysRecursively(parsed, "", &normalizations)

	// 3. Extract into Canonical Scope Representation
	canonical, err := s.buildCanonicalScope(cleanedData, filename, &normalizations)
	if err != nil {
		return nil, err
	}

	// 4. Multi-Root Domain Discovery
	rootCandidates := s.discoverRootDomains(canonical, filename)
	if len(rootCandidates) == 0 {
		return nil, ErrNoDomainsExtracted
	}

	// Fail-closed root domain selection:
	// If exactly 1 root domain exists, it is marked as CANDIDATE.
	// If multiple roots exist, NO silent default selection is permitted (must be confirmed by operator).
	selectedDomain := ""
	if len(rootCandidates) == 1 {
		selectedDomain = rootCandidates[0].NormalizedDomain
		rootCandidates[0].Status = "CANDIDATE"
	} else {
		for i := range rootCandidates {
			if rootCandidates[i].Status != "AMBIGUOUS" {
				rootCandidates[i].Status = "DISCOVERED"
			}
		}
	}
	canonical.PrimaryRootDomain = selectedDomain

	// Populate root domains list
	uniqueRoots := make([]string, 0, len(rootCandidates))
	for _, c := range rootCandidates {
		uniqueRoots = append(uniqueRoots, c.NormalizedDomain)
	}
	canonical.RootDomains = uniqueRoots
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

	// Compute Cryptographic Hashes for Full Provenance & Auditability (Section 9)
	origFileHash := sha256.Sum256(raw)
	origFileHex := hex.EncodeToString(origFileHash[:])

	canonicalJSON, _ := json.Marshal(canonical)
	canonicalHash := sha256.Sum256(canonicalJSON)
	canonicalHex := hex.EncodeToString(canonicalHash[:])

	normJSON, _ := json.Marshal(normalizations)
	normHash := sha256.Sum256(normJSON)
	normHex := hex.EncodeToString(normHash[:])

	review := &models.ScopeImportReview{
		ID:                          randomID("rev"),
		FileName:                    filename,
		Status:                      "PENDING_CONFIRMATION",
		RootDomains:                 rootCandidates,
		SelectedRootDomain:          selectedDomain,
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

// normalizeKeysRecursively traverses JSON structures, strictly trimming leading and trailing whitespace from keys.
func (s *ScopeImportSanitizer) normalizeKeysRecursively(node any, currentPath string, normalizations *[]models.ScopeNormalization) any {
	switch v := node.(type) {
	case map[string]any:
		cleanedMap := make(map[string]any, len(v))
		for k, val := range v {
			trimmedKey := strings.TrimSpace(k)
			if trimmedKey != k {
				*normalizations = append(*normalizations, models.ScopeNormalization{
					Original:   k,
					Normalized: trimmedKey,
					Field:      fmt.Sprintf("%s/%s", currentPath, k),
					Reason:     "trimmed leading/trailing whitespace from JSON object key",
					Severity:   "INFO",
				})
			}
			newPath := trimmedKey
			if currentPath != "" {
				newPath = fmt.Sprintf("%s/%s", currentPath, trimmedKey)
			}
			cleanedMap[trimmedKey] = s.normalizeKeysRecursively(val, newPath, normalizations)
		}
		return cleanedMap
	case []any:
		cleanedSlice := make([]any, len(v))
		for i, item := range v {
			itemPath := fmt.Sprintf("%s[%d]", currentPath, i)
			cleanedSlice[i] = s.normalizeKeysRecursively(item, itemPath, normalizations)
		}
		return cleanedSlice
	case string:
		return v
	default:
		return v
	}
}

// NormalizeRegex applies safe transformations to known corrupted regular expressions.
func (s *ScopeImportSanitizer) NormalizeRegex(rawRegex string, fieldName string, normalizations *[]models.ScopeNormalization) (string, error) {
	trimmed := strings.TrimSpace(rawRegex)
	if trimmed != rawRegex {
		*normalizations = append(*normalizations, models.ScopeNormalization{
			Original:   rawRegex,
			Normalized: trimmed,
			Field:      fieldName,
			Reason:     "trimmed whitespace from regex pattern",
			Severity:   "INFO",
		})
	}

	if trimmed == "" {
		return "", nil
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
				s.parseBurpScope(scopeObj, canonical, normalizations)
				return canonical, nil
			}
		}

		// Check direct include / exclude
		if _, hasInclude := rootMap["include"]; hasInclude {
			canonical.SourceFiles[0].Format = "ADVANCED_SCOPE"
			s.parseBurpScope(rootMap, canonical, normalizations)
			return canonical, nil
		}

		// Check HackerOne style: { "scope": [ { "asset_identifier": "...", "eligible_for_bounty": true } ] }
		if scopeList, hasList := rootMap["scope"].([]any); hasList {
			canonical.SourceFiles[0].Format = "HACKERONE"
			s.parseAssetList(scopeList, canonical, normalizations)
			return canonical, nil
		}
	}

	return nil, errors.New("unrecognized scope JSON structure")
}

func (s *ScopeImportSanitizer) parseBurpScope(scopeObj map[string]any, canonical *models.CanonicalScope, normalizations *[]models.ScopeNormalization) {
	parseRuleSlice := func(items []any, isInclude bool) {
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

			rawHost, _ := ruleMap["host"].(string)
			normalizedHost, err := s.NormalizeRegex(rawHost, fmt.Sprintf("rule[%d].host", i), normalizations)
			if err != nil {
				*normalizations = append(*normalizations, models.ScopeNormalization{
					Original:   rawHost,
					Normalized: "[REJECTED]",
					Field:      fmt.Sprintf("rule[%d].host", i),
					Reason:     fmt.Sprintf("regex safety failure: %v", err),
					Severity:   "CRITICAL",
				})
				continue
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
	}

	if inc, ok := scopeObj["include"].([]any); ok {
		parseRuleSlice(inc, true)
	}
	if exc, ok := scopeObj["exclude"].([]any); ok {
		parseRuleSlice(exc, false)
	}
	canonical.SourceFiles[0].RuleCount = len(canonical.IncludeHosts) + len(canonical.ExcludeHosts)
}

func (s *ScopeImportSanitizer) parseAssetList(items []any, canonical *models.CanonicalScope, normalizations *[]models.ScopeNormalization) {
	for i, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ident, _ := m["asset_identifier"].(string)
		trimmed := strings.TrimSpace(ident)
		if trimmed == "" {
			continue
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
			continue
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
}

// discoverRootDomains extracts all candidate root domains from the canonical scope rules.
func (s *ScopeImportSanitizer) discoverRootDomains(canonical *models.CanonicalScope, filename string) []models.RootDomainCandidate {
	discovered := make(map[string]models.RootDomainCandidate)

	extractCandidates := func(rules []models.AdvancedScopeRule, rulePrefix string) {
		for i, rule := range rules {
			host := rule.Host
			cleaned := strings.Trim(host, "^$")
			cleaned = strings.TrimPrefix(cleaned, ".*\\.")
			cleaned = strings.TrimPrefix(cleaned, "\\.")
			cleaned = strings.ReplaceAll(cleaned, "\\.", ".")
			cleaned = strings.TrimSpace(cleaned)

			// Extract base/root domain (e.g. admin.shopify.com -> shopify.com)
			parts := strings.Split(cleaned, ".")
			var domain string
			if len(parts) >= 2 {
				lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
				if isValidHostname(lastTwo) {
					domain = strings.ToLower(lastTwo)
				}
			}
			if domain == "" {
				domainMatch := regexp.MustCompile(`([a-zA-Z0-9\-]+\.[a-zA-Z]{2,})$`).FindString(cleaned)
				if domainMatch != "" && isValidHostname(domainMatch) {
					domain = strings.ToLower(domainMatch)
				}
			}

			if domain != "" && isValidHostname(domain) {
				if _, exists := discovered[domain]; !exists {
					discovered[domain] = models.RootDomainCandidate{
						ID:               randomID("cand"),
						NormalizedDomain: domain,
						SourceFile:       filename,
						SourcePath:       fmt.Sprintf("%s[%d].host", rulePrefix, i),
						SourceRuleID:     fmt.Sprintf("%s-%d", rulePrefix, i),
						Evidence:         fmt.Sprintf("Discovered in rule pattern: '%s'", rule.Host),
						Confidence:       "HIGH",
						Status:           "DISCOVERED",
					}
				}
			}
		}
	}

	extractCandidates(canonical.IncludeHosts, "include")
	extractCandidates(canonical.ExcludeHosts, "exclude")

	list := make([]models.RootDomainCandidate, 0, len(discovered))
	for _, c := range discovered {
		list = append(list, c)
	}
	return list
}
