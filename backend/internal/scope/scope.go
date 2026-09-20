package scope

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

var (
	ErrTargetNil          = errors.New("target cannot be nil")
	ErrTargetInactive     = errors.New("target is not active")
	ErrEmptyScope         = errors.New("target scope is empty; cannot authorize actions")
	ErrMalformedTarget    = errors.New("target configuration is malformed or invalid")
	ErrMalformedHost      = errors.New("hostname is malformed or invalid")
	ErrMalformedURL       = errors.New("url is malformed or has invalid scheme")
	ErrHostMismatch       = errors.New("hostname does not match URL host")
	ErrExcluded           = errors.New("host or URL matches excluded pattern")
	ErrDomainOutOfScope   = errors.New("hostname is not in allowed domains")
	ErrURLPathRestricted  = errors.New("url path is not in allowed url patterns")
	ErrWildcardTooBroad   = errors.New("broad wildcards such as '*' or top-level domains are strictly forbidden")
)

// hostnameRegex checks for valid RFC 1123 DNS labels.
var hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

// ScopeDecision details the outcome of an authorization query.
type ScopeDecision struct {
	InScope bool   `json:"in_scope"`
	Reason  string `json:"reason"`
	Matched string `json:"matched_rule,omitempty"`
}

// ScopeService defines the contract for checking research target boundaries.
type ScopeService interface {
	IsInScope(target *models.Target, hostname string, rawURL string) (bool, error)
	Evaluate(target *models.Target, hostname string, rawURL string) ScopeDecision
	ValidateTarget(target *models.Target) error
}

// Validator is the fail-closed implementation of ScopeService.
type Validator struct{}

// NewValidator creates a new fail-closed scope validator.
func NewValidator() *Validator {
	return &Validator{}
}

// ParseBugBountyScopeJSON parses various bug-bounty scope export formats:
// 1. Burp Suite target scope export ({ "target": { "scope": { "advanced_mode": true, "include": [...], "exclude": [...] } } })
// 2. Direct scope object ({ "advanced_mode": true, "include": [...], "exclude": [...] })
// 3. Platform asset lists ({ "scope": [ { "asset_identifier": "...", "eligible_for_bounty": true } ] })
func ParseBugBountyScopeJSON(data []byte) (*models.AdvancedScopeConfig, error) {
	if len(data) == 0 {
		return nil, errors.New("empty scope data")
	}

	// Format 1: Burp Suite nested target.scope
	type burpEnvelope struct {
		Target struct {
			Scope struct {
				AdvancedMode bool                       `json:"advanced_mode"`
				Include      []models.AdvancedScopeRule `json:"include"`
				Exclude      []models.AdvancedScopeRule `json:"exclude"`
			} `json:"scope"`
		} `json:"target"`
	}
	var burp burpEnvelope
	if err := json.Unmarshal(data, &burp); err == nil && (len(burp.Target.Scope.Include) > 0 || len(burp.Target.Scope.Exclude) > 0) {
		return &models.AdvancedScopeConfig{
			AdvancedMode: burp.Target.Scope.AdvancedMode,
			Include:      burp.Target.Scope.Include,
			Exclude:      burp.Target.Scope.Exclude,
		}, nil
	}

	// Format 2: Direct AdvancedScopeConfig
	var direct models.AdvancedScopeConfig
	if err := json.Unmarshal(data, &direct); err == nil && (len(direct.Include) > 0 || len(direct.Exclude) > 0) {
		return &direct, nil
	}

	// Format 3: HackerOne/Bugcrowd style assets list
	type assetItem struct {
		AssetIdentifier   string `json:"asset_identifier"`
		EligibleForBounty bool   `json:"eligible_for_bounty"`
		Instruction       string `json:"instruction"`
	}
	type assetList struct {
		Scope []assetItem `json:"scope"`
	}
	var al assetList
	if err := json.Unmarshal(data, &al); err == nil && len(al.Scope) > 0 {
		cfg := &models.AdvancedScopeConfig{AdvancedMode: true}
		for _, item := range al.Scope {
			hostPat := strings.TrimSpace(item.AssetIdentifier)
			if hostPat == "" {
				continue
			}
			// Convert wildcard domain (e.g. *.arc.io) to regex pattern
			regexHost := hostPat
			if strings.HasPrefix(hostPat, "*.") {
				base := regexp.QuoteMeta(strings.TrimPrefix(hostPat, "*."))
				regexHost = fmt.Sprintf(`^.*\.%s$`, base)
			} else if !strings.Contains(hostPat, "^") && !strings.Contains(hostPat, "$") {
				regexHost = fmt.Sprintf(`^%s$`, regexp.QuoteMeta(hostPat))
			}

			rule := models.AdvancedScopeRule{
				Enabled:  true,
				Host:     regexHost,
				Protocol: "any",
			}
			if item.EligibleForBounty {
				cfg.Include = append(cfg.Include, rule)
			} else {
				cfg.Exclude = append(cfg.Exclude, rule)
			}
		}
		return cfg, nil
	}

	return nil, errors.New("unrecognized scope JSON format")
}

// ValidateTarget ensures a target definition is strictly well-formed and safe.
func (v *Validator) ValidateTarget(target *models.Target) error {
	if target == nil {
		return ErrTargetNil
	}
	if strings.TrimSpace(target.Name) == "" {
		return fmt.Errorf("%w: target name cannot be empty", ErrMalformedTarget)
	}
	root := strings.ToLower(strings.TrimSpace(target.RootDomain))
	if root == "" && (target.ScopeConfig == nil || len(target.ScopeConfig.Include) == 0) {
		return fmt.Errorf("%w: root domain cannot be empty", ErrMalformedTarget)
	}
	if root != "" && !isValidHostname(root) {
		return fmt.Errorf("%w: root domain '%s' is invalid", ErrMalformedTarget, root)
	}

	// Validate allowed domains
	for _, domain := range target.AllowedDomains {
		d := strings.ToLower(strings.TrimSpace(domain))
		if d == "" {
			continue
		}
		if d == "*" || d == "*." || strings.Count(d, ".") < 1 {
			return ErrWildcardTooBroad
		}
		if strings.HasPrefix(d, "*.") {
			base := strings.TrimPrefix(d, "*.")
			if !isValidHostname(base) {
				return fmt.Errorf("%w: invalid wildcard domain '%s'", ErrMalformedTarget, domain)
			}
		} else if !isValidHostname(d) {
			return fmt.Errorf("%w: invalid allowed domain '%s'", ErrMalformedTarget, domain)
		}
	}

	// Validate Advanced Scope Rules if configured
	if target.ScopeConfig != nil {
		for _, inc := range target.ScopeConfig.Include {
			if inc.Host != "" {
				if _, err := regexp.Compile(inc.Host); err != nil {
					return fmt.Errorf("%w: invalid include host regex '%s': %v", ErrMalformedTarget, inc.Host, err)
				}
			}
		}
		for _, exc := range target.ScopeConfig.Exclude {
			if exc.Host != "" {
				if _, err := regexp.Compile(exc.Host); err != nil {
					return fmt.Errorf("%w: invalid exclude host regex '%s': %v", ErrMalformedTarget, exc.Host, err)
				}
			}
		}
	}

	return nil
}

// IsInScope verifies if a given hostname and optional URL are explicitly authorized.
func (v *Validator) IsInScope(target *models.Target, hostname string, rawURL string) (bool, error) {
	decision := v.Evaluate(target, hostname, rawURL)
	if !decision.InScope {
		return false, errors.New(decision.Reason)
	}
	return true, nil
}

// Evaluate provides a detailed ScopeDecision explaining whether the request is authorized.
// Order of Evaluation (strictly fail-closed):
// Input -> Normalize -> Explicit EXCLUDE? (YES -> BLOCK) -> INCLUDE? (NO -> BLOCK; YES -> AUTHORIZED)
func (v *Validator) Evaluate(target *models.Target, hostname string, rawURL string) ScopeDecision {
	// Rule 1: Fail closed on nil target
	if target == nil {
		return ScopeDecision{InScope: false, Reason: ErrTargetNil.Error()}
	}

	// Rule 2: Target must be active
	if target.Status != "" && target.Status != models.TargetStatusActive {
		return ScopeDecision{InScope: false, Reason: ErrTargetInactive.Error()}
	}

	// Clean and normalize hostname
	host := strings.ToLower(strings.TrimSpace(hostname))

	// If URL is provided, parse and validate it
	var parsedURL *url.URL
	var protocol string = "any"
	var port string = ""
	var path string = "/"

	if rawURL != "" {
		u, err := url.Parse(rawURL)
		if err != nil {
			return ScopeDecision{InScope: false, Reason: fmt.Sprintf("%s: %v", ErrMalformedURL.Error(), err)}
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return ScopeDecision{InScope: false, Reason: fmt.Sprintf("%s: only http/https allowed", ErrMalformedURL.Error())}
		}
		protocol = strings.ToLower(u.Scheme)
		urlHost := u.Hostname()
		if urlHost == "" {
			return ScopeDecision{InScope: false, Reason: fmt.Sprintf("%s: missing host in URL", ErrMalformedURL.Error())}
		}
		// If both hostname and URL are passed, they must agree
		if host != "" && strings.ToLower(urlHost) != host {
			return ScopeDecision{InScope: false, Reason: ErrHostMismatch.Error()}
		}
		if host == "" {
			host = strings.ToLower(urlHost)
		}
		port = u.Port()
		if port == "" {
			if protocol == "https" {
				port = "443"
			} else if protocol == "http" {
				port = "80"
			}
		}
		path = u.Path
		if path == "" {
			path = "/"
		}
		parsedURL = u
	}

	// Hostname validation
	if host == "" {
		return ScopeDecision{InScope: false, Reason: ErrMalformedHost.Error()}
	}
	if !isValidHostname(host) {
		return ScopeDecision{InScope: false, Reason: fmt.Sprintf("%s: '%s'", ErrMalformedHost.Error(), host)}
	}

	// =========================================================================
	// STEP 1: EXPLICIT EXCLUDE EVALUATION (HIGHEST PRECEDENCE)
	// Explicit exclusions override broad includes.
	// E.g., *.arc.io may include api.arc.io, but community.arc.io must be blocked.
	// =========================================================================

	// A. Check simple excluded patterns
	for _, excluded := range target.ExcludedPatterns {
		ex := strings.ToLower(strings.TrimSpace(excluded))
		if ex == "" {
			continue
		}
		// Check host match against exclusion
		if matchesPattern(host, ex) {
			return ScopeDecision{InScope: false, Reason: fmt.Sprintf("%s: host explicitly excluded '%s'", ErrExcluded.Error(), ex)}
		}
		// Check URL match against exclusion if URL present
		if rawURL != "" && (strings.Contains(rawURL, ex) || (parsedURL != nil && strings.HasPrefix(parsedURL.Path, ex))) {
			return ScopeDecision{InScope: false, Reason: fmt.Sprintf("%s: URL explicitly excluded '%s'", ErrExcluded.Error(), ex)}
		}
	}

	// B. Check AdvancedScopeConfig Exclude Rules (Burp Suite format)
	if target.ScopeConfig != nil {
		for _, rule := range target.ScopeConfig.Exclude {
			if !rule.Enabled {
				continue
			}
			if matchAdvancedRule(rule, host, port, protocol, path) {
				return ScopeDecision{
					InScope: false,
					Reason:  fmt.Sprintf("%s: matched advanced exclude rule [host: %s, file: %s]", ErrExcluded.Error(), rule.Host, rule.File),
				}
			}
		}
	}

	// =========================================================================
	// STEP 2: INCLUDE EVALUATION
	// =========================================================================

	hostAuthorized := false
	matchedRule := ""

	// A. Check standard allowed list
	rootDomain := strings.ToLower(strings.TrimSpace(target.RootDomain))
	allowedList := make([]string, 0, len(target.AllowedDomains)+1)
	if rootDomain != "" {
		allowedList = append(allowedList, rootDomain)
	}
	for _, ad := range target.AllowedDomains {
		clean := strings.ToLower(strings.TrimSpace(ad))
		if clean != "" {
			allowedList = append(allowedList, clean)
		}
	}

	for _, rule := range allowedList {
		if strings.HasPrefix(rule, "*.") {
			base := strings.TrimPrefix(rule, "*.")
			if host == base || strings.HasSuffix(host, "."+base) {
				hostAuthorized = true
				matchedRule = rule
				break
			}
		} else {
			if host == rule {
				hostAuthorized = true
				matchedRule = rule
				break
			}
		}
	}

	// B. Check AdvancedScopeConfig Include Rules
	if !hostAuthorized && target.ScopeConfig != nil {
		for _, rule := range target.ScopeConfig.Include {
			if !rule.Enabled {
				continue
			}
			if matchAdvancedRule(rule, host, port, protocol, path) {
				hostAuthorized = true
				matchedRule = fmt.Sprintf("advanced_include: host=%s, file=%s", rule.Host, rule.File)
				break
			}
		}
	}

	if !hostAuthorized {
		return ScopeDecision{InScope: false, Reason: fmt.Sprintf("%s: host '%s' not in authorized scope", ErrDomainOutOfScope.Error(), host)}
	}

	// =========================================================================
	// STEP 3: URL PATH PATTERN RESTRICTIONS (if configured)
	// =========================================================================
	if len(target.AllowedURLPatterns) > 0 {
		if parsedURL == nil {
			return ScopeDecision{InScope: false, Reason: fmt.Sprintf("%s: URL required when path restrictions exist", ErrURLPathRestricted.Error())}
		}

		pathAuthorized := false
		for _, pattern := range target.AllowedURLPatterns {
			p := strings.TrimSpace(pattern)
			if p == "" {
				continue
			}
			if matchesPathPattern(path, p) {
				pathAuthorized = true
				matchedRule = fmt.Sprintf("%s && %s", matchedRule, p)
				break
			}
		}

		if !pathAuthorized {
			return ScopeDecision{InScope: false, Reason: fmt.Sprintf("%s: path '%s' not in allowed patterns", ErrURLPathRestricted.Error(), path)}
		}
	}

	return ScopeDecision{
		InScope: true,
		Reason:  "authorized",
		Matched: matchedRule,
	}
}

// matchAdvancedRule matches host regex, port regex, protocol, and file/path regex.
func matchAdvancedRule(rule models.AdvancedScopeRule, host, port, protocol, path string) bool {
	// 1. Host match (required)
	if rule.Host != "" {
		re, err := regexp.Compile("(?i)" + rule.Host)
		if err != nil || !re.MatchString(host) {
			return false
		}
	}

	// 2. Protocol match (if specified and not "any")
	if rule.Protocol != "" && rule.Protocol != "any" && rule.Protocol != "^.*$" {
		if strings.ToLower(rule.Protocol) != strings.ToLower(protocol) {
			// Also check as regex
			re, err := regexp.Compile("(?i)" + rule.Protocol)
			if err != nil || !re.MatchString(protocol) {
				return false
			}
		}
	}

	// 3. Port match (if specified and port is available)
	if rule.Port != "" && rule.Port != "^.*$" && port != "" {
		re, err := regexp.Compile(rule.Port)
		if err != nil || !re.MatchString(port) {
			return false
		}
	}

	// 4. File / Path match (if specified)
	if rule.File != "" && rule.File != "^/.*$" && rule.File != "^.*$" {
		re, err := regexp.Compile("(?i)" + rule.File)
		if err != nil || !re.MatchString(path) {
			return false
		}
	}

	return true
}

func isValidHostname(h string) bool {
	// Strip trailing dot if present
	h = strings.TrimSuffix(h, ".")
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	// Check if valid IP address
	if ip := net.ParseIP(h); ip != nil {
		return true
	}
	return hostnameRegex.MatchString(h)
}

func matchesPattern(target string, pattern string) bool {
	pattern = strings.ToLower(pattern)
	target = strings.ToLower(target)
	if pattern == target {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		return target == base || strings.HasSuffix(target, "."+base)
	}
	return false
}

func matchesPathPattern(path string, pattern string) bool {
	if pattern == "/*" || pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, prefix)
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}
	return strings.HasPrefix(path, pattern)
}

