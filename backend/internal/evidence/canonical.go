package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// Canonicalizer converts sanitized evidence into a deterministic canonical representation and computes its SHA-256 integrity hash.
type Canonicalizer struct{}

// NewCanonicalizer creates a canonicalizer.
func NewCanonicalizer() *Canonicalizer {
	return &Canonicalizer{}
}

// CanonicalizeAndHash generates the deterministic JSON string and computes the SHA-256 hash.
// Updates ev.CanonicalRepresentation and ev.SHA256, returning the computed hash.
func (c *Canonicalizer) CanonicalizeAndHash(ev *models.Evidence) (string, error) {
	if ev == nil {
		return "", nil
	}

	canonicalMap := c.buildCanonicalMap(ev)
	canonicalBytes, err := json.Marshal(canonicalMap)
	if err != nil {
		return "", err
	}

	canonicalStr := string(canonicalBytes)
	hasher := sha256.New()
	hasher.Write(canonicalBytes)
	hashHex := hex.EncodeToString(hasher.Sum(nil))

	ev.CanonicalRepresentation = canonicalStr
	ev.SHA256 = hashHex
	return hashHex, nil
}

func (c *Canonicalizer) buildCanonicalMap(ev *models.Evidence) map[string]interface{} {
	m := make(map[string]interface{})

	// Structural identities
	m["target_id"] = ev.TargetID
	m["asset_id"] = ev.AssetID
	m["observation_id"] = ev.ObservationID
	m["source"] = string(ev.Source)
	m["evidence_type"] = string(ev.EvidenceType)
	m["summary"] = strings.TrimSpace(ev.Summary)
	m["status_code"] = ev.StatusCode

	// Request normalization
	if ev.Request != nil {
		reqMap := make(map[string]interface{})
		reqMap["method"] = strings.ToUpper(strings.TrimSpace(ev.Request.Method))
		reqMap["url"] = strings.TrimSpace(ev.Request.URL)
		reqMap["headers"] = c.normalizeHeaders(ev.Request.Headers)
		reqMap["body_summary"] = strings.TrimSpace(ev.Request.BodySummary)
		reqMap["body_length"] = ev.Request.BodyLength
		reqMap["is_authenticated"] = ev.Request.IsAuthenticated
		reqMap["auth_context_role"] = ev.Request.AuthContextRole
		m["request"] = reqMap
	}

	// Response normalization
	if ev.Response != nil {
		respMap := make(map[string]interface{})
		respMap["status_code"] = ev.Response.StatusCode
		respMap["headers"] = c.normalizeHeaders(ev.Response.Headers)
		respMap["body_snippet"] = strings.TrimSpace(ev.Response.BodySnippet)
		respMap["body_length"] = ev.Response.BodyLength
		respMap["body_hash"] = ev.Response.BodyHash
		respMap["content_type"] = strings.ToLower(strings.TrimSpace(ev.Response.ContentType))
		m["response"] = respMap
	}

	// Relevant headers
	if len(ev.RelevantHeaders) > 0 {
		m["relevant_headers"] = c.normalizeHeaders(ev.RelevantHeaders)
	}

	// Redirect chain
	if len(ev.RedirectChain) > 0 {
		m["redirect_chain"] = ev.RedirectChain
	}

	// DNS Context
	if ev.DNSContext != nil {
		dnsMap := make(map[string]interface{})
		dnsMap["hostname"] = strings.ToLower(strings.TrimSpace(ev.DNSContext.Hostname))
		sortedIPs := append([]string{}, ev.DNSContext.IPAddresses...)
		sort.Strings(sortedIPs)
		dnsMap["ip_addresses"] = sortedIPs
		sortedCNAMEs := append([]string{}, ev.DNSContext.CNAMEs...)
		sort.Strings(sortedCNAMEs)
		dnsMap["cnames"] = sortedCNAMEs
		m["dns_context"] = dnsMap
	}

	// Scope decision
	scopeMap := make(map[string]interface{})
	scopeMap["is_in_scope"] = ev.ScopeDecision.IsInScope
	scopeMap["evaluated_host"] = strings.ToLower(strings.TrimSpace(ev.ScopeDecision.EvaluatedHost))
	scopeMap["rule_matched"] = ev.ScopeDecision.RuleMatched
	m["scope_decision"] = scopeMap

	// Provenance
	provMap := make(map[string]interface{})
	provMap["source"] = string(ev.Provenance.Source)
	provMap["operation_id"] = ev.Provenance.OperationID
	provMap["target_id"] = ev.Provenance.TargetID
	provMap["asset_id"] = ev.Provenance.AssetID
	provMap["initiator"] = ev.Provenance.Initiator
	m["provenance"] = provMap

	return m
}

func (c *Canonicalizer) normalizeHeaders(h map[string]string) map[string]string {
	if len(h) == 0 {
		return map[string]string{}
	}

	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, strings.ToLower(strings.TrimSpace(k)))
	}
	sort.Strings(keys)

	norm := make(map[string]string, len(h))
	for _, k := range keys {
		// Find original key matching lower
		for origK, v := range h {
			if strings.ToLower(strings.TrimSpace(origK)) == k {
				norm[k] = strings.TrimSpace(v)
				break
			}
		}
	}
	return norm
}
