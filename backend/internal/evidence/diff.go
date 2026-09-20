package evidence

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

var volatileHeaders = map[string]bool{
	"date":            true,
	"age":             true,
	"expires":         true,
	"last-modified":   true,
	"etag":            true,
	"cf-ray":          true,
	"cf-cache-status": true,
	"x-request-id":    true,
	"x-amz-cf-id":     true,
	"x-trace-id":      true,
	"server-timing":   true,
}

// DifferentialEngine computes 3-level comparative evidence analysis between two observations.
type DifferentialEngine struct{}

// NewDifferentialEngine creates a new differential engine.
func NewDifferentialEngine() *DifferentialEngine {
	return &DifferentialEngine{}
}

// ComputeDiff compares Evidence A and Evidence B across Level 1 (raw), Level 2 (semantic), and Level 3 (security-relevant).
func (d *DifferentialEngine) ComputeDiff(a, b *models.Evidence, filterNoise bool) (*models.EvidenceDiff, error) {
	if a == nil || b == nil {
		return nil, fmt.Errorf("both evidence items must be non-nil")
	}

	targetID := a.TargetID
	if targetID == "" {
		targetID = b.TargetID
	}
	assetID := a.AssetID
	if assetID == "" {
		assetID = b.AssetID
	}

	// 1. Level 1 - Raw Diff
	raw := models.Level1RawDiff{
		StatusFrom:      a.StatusCode,
		StatusTo:        b.StatusCode,
		StatusChanged:   a.StatusCode != b.StatusCode,
		AddedHeaders:    make(map[string]string),
		RemovedHeaders:  make(map[string]string),
		ModifiedHeaders: make(map[string]string),
	}

	if a.Response != nil && b.Response != nil {
		raw.BodyLengthDelta = b.Response.BodyLength - a.Response.BodyLength
		raw.BodyHashA = a.Response.BodyHash
		raw.BodyHashB = b.Response.BodyHash
		raw.BodyHashChanged = a.Response.BodyHash != "" && b.Response.BodyHash != "" && a.Response.BodyHash != b.Response.BodyHash
		raw.ResponseTimeDelta = b.Response.ResponseTimeMs - a.Response.ResponseTimeMs

		// Compare headers
		d.compareHeaders(a.Response.Headers, b.Response.Headers, filterNoise, &raw)
	}

	// 2. Level 2 - Semantic Diff
	semantic := models.Level2SemanticDiff{
		AuthBehaviorChanged:  false,
		ContentTypeChanged:   false,
		RedirectChanged:      false,
		ErrorPayloadDetected: false,
	}

	if (a.StatusCode == 401 || a.StatusCode == 403) && (b.StatusCode >= 200 && b.StatusCode < 300) {
		semantic.Category = "AUTHORIZATION_RESPONSE_SHIFT"
		semantic.Meaning = fmt.Sprintf("Response transitioned from restricted (%d) to accessible (%d)", a.StatusCode, b.StatusCode)
		semantic.AuthBehaviorChanged = true
	} else if (a.StatusCode >= 200 && a.StatusCode < 300) && (b.StatusCode == 401 || b.StatusCode == 403) {
		semantic.Category = "ACCESS_RESTRICTION_ENFORCED"
		semantic.Meaning = fmt.Sprintf("Response transitioned from accessible (%d) to restricted (%d)", a.StatusCode, b.StatusCode)
		semantic.AuthBehaviorChanged = true
	} else if raw.StatusChanged {
		semantic.Category = "HTTP_STATUS_SHIFT"
		semantic.Meaning = fmt.Sprintf("HTTP status code shifted from %d to %d", a.StatusCode, b.StatusCode)
	} else if raw.BodyHashChanged && raw.BodyLengthDelta != 0 {
		semantic.Category = "RESPONSE_BODY_MUTATION"
		semantic.Meaning = fmt.Sprintf("Response body mutated with size delta of %d bytes", raw.BodyLengthDelta)
	} else {
		semantic.Category = "EQUIVALENT_BEHAVIOR"
		semantic.Meaning = "Observations exhibit functionally equivalent response behavior"
	}

	if a.Response != nil && b.Response != nil {
		if a.Response.ContentType != b.Response.ContentType && a.Response.ContentType != "" && b.Response.ContentType != "" {
			semantic.ContentTypeChanged = true
		}
		if b.StatusCode >= 400 && b.StatusCode < 600 {
			semantic.ErrorPayloadDetected = true
		}
	}

	if len(a.RedirectChain) != len(b.RedirectChain) {
		semantic.RedirectChanged = true
	}

	// 3. Level 3 - Security-Relevant Diff
	security := models.Level3SecurityDiff{
		ObservationContext:   fmt.Sprintf("Comparative analysis of evidence %s vs %s", a.ID, b.ID),
		RelevanceExplanation: "No critical security deviation observed between probes.",
		RequiresFollowup:     false,
		SuggestedQuestions:   []string{},
	}

	isSecurityRelevant := false

	if semantic.AuthBehaviorChanged {
		isSecurityRelevant = true
		security.RequiresFollowup = true
		security.RelevanceExplanation = fmt.Sprintf(
			"Differential access control observed: Probe A (%s, status %d) vs Probe B (%s, status %d). Different authorization or context produced varying resource exposure.",
			a.Summary, a.StatusCode, b.Summary, b.StatusCode,
		)
		security.SuggestedQuestions = []string{
			"Does Probe B represent an unauthenticated or lower-privileged authorization context?",
			"Are the returned body contents equivalent to those served to higher-privileged sessions?",
			"Does the endpoint rely on client-side routing rather than server-side authorization enforcement?",
		}
	} else if raw.StatusChanged && (a.StatusCode == 500 || b.StatusCode == 500) {
		isSecurityRelevant = true
		security.RequiresFollowup = true
		security.RelevanceExplanation = "Server error (HTTP 500) triggered conditionally by probe variation."
		security.SuggestedQuestions = []string{
			"Does the condition represent an unhandled exception or parsing failure?",
			"Are internal stack traces, frameworks, or database errors leaked in the 500 response body?",
		}
	} else if raw.StatusChanged && (a.StatusCode == 301 || a.StatusCode == 302 || b.StatusCode == 301 || b.StatusCode == 302) {
		isSecurityRelevant = true
		security.RequiresFollowup = true
		security.RelevanceExplanation = "Redirect behavior mutated between comparative requests."
		security.SuggestedQuestions = []string{
			"Does the redirect destination validate hostnames and avoid open redirection?",
			"Does the redirect drop sensitive headers or downgrade protocols?",
		}
	}

	diff := &models.EvidenceDiff{
		ID:                 "diff-" + uuid.New().String()[:12],
		TargetID:           targetID,
		AssetID:            assetID,
		EvidenceAID:        a.ID,
		EvidenceBID:        b.ID,
		RawDiff:            raw,
		SemanticDiff:       semantic,
		SecurityDiff:       security,
		IsNoiseFiltered:    filterNoise,
		IsSecurityRelevant: isSecurityRelevant,
		ComputedAt:         time.Now().UTC(),
	}

	return diff, nil
}

func (d *DifferentialEngine) compareHeaders(hA, hB map[string]string, filterNoise bool, raw *models.Level1RawDiff) {
	normA := make(map[string]string)
	for k, v := range hA {
		normA[strings.ToLower(strings.TrimSpace(k))] = v
	}
	normB := make(map[string]string)
	for k, v := range hB {
		normB[strings.ToLower(strings.TrimSpace(k))] = v
	}

	for k, vB := range normB {
		if filterNoise && volatileHeaders[k] {
			continue
		}
		if vA, exists := normA[k]; !exists {
			raw.AddedHeaders[k] = vB
		} else if vA != vB {
			raw.ModifiedHeaders[k] = fmt.Sprintf("%s -> %s", vA, vB)
		}
	}

	for k, vA := range normA {
		if filterNoise && volatileHeaders[k] {
			continue
		}
		if _, exists := normB[k]; !exists {
			raw.RemovedHeaders[k] = vA
		}
	}
}
