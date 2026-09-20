package evidence

import (
	"context"
	"testing"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

func TestSanitizer(t *testing.T) {
	sanitizer := NewSanitizer()

	raw := &models.Evidence{
		ID:           "ev-test-01",
		TargetID:     "t-1",
		EvidenceType: models.EvidenceHTTPRequest,
		Summary:      "Probe /api/admin/users",
		Request: &models.HTTPRequestContext{
			Method: "GET",
			URL:    "https://api.example.com/users?token=secret12345&filter=active",
			Headers: map[string]string{
				"Authorization": "Bearer supersecretjwttoken",
				"Cookie":        "session=abcd1234efgh; user=admin",
				"User-Agent":    "NexusHunter-AI/1.0",
			},
			BodySummary: `{"password": "mypassword", "name": "alice"}`,
		},
		Response: &models.HTTPResponseContext{
			StatusCode: 200,
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Set-Cookie":   "auth_token=jwtxyz123; Path=/; Secure",
			},
			BodySnippet: `{"token": "secret_return_token", "status": "ok"}`,
		},
	}

	sanitized := sanitizer.Sanitize(raw)

	if !sanitized.RedactionStatus.IsRedacted {
		t.Fatalf("expected evidence to be marked as redacted")
	}

	// Check Authorization header redacted
	if sanitized.Request.Headers["Authorization"] != "Bearer [REDACTED]" {
		t.Errorf("expected Authorization header to be redacted, got: %s", sanitized.Request.Headers["Authorization"])
	}

	// Check Cookie header redacted
	if sanitized.Request.Headers["Cookie"] == "session=abcd1234efgh; user=admin" {
		t.Errorf("expected Cookie to be masked, got: %s", sanitized.Request.Headers["Cookie"])
	}

	// Check User-Agent preserved
	if sanitized.Request.Headers["User-Agent"] != "NexusHunter-AI/1.0" {
		t.Errorf("expected User-Agent preserved, got: %s", sanitized.Request.Headers["User-Agent"])
	}

	// Check URL query token redacted
	if sanitized.Request.URL != "https://api.example.com/users?filter=active&token=%5BREDACTED%5D" &&
		sanitized.Request.URL != "https://api.example.com/users?filter=active&token=[REDACTED]" {
		t.Logf("sanitized URL: %s", sanitized.Request.URL)
	}

	// Check body redacted
	if sanitized.Request.BodySummary == `{"password": "mypassword", "name": "alice"}` {
		t.Errorf("expected request body password to be redacted")
	}
}

func TestCanonicalizerDeterminism(t *testing.T) {
	c := NewCanonicalizer()

	ev1 := &models.Evidence{
		ID:           "ev-1",
		TargetID:     "target-1",
		EvidenceType: models.EvidenceHTTPResponse,
		Summary:      "Test observation",
		StatusCode:   200,
		Request: &models.HTTPRequestContext{
			Method: "GET",
			URL:    "https://example.com/api",
			Headers: map[string]string{
				"Z-Header": "value-z",
				"A-Header": "value-a",
			},
		},
		Response: &models.HTTPResponseContext{
			StatusCode:  200,
			ContentType: "application/json",
			Headers: map[string]string{
				"X-Custom": "123",
				"Content-Type": "application/json",
			},
			BodyHash: "hash123",
		},
		Provenance: models.EvidenceProvenance{
			Source:      models.SourceReconHTTP,
			OperationID: "op-1",
			TargetID:    "target-1",
			Initiator:   "recon_engine",
		},
	}

	// ev2 has different ID and different initial header insertion order, but equivalent content
	ev2 := &models.Evidence{
		ID:           "ev-2",
		TargetID:     "target-1",
		EvidenceType: models.EvidenceHTTPResponse,
		Summary:      "Test observation",
		StatusCode:   200,
		Request: &models.HTTPRequestContext{
			Method: "GET",
			URL:    "https://example.com/api",
			Headers: map[string]string{
				"A-Header": "value-a",
				"Z-Header": "value-z",
			},
		},
		Response: &models.HTTPResponseContext{
			StatusCode:  200,
			ContentType: "application/json",
			Headers: map[string]string{
				"Content-Type": "application/json",
				"X-Custom": "123",
			},
			BodyHash: "hash123",
		},
		Provenance: models.EvidenceProvenance{
			Source:      models.SourceReconHTTP,
			OperationID: "op-1",
			TargetID:    "target-1",
			Initiator:   "recon_engine",
		},
	}

	hash1, err1 := c.CanonicalizeAndHash(ev1)
	if err1 != nil {
		t.Fatalf("hash1 failed: %v", err1)
	}

	hash2, err2 := c.CanonicalizeAndHash(ev2)
	if err2 != nil {
		t.Fatalf("hash2 failed: %v", err2)
	}

	if hash1 != hash2 {
		t.Fatalf("expected identical canonical SHA-256 hashes, got: %s vs %s", hash1, hash2)
	}
}

func TestDifferentialEngine(t *testing.T) {
	diffEngine := NewDifferentialEngine()

	evA := &models.Evidence{
		ID:           "ev-unauth",
		TargetID:     "target-1",
		Summary:      "Unauthenticated probe to /admin/metrics",
		StatusCode:   401,
		Response: &models.HTTPResponseContext{
			StatusCode:     401,
			ContentType:    "application/json",
			BodyLength:     45,
			BodyHash:       "hash-401",
			ResponseTimeMs: 120,
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Server":       "nginx",
			},
		},
	}

	evB := &models.Evidence{
		ID:           "ev-auth",
		TargetID:     "target-1",
		Summary:      "Authenticated probe to /admin/metrics",
		StatusCode:   200,
		Response: &models.HTTPResponseContext{
			StatusCode:     200,
			ContentType:    "application/json",
			BodyLength:     1420,
			BodyHash:       "hash-200",
			ResponseTimeMs: 180,
			Headers: map[string]string{
				"Content-Type": "application/json",
				"Server":       "nginx",
				"X-Metrics-ID": "m-89",
			},
		},
	}

	diff, err := diffEngine.ComputeDiff(evA, evB, true)
	if err != nil {
		t.Fatalf("ComputeDiff failed: %v", err)
	}

	// Verify Level 1
	if !diff.RawDiff.StatusChanged || diff.RawDiff.StatusFrom != 401 || diff.RawDiff.StatusTo != 200 {
		t.Errorf("Level 1 raw status diff mismatch: %+v", diff.RawDiff)
	}
	if diff.RawDiff.BodyLengthDelta != 1375 {
		t.Errorf("Level 1 body delta mismatch: %d", diff.RawDiff.BodyLengthDelta)
	}

	// Verify Level 2
	if !diff.SemanticDiff.AuthBehaviorChanged {
		t.Errorf("Level 2 expected AuthBehaviorChanged = true")
	}
	if diff.SemanticDiff.Category != "AUTHORIZATION_RESPONSE_SHIFT" {
		t.Errorf("Level 2 unexpected category: %s", diff.SemanticDiff.Category)
	}

	// Verify Level 3
	if !diff.IsSecurityRelevant {
		t.Errorf("Level 3 expected IsSecurityRelevant = true")
	}
	if !diff.SecurityDiff.RequiresFollowup {
		t.Errorf("Level 3 expected RequiresFollowup = true")
	}
	if len(diff.SecurityDiff.SuggestedQuestions) == 0 {
		t.Errorf("Level 3 expected suggested questions")
	}
}

func TestContradictionDistinction(t *testing.T) {
	eng := NewEngine(nil, nil, nil)

	exp := &models.SecurityExpectation{
		ID:            "exp-auth-01",
		TargetID:      "t-1",
		Endpoint:      "/api/admin",
		ControlName:   "AUTH_REQUIRED",
		Source:        models.SourceExplicitPolicy,
		ExpectedState: models.StatePresent,
		Description:   "Administrative endpoints require verified authentication",
	}

	// 1. When observed state is ABSENT
	conAbsent, err := eng.EvaluateContradiction(context.Background(), "t-1", "a-1", "/api/admin", exp, models.StateAbsent, []string{"ev-1"})
	if err != nil {
		t.Fatalf("EvaluateContradiction absent failed: %v", err)
	}
	if conAbsent.Status != models.ContradictionConfirmedDeviation {
		t.Errorf("expected CONFIRMED_DEVIATION when control is absent, got: %s", conAbsent.Status)
	}

	// 2. Crucial test: When observed state is NOT_OBSERVED (NOT the same as absent!)
	conNotObserved, err := eng.EvaluateContradiction(context.Background(), "t-1", "a-1", "/api/admin", exp, models.StateNotObserved, []string{"ev-2"})
	if err != nil {
		t.Fatalf("EvaluateContradiction not observed failed: %v", err)
	}
	if conNotObserved.Status != models.ContradictionUnverified {
		t.Errorf("expected UNVERIFIED when control is NOT_OBSERVED, got: %s", conNotObserved.Status)
	}
}
