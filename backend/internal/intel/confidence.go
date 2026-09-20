package intel

import (
	"fmt"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// CalculateConfidence determines the appropriate confidence level and evidence description.
func CalculateConfidence(rule *FingerprintRule, matchValue string, version *string, matchedCount int) (models.ConfidenceLevel, string) {
	confidence := rule.BaseConfidence

	// If explicit version was extracted, elevate confidence to HIGH
	if version != nil && *version != "" {
		confidence = models.ConfidenceHigh
	}

	// If multiple independent signals corroborated, elevate LOW -> MEDIUM, MEDIUM -> HIGH
	if matchedCount > 1 {
		if confidence == models.ConfidenceLow {
			confidence = models.ConfidenceMedium
		} else if confidence == models.ConfidenceMedium {
			confidence = models.ConfidenceHigh
		}
	}

	evidence := fmt.Sprintf("[%s:%s] matched %q", rule.Category, rule.MatchTarget, matchValue)
	if version != nil {
		evidence += fmt.Sprintf(" (version: %s)", *version)
	}
	if matchedCount > 1 {
		evidence += fmt.Sprintf(" (corroborated by %d signals)", matchedCount)
	}

	return confidence, evidence
}
