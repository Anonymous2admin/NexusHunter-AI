package intel

import (
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// DetectServiceChanges compares a previous service observation against current values.
func DetectServiceChanges(targetID, assetID string, prev *models.ServiceObservation, curr *models.ServiceObservation) *models.AssetChange {
	if prev == nil {
		return &models.AssetChange{
			ID:         newID("chg"),
			TargetID:   targetID,
			AssetID:    assetID,
			ChangeType: models.ChangeChangedService,
			EntityType: "service",
			EntityID:   curr.ServiceIdentity,
			PreviousState: nil,
			CurrentState: map[string]interface{}{
				"identity":    curr.ServiceIdentity,
				"status_code": curr.StatusCode,
				"page_title":  curr.PageTitle,
				"web_server":  curr.WebServer,
				"tls_version": curr.TLSVersion,
			},
			DetectedAt: time.Now().UTC(),
		}
	}

	// Check if meaningful attributes changed
	if prev.StatusCode != curr.StatusCode ||
		prev.PageTitle != curr.PageTitle ||
		prev.WebServer != curr.WebServer ||
		prev.TLSVersion != curr.TLSVersion {
		return &models.AssetChange{
			ID:         newID("chg"),
			TargetID:   targetID,
			AssetID:    assetID,
			ChangeType: models.ChangeChangedService,
			EntityType: "service",
			EntityID:   curr.ServiceIdentity,
			PreviousState: map[string]interface{}{
				"status_code": prev.StatusCode,
				"page_title":  prev.PageTitle,
				"web_server":  prev.WebServer,
				"tls_version": prev.TLSVersion,
			},
			CurrentState: map[string]interface{}{
				"status_code": curr.StatusCode,
				"page_title":  curr.PageTitle,
				"web_server":  curr.WebServer,
				"tls_version": curr.TLSVersion,
			},
			DetectedAt: time.Now().UTC(),
		}
	}

	return nil
}

// DetectTechnologyChange records a new technology observation transition.
func DetectTechnologyChange(targetID, assetID string, tech *models.TechnologyObservation, isNew bool) *models.AssetChange {
	if !isNew {
		return nil
	}
	v := ""
	if tech.Version != nil {
		v = *tech.Version
	}
	return &models.AssetChange{
		ID:         newID("chg"),
		TargetID:   targetID,
		AssetID:    assetID,
		ChangeType: models.ChangeNewTechnology,
		EntityType: "technology",
		EntityID:   tech.TechnologyName,
		PreviousState: nil,
		CurrentState: map[string]interface{}{
			"technology_name": tech.TechnologyName,
			"category":        tech.Category,
			"version":         v,
			"confidence":      string(tech.Confidence),
		},
		DetectedAt: time.Now().UTC(),
	}
}
