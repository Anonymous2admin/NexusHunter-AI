package recon

import (
	"context"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
)

// Evidence represents reproducible proof of observation gathered during authorized testing.
type Evidence struct {
	ID          string                 `json:"id"`
	JobID       string                 `json:"job_id"`
	TargetID    string                 `json:"target_id"`
	Host        string                 `json:"host"`
	URL         string                 `json:"url,omitempty"`
	Source      string                 `json:"source"`
	ObservedAt  time.Time              `json:"observed_at"`
	Data        map[string]interface{} `json:"data"`
	ScopeProof  string                 `json:"scope_proof"` // Proof of scope authorization rule
}

// Scanner defines the contract for passive reconnaissance modules.
// Active and destructive capabilities are strictly forbidden by architectural mandate.
type Scanner interface {
	Name() string
	Type() string
	// Run executes an authorized reconnaissance pass against an explicitly validated target.
	Run(ctx context.Context, target *models.Target, validator scope.ScopeService) ([]Evidence, error)
}
