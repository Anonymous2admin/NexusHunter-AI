package planner

import (
	"context"
	"testing"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/scope"
)

func TestPlanner_ValidationAndSafety(t *testing.T) {
	validator := scope.NewValidator()
	target := &models.Target{
		ID:         "tgt-1",
		RootDomain: "example.com",
		ScopeConfig: &models.AdvancedScopeConfig{
			AdvancedMode: true,
			Include: []models.AdvancedScopeRule{
				{Enabled: true, Host: `^.*\.example\.com$`},
			},
		},
	}

	service := NewService(validator)

	// 1. Generate valid plan
	ctx := PlannerContext{
		Asset: &models.Asset{
			ID:       "asset-1",
			Hostname: "app.example.com",
		},
		JSReferences: []*models.JSReference{
			{NormalizedValue: "/api/v1/profile"},
		},
	}

	plan, err := service.GenerateInvestigationPlan(context.Background(), target, "asset-1", ctx)
	if err != nil {
		t.Fatalf("unexpected error generating plan: %v", err)
	}

	if plan.EpistemicStatus != "HYPOTHESIZED" {
		t.Errorf("plan epistemic status should be HYPOTHESIZED, got %s", plan.EpistemicStatus)
	}

	if len(plan.Steps) == 0 {
		t.Fatalf("plan should have generated verification steps")
	}

	for _, step := range plan.Steps {
		if !AllowedActionTypes[step.ActionType] {
			t.Errorf("action type %s not in allowed list", step.ActionType)
		}
	}

	// 2. Reject banned exploit step
	badPlan := &models.InvestigationPlan{
		Steps: []models.InvestigationPlanStep{
			{
				StepNumber: 1,
				ActionType: "FETCH_URL",
				Description: "inject sqli_payload into target parameter",
				TargetURL: "https://app.example.com/api",
			},
		},
	}
	if err := service.ValidatePlan(badPlan, target); err == nil {
		t.Errorf("expected plan with 'inject sqli_payload' to be rejected")
	}

	// 3. Reject invalid action type
	badActionPlan := &models.InvestigationPlan{
		Steps: []models.InvestigationPlanStep{
			{
				StepNumber: 1,
				ActionType: "EXECUTE_ARBITRARY_COMMAND",
				Description: "safe inspection",
				TargetURL: "https://app.example.com",
			},
		},
	}
	if err := service.ValidatePlan(badActionPlan, target); err == nil {
		t.Errorf("expected unauthorized action type to be rejected")
	}

	// 4. Reject premature confirmation
	prematurePlan := &models.InvestigationPlan{
		EpistemicStatus:        "CONFIRMED",
		EvidenceRequiredCount:  3,
		EvidenceSatisfiedCount: 0,
		Steps: []models.InvestigationPlanStep{
			{StepNumber: 1, ActionType: "FETCH_URL", Description: "Safe fetch", TargetURL: "https://app.example.com"},
		},
	}
	if err := service.ValidatePlan(prematurePlan, target); err == nil {
		t.Errorf("expected premature CONFIRMED status to be rejected")
	}

	// 5. Test human approval
	updatedPlan, err := service.ApproveStep(context.Background(), plan.ID, 1)
	if err != nil {
		t.Fatalf("unexpected error approving step: %v", err)
	}
	if !updatedPlan.Steps[0].ApprovedByHuman || updatedPlan.Steps[0].Status != "APPROVED" {
		t.Errorf("step should be marked APPROVED by human")
	}
}
