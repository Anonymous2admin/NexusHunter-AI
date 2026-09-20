package events

import (
	"context"
	"testing"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

func TestEventBus_PublishAndSubscribe(t *testing.T) {
	bus := NewMemoryEventBus(100)

	ch, unsub := bus.Subscribe(models.EventJobCreated)
	defer unsub()

	ctx := context.Background()
	testEvt := models.Event{
		EventType: models.EventJobCreated,
		JobID:     "job-123",
		TargetID:  "target-abc",
		Payload: map[string]interface{}{
			"scan_type": "DNS_RECON",
		},
	}

	if err := bus.Publish(ctx, testEvt); err != nil {
		t.Fatalf("failed to publish event: %v", err)
	}

	select {
	case received := <-ch:
		if received.JobID != "job-123" {
			t.Errorf("expected job_id 'job-123', got '%s'", received.JobID)
		}
		if received.EventType != models.EventJobCreated {
			t.Errorf("expected event_type '%s', got '%s'", models.EventJobCreated, received.EventType)
		}
		if received.EventID == "" {
			t.Errorf("expected non-empty event_id")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}

	// Verify history
	recent := bus.GetRecentEvents(10)
	if len(recent) != 1 {
		t.Fatalf("expected 1 recent event, got %d", len(recent))
	}
}

func TestEventBus_SubscribeAll(t *testing.T) {
	bus := NewMemoryEventBus(50)

	ch, unsub := bus.SubscribeAll()
	defer unsub()

	ctx := context.Background()
	_ = bus.Publish(ctx, models.Event{EventType: models.EventJobStarted, JobID: "job-1"})
	_ = bus.Publish(ctx, models.Event{EventType: models.EventAssetDiscovered, JobID: "job-1"})

	for i := 0; i < 2; i++ {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for event %d", i)
		}
	}
}
