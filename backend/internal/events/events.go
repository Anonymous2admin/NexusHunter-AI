package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/nexushunter-ai/nexushunter-ai/backend/internal/models"
)

// EventBus defines the interface for publishing and receiving internal security research events.
type EventBus interface {
	Publish(ctx context.Context, event models.Event) error
	Subscribe(eventType string) (<-chan models.Event, func())
	SubscribeAll() (<-chan models.Event, func())
	GetRecentEvents(limit int) []models.Event
}

// MemoryEventBus is an in-memory thread-safe pub/sub event bus.
type MemoryEventBus struct {
	mu          sync.RWMutex
	subscribers map[string][]chan models.Event
	allSubs     []chan models.Event
	history     []models.Event
	maxHistory  int
}

// NewMemoryEventBus initializes an in-memory event bus with bounded history.
func NewMemoryEventBus(maxHistory int) *MemoryEventBus {
	if maxHistory <= 0 {
		maxHistory = 500
	}
	return &MemoryEventBus{
		subscribers: make(map[string][]chan models.Event),
		allSubs:     make([]chan models.Event, 0),
		history:     make([]models.Event, 0, maxHistory),
		maxHistory:  maxHistory,
	}
}

// GenerateID produces a random cryptographic hex ID.
func GenerateID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

// Publish distributes an event to all matching subscribers and appends to event history.
func (b *MemoryEventBus) Publish(ctx context.Context, event models.Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if event.EventID == "" {
		event.EventID = GenerateID("evt")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Append to history
	if len(b.history) >= b.maxHistory {
		b.history = b.history[1:]
	}
	b.history = append(b.history, event)

	// Send to specific subscribers
	if subs, ok := b.subscribers[event.EventType]; ok {
		for _, ch := range subs {
			select {
			case ch <- event:
			default:
				// non-blocking drop if channel buffer full to prevent deadlocks
			}
		}
	}

	// Send to catch-all subscribers
	for _, ch := range b.allSubs {
		select {
		case ch <- event:
		default:
		}
	}

	return nil
}

// Subscribe listens to a specific event type. Returns channel and unsubscribe cancellation func.
func (b *MemoryEventBus) Subscribe(eventType string) (<-chan models.Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan models.Event, 64)
	b.subscribers[eventType] = append(b.subscribers[eventType], ch)

	unsub := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		subs := b.subscribers[eventType]
		for i, c := range subs {
			if c == ch {
				b.subscribers[eventType] = append(subs[:i], subs[i+1:]...)
				close(ch)
				break
			}
		}
	}

	return ch, unsub
}

// SubscribeAll listens to all event types.
func (b *MemoryEventBus) SubscribeAll() (<-chan models.Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan models.Event, 128)
	b.allSubs = append(b.allSubs, ch)

	unsub := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		for i, c := range b.allSubs {
			if c == ch {
				b.allSubs = append(b.allSubs[:i], b.allSubs[i+1:]...)
				close(ch)
				break
			}
		}
	}

	return ch, unsub
}

// GetRecentEvents retrieves the latest events recorded.
func (b *MemoryEventBus) GetRecentEvents(limit int) []models.Event {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if limit <= 0 || limit > len(b.history) {
		limit = len(b.history)
	}

	result := make([]models.Event, limit)
	start := len(b.history) - limit
	copy(result, b.history[start:])
	return result
}
