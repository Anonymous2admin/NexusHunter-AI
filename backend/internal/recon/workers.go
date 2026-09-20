package recon

import (
	"context"
	"sync"
	"time"
)

// RateLimiter provides token-bucket rate limiting to throttle active network requests safely.
type RateLimiter struct {
	tokens chan struct{}
	ticker *time.Ticker
	stop   chan struct{}
	once   sync.Once
}

// NewRateLimiter initializes a bounded token bucket.
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	if rps <= 0 {
		rps = 20.0
	}
	if burst <= 0 {
		burst = 30
	}

	interval := time.Duration(float64(time.Second) / rps)
	rl := &RateLimiter{
		tokens: make(chan struct{}, burst),
		ticker: time.NewTicker(interval),
		stop:   make(chan struct{}),
	}

	// Prime initial burst
	for i := 0; i < burst; i++ {
		rl.tokens <- struct{}{}
	}

	go func() {
		for {
			select {
			case <-rl.ticker.C:
				select {
				case rl.tokens <- struct{}{}:
				default:
				}
			case <-rl.stop:
				return
			}
		}
	}()

	return rl
}

// Wait blocks until a rate limit token is available or the context is cancelled.
func (rl *RateLimiter) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-rl.tokens:
		return nil
	}
}

// Stop terminates the rate limiter ticker.
func (rl *RateLimiter) Stop() {
	rl.once.Do(func() {
		rl.ticker.Stop()
		close(rl.stop)
	})
}

// WorkerPool runs a concurrent pool of worker goroutines consuming jobs from an input channel.
type WorkerPool[T any] struct {
	concurrency int
	taskChan    chan T
	wg          sync.WaitGroup
	rateLimiter *RateLimiter
}

// NewWorkerPool creates a worker pool with specified concurrency and optional rate limiter.
func NewWorkerPool[T any](concurrency int, bufferSize int, rl *RateLimiter) *WorkerPool[T] {
	if concurrency <= 0 {
		concurrency = 5
	}
	if bufferSize <= 0 {
		bufferSize = concurrency * 2
	}
	return &WorkerPool[T]{
		concurrency: concurrency,
		taskChan:    make(chan T, bufferSize),
		rateLimiter: rl,
	}
}

// Start launches worker goroutines that process items with the provided worker function.
func (p *WorkerPool[T]) Start(ctx context.Context, handler func(ctx context.Context, item T)) {
	for i := 0; i < p.concurrency; i++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case item, ok := <-p.taskChan:
					if !ok {
						return
					}
					if p.rateLimiter != nil {
						if err := p.rateLimiter.Wait(ctx); err != nil {
							return
						}
					}
					handler(ctx, item)
				}
			}
		}()
	}
}

// Submit enqueues an item into the pool.
func (p *WorkerPool[T]) Submit(ctx context.Context, item T) bool {
	select {
	case <-ctx.Done():
		return false
	case p.taskChan <- item:
		return true
	}
}

// Close closes the task channel and waits for all workers to finish.
func (p *WorkerPool[T]) Close() {
	close(p.taskChan)
	p.wg.Wait()
}
