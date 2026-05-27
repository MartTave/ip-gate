package ratelimit

import (
	"sync"
	"testing"
	"time"
)

func newLimiter(maxRequests int) *RateLimiter {
	return New(100*time.Millisecond, maxRequests)
}

func TestAllow_UnderLimit(t *testing.T) {
	rl := newLimiter(5)
	for i := 0; i < 5; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
}

func TestAllow_AtLimit(t *testing.T) {
	rl := newLimiter(3)
	for i := 0; i < 3; i++ {
		rl.Allow("1.2.3.4")
	}
	if rl.Allow("1.2.3.4") {
		t.Error("request after limit should be denied")
	}
}

func TestAllow_DifferentIPs(t *testing.T) {
	rl := newLimiter(2)
	rl.Allow("1.2.3.4")
	rl.Allow("1.2.3.4")
	if rl.Allow("1.2.3.4") {
		t.Error("1.2.3.4 should be rate limited")
	}
	if !rl.Allow("5.6.7.8") {
		t.Error("5.6.7.8 should have its own quota")
	}
}

func TestAllow_WindowExpiry(t *testing.T) {
	rl := New(50*time.Millisecond, 2)

	if !rl.Allow("1.2.3.4") {
		t.Fatal("first request should be allowed")
	}
	if !rl.Allow("1.2.3.4") {
		t.Fatal("second request should be allowed")
	}

	time.Sleep(60 * time.Millisecond)

	for i := 0; i < 2; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Fatalf("request %d after window expiry should be allowed", i+1)
		}
	}
}

func TestAllow_Concurrent(t *testing.T) {
	rl := newLimiter(100)
	var wg sync.WaitGroup
	allowed := make(chan bool, 200)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed <- rl.Allow("1.2.3.4")
		}()
	}
	wg.Wait()
	close(allowed)

	count := 0
	for range allowed {
		count++
	}
	if count != 100 {
		t.Errorf("expected 100 results, got %d", count)
	}
}

func TestCleanup(t *testing.T) {
	rl := New(10*time.Millisecond, 5)
	rl.Allow("1.2.3.4")
	rl.Allow("5.6.7.8")

	time.Sleep(50 * time.Millisecond)
	rl.Cleanup()

	rl.mu.Lock()
	remaining := len(rl.entries)
	rl.mu.Unlock()

	if remaining != 0 {
		t.Errorf("expected 0 entries after cleanup, got %d", remaining)
	}
}

func TestCleanup_PreservesValid(t *testing.T) {
	rl := New(1*time.Hour, 5)
	rl.Allow("1.2.3.4")
	rl.Allow("5.6.7.8")

	rl.Cleanup()

	rl.mu.Lock()
	remaining := len(rl.entries)
	rl.mu.Unlock()

	if remaining != 2 {
		t.Errorf("expected 2 entries after cleanup, got %d", remaining)
	}
}

func TestNew(t *testing.T) {
	rl := New(time.Minute, 10)
	if rl == nil {
		t.Fatal("expected non-nil limiter")
	}
	if rl.window != time.Minute {
		t.Errorf("expected window 1m, got %v", rl.window)
	}
	if rl.maxRequests != 10 {
		t.Errorf("expected maxRequests 10, got %d", rl.maxRequests)
	}
}
