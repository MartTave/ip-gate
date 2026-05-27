package ratelimit

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu          sync.Mutex
	window      time.Duration
	maxRequests int
	entries     map[string][]time.Time
}

func New(window time.Duration, maxRequests int) *RateLimiter {
	return &RateLimiter{
		window:      window,
		maxRequests: maxRequests,
		entries:     make(map[string][]time.Time),
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	timestamps, exists := rl.entries[ip]
	if !exists {
		timestamps = []time.Time{}
	}

	var valid []time.Time
	for _, t := range timestamps {
		if now.Sub(t) < rl.window {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.maxRequests {
		rl.entries[ip] = valid
		return false
	}

	valid = append(valid, now)
	rl.entries[ip] = valid
	return true
}

func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for ip, timestamps := range rl.entries {
		var valid []time.Time
		for _, t := range timestamps {
			if now.Sub(t) < rl.window {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.entries, ip)
		} else {
			rl.entries[ip] = valid
		}
	}
}
