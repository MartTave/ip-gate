package store

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"time"
)

// Data Structures
type KnockRequest struct {
	IP          string
	RequestedAt time.Time
	ExpiresAt   time.Time
}

type ApprovedIP struct {
	IP        string
	ExpiresAt time.Time
}

type AllowRequest struct {
	IP     string `json:"ip"`
	Action string `json:"action"`
	TTL    string `json:"ttl,omitempty"`
}

// Global State
var (
	knockRequests   = make(map[string]KnockRequest)
	approvedIPs     = make(map[string]ApprovedIP)
	rateLimiter     = make(map[string][]time.Time)
	mu              sync.Mutex
	allowedTTLs     = map[string]time.Duration{
		"5m":  5 * time.Minute,
		"30m": 30 * time.Minute,
		"1h":  1 * time.Hour,
		"2h":  2 * time.Hour,
		"5h":  5 * time.Hour,
		"12h": 12 * time.Hour,
		"24h": 24 * time.Hour,
	}

	// Environment Variables
	RequestTTLMinutes    int
	RateLimitWindowSec   int
	RateLimitMaxRequests int
	ServerPort           string
)

// LoadEnv loads environment variables with defaults
func LoadEnv() {
	// REQUEST_TTL_MINUTES
	if v := os.Getenv("REQUEST_TTL_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			RequestTTLMinutes = n
		} else {
			log.Printf("Invalid REQUEST_TTL_MINUTES: %v, using default 5", err)
			RequestTTLMinutes = 5
		}
	} else {
		RequestTTLMinutes = 5
	}

	// RATE_LIMIT_WINDOW_SEC
	if v := os.Getenv("RATE_LIMIT_WINDOW_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			RateLimitWindowSec = n
		} else {
			log.Printf("Invalid RATE_LIMIT_WINDOW_SEC: %v, using default 60", err)
			RateLimitWindowSec = 60
		}
	} else {
		RateLimitWindowSec = 60
	}

	// RATE_LIMIT_MAX_REQUESTS
	if v := os.Getenv("RATE_LIMIT_MAX_REQUESTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			RateLimitMaxRequests = n
		} else {
			log.Printf("Invalid RATE_LIMIT_MAX_REQUESTS: %v, using default 3", err)
			RateLimitMaxRequests = 3
		}
	} else {
		RateLimitMaxRequests = 3
	}

	// PORT
	ServerPort = os.Getenv("PORT")
	if ServerPort == "" {
		ServerPort = "8080"
	}
}

// CleanupExpired removes expired entries from state
func CleanupExpired() {
	now := time.Now()

	mu.Lock()
	defer mu.Unlock()

	// Clean knock requests
	for ip, req := range knockRequests {
		if now.After(req.ExpiresAt) {
			delete(knockRequests, ip)
		}
	}

	// Clean approved IPs
	for ip, app := range approvedIPs {
		if now.After(app.ExpiresAt) {
			delete(approvedIPs, ip)
		}
	}

	// Clean rate limiter
	for ip, timestamps := range rateLimiter {
		var valid []time.Time
		window := time.Duration(RateLimitWindowSec) * time.Second
		for _, t := range timestamps {
			if now.Sub(t) < window {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rateLimiter, ip)
		} else {
			rateLimiter[ip] = valid
		}
	}
}

// CheckRateLimit returns false if IP has exceeded rate limit
func CheckRateLimit(ip string) bool {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	window := time.Duration(RateLimitWindowSec) * time.Second
	maxRequests := RateLimitMaxRequests

	timestamps, exists := rateLimiter[ip]
	if !exists {
		timestamps = []time.Time{}
	}

	// Filter valid timestamps within window
	var valid []time.Time
	for _, t := range timestamps {
		if now.Sub(t) < window {
			valid = append(valid, t)
		}
	}

	if len(valid) >= maxRequests {
		rateLimiter[ip] = valid
		return false
	}

	valid = append(valid, now)
	rateLimiter[ip] = valid
	return true
}

// AddKnockRequest adds a new knock request for IP, returns false if already pending
func AddKnockRequest(ip string) bool {
	mu.Lock()
	defer mu.Unlock()

	// Check for existing pending request
	if req, exists := knockRequests[ip]; exists && time.Now().Before(req.ExpiresAt) {
		return false
	}

	// Create new knock request
	ttl := time.Duration(RequestTTLMinutes) * time.Minute
	now := time.Now()
	knockRequests[ip] = KnockRequest{
		IP:          ip,
		RequestedAt: now,
		ExpiresAt:   now.Add(ttl),
	}

	return true
}

// ApproveIP approves an IP with given TTL, returns error if TTL invalid
func ApproveIP(ip string, ttl string) error {
	mu.Lock()
	defer mu.Unlock()

	duration, ok := allowedTTLs[ttl]
	if !ok {
		return fmt.Errorf("invalid TTL: %s", ttl)
	}

	now := time.Now()
	approvedIPs[ip] = ApprovedIP{
		IP:        ip,
		ExpiresAt: now.Add(duration),
	}
	delete(knockRequests, ip)
	return nil
}

// DenyIP removes an IP from pending requests
func DenyIP(ip string) {
	mu.Lock()
	defer mu.Unlock()
	delete(knockRequests, ip)
}

// GetPendingRequests returns a list of non-expired pending knock requests
func GetPendingRequests() []map[string]interface{} {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	var pending []map[string]interface{}
	for ip, req := range knockRequests {
		if now.Before(req.ExpiresAt) {
			pending = append(pending, map[string]interface{}{
				"ip":           ip,
				"requested_at": req.RequestedAt,
				"expires_at":   req.ExpiresAt,
			})
		}
	}
	return pending
}

// GetApprovedIPs returns a list of non-expired approved IPs
func GetApprovedIPs() []map[string]interface{} {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	var approved []map[string]interface{}
	for ip, app := range approvedIPs {
		if now.Before(app.ExpiresAt) {
			approved = append(approved, map[string]interface{}{
				"ip":         ip,
				"expires_at": app.ExpiresAt,
			})
		}
	}
	return approved
}

// CheckIPAllowed returns true if the IP is approved and not expired
func CheckIPAllowed(ip string) bool {
	mu.Lock()
	defer mu.Unlock()

	app, exists := approvedIPs[ip]
	if !exists {
		return false
	}
	return time.Now().Before(app.ExpiresAt)
}

// RevokeIP removes an approved IP
func RevokeIP(ip string) {
	mu.Lock()
	defer mu.Unlock()
	delete(approvedIPs, ip)
}
