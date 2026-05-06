package store

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Data Structures
type KnockRequest struct {
	IP          string
	RequestedAt time.Time
	ExpiresAt   time.Time
	timer       *time.Timer // Timer for auto-expiry
}

type ApprovedIP struct {
	IP        string
	ExpiresAt time.Time
	timer     *time.Timer // Timer for auto-expiry
}

type AllowRequest struct {
	IP     string `json:"ip"`
	Action string `json:"action"`
	TTL    string `json:"ttl,omitempty"`
}

// TTLOption represents a TTL choice for the dropdown
type TTLOption struct {
	Value    string
	Label    string
	Duration time.Duration
}

// Global State
var (
	knockRequests   = make(map[string]KnockRequest)
	approvedIPs     = make(map[string]ApprovedIP)
	rateLimiter     = make(map[string][]time.Time)
	mu              sync.Mutex

	// Environment Variables
	RequestTTLMinutes    int
	RateLimitWindowSec   int
	RateLimitMaxRequests int
	ServerPort           string
	MaxTTL               time.Duration // Maximum allowed TTL
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

	// MAX_TTL (default 48h)
	if v := os.Getenv("MAX_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			MaxTTL = d
		} else {
			log.Printf("Invalid MAX_TTL: %v, using default 48h", err)
			MaxTTL = 48 * time.Hour
		}
	} else {
		MaxTTL = 48 * time.Hour
	}

	// Log the number of TTL options available
	options := GetTTLOptions()
	log.Printf("MAX_TTL set to %s, generated %d TTL options", MaxTTL, len(options))
}

// GetTTLOptions returns the allowed TTL values sorted by duration
func GetTTLOptions() []TTLOption {
	var options []TTLOption

	// Small fixed options (always available if < MaxTTL)
	smallOptions := []time.Duration{
		5 * time.Minute,
		10 * time.Minute,
		20 * time.Minute,
		40 * time.Minute,
		1 * time.Hour,
		2 * time.Hour,
		4 * time.Hour,
		8 * time.Hour,
		12 * time.Hour,
		24 * time.Hour,
		48 * time.Hour,
	}

	for _, d := range smallOptions {
		if d <= MaxTTL {
			options = append(options, TTLOption{
				Value:    formatTTL(d),
				Label:    formatTTL(d),
				Duration: d,
			})
		}
	}

	// Sort by duration
	sort.Slice(options, func(i, j int) bool {
		return options[i].Duration < options[j].Duration
	})

	return options
}

// formatTTL formats duration to string (e.g., "5m", "1h", "24h")
func formatTTL(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}

// CleanupExpired removes expired entries from state (safety net)
func CleanupExpired() {
	now := time.Now()

	mu.Lock()
	defer mu.Unlock()

	// Clean knock requests
	for ip, req := range knockRequests {
		if now.After(req.ExpiresAt) {
			if req.timer != nil {
				req.timer.Stop()
			}
			delete(knockRequests, ip)
		}
	}

	// Clean approved IPs
	for ip, app := range approvedIPs {
		if now.After(app.ExpiresAt) {
			if app.timer != nil {
				app.timer.Stop()
			}
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

	// Cancel existing timer if any
	if req, exists := knockRequests[ip]; exists && req.timer != nil {
		req.timer.Stop()
	}

	// Create new knock request
	ttl := time.Duration(RequestTTLMinutes) * time.Minute
	now := time.Now()
	expiresAt := now.Add(ttl)

	// Create timer for auto-expiry
	timer := time.AfterFunc(ttl, func() {
		mu.Lock()
		if req, exists := knockRequests[ip]; exists {
			if req.timer != nil {
				req.timer.Stop()
			}
			delete(knockRequests, ip)
		}
		mu.Unlock()
		log.Printf("Knock request expired for IP: %s", ip)
	})

	knockRequests[ip] = KnockRequest{
		IP:          ip,
		RequestedAt: now,
		ExpiresAt:   expiresAt,
		timer:       timer,
	}

	return true
}

// ApproveIP approves an IP with given TTL, returns error if TTL invalid
func ApproveIP(ip string, ttl string) error {
	mu.Lock()
	defer mu.Unlock()

	// CHECK: IP must have a pending knock request
	req, exists := knockRequests[ip]
	if !exists || time.Now().After(req.ExpiresAt) {
		delete(knockRequests, ip) // Clean up expired request if exists
		return fmt.Errorf("IP %s has no pending request", ip)
	}

	// Find TTL in allowed options
	options := GetTTLOptions()
	var duration time.Duration
	found := false
	for _, opt := range options {
		if opt.Value == ttl {
			duration = opt.Duration
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("invalid TTL: %s", ttl)
	}

	now := time.Now()
	expiresAt := now.Add(duration)

	// Cancel knock request timer
	if req.timer != nil {
		req.timer.Stop()
	}

	// Create timer for approved IP expiry
	timer := time.AfterFunc(duration, func() {
		mu.Lock()
		if app, exists := approvedIPs[ip]; exists {
			if app.timer != nil {
				app.timer.Stop()
			}
			delete(approvedIPs, ip)
		}
		mu.Unlock()
		log.Printf("Approved IP expired: %s", ip)
	})

	approvedIPs[ip] = ApprovedIP{
		IP:        ip,
		ExpiresAt: expiresAt,
		timer:     timer,
	}

	delete(knockRequests, ip)
	return nil
}

// DenyIP removes an IP from pending requests, returns error if no pending request
func DenyIP(ip string) error {
	mu.Lock()
	defer mu.Unlock()

	// CHECK: IP must have a pending request
	req, exists := knockRequests[ip]
	if !exists || time.Now().After(req.ExpiresAt) {
		delete(knockRequests, ip) // Clean up expired request if exists
		return fmt.Errorf("IP %s has no pending request", ip)
	}

	if req.timer != nil {
		req.timer.Stop()
	}
	delete(knockRequests, ip)
	return nil
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

// RevokeIP removes an approved IP, returns error if IP is not approved
func RevokeIP(ip string) error {
	mu.Lock()
	defer mu.Unlock()

	// CHECK: IP must be in approved list
	app, exists := approvedIPs[ip]
	if !exists {
		return fmt.Errorf("IP %s is not approved", ip)
	}

	if app.timer != nil {
		app.timer.Stop()
	}
	delete(approvedIPs, ip)
	return nil
}
