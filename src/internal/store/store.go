package store

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IPState represents the state of an IP
type IPState int

const (
	statePending IPState = iota
	stateAllowed
	stateDone
)

// DoneReason represents why an IP is in Done state
type DoneReason string

const (
	DoneDenied       DoneReason = "denied"
	DoneAutoRevoke   DoneReason = "automatic_revoke"
	DoneManualRevoke DoneReason = "manual_revoke"
)

// State interface - different states carry their own data
type State interface {
	isState()
}

type PendingState struct {
	RequestedAt time.Time
	ExpiresAt   time.Time
	timer       *time.Timer
}

func (*PendingState) isState() {}

type AllowedState struct {
	approval Approval
}

func (*AllowedState) isState() {}

type DoneState struct {
	DoneAt time.Time
	Reason DoneReason
}

func (*DoneState) isState() {}

// Approval interface
type Approval interface {
	GetExpiresAt() time.Time
	GetApprovedAt() time.Time
	GetTimer() *time.Timer
	SetTimer(t *time.Timer)
	Format() string
}

type ManualApproval struct {
	ExpiresAt  time.Time
	ApprovedAt time.Time
	timer      *time.Timer
}

func (m *ManualApproval) GetExpiresAt() time.Time { return m.ExpiresAt }
func (m *ManualApproval) GetApprovedAt() time.Time { return m.ApprovedAt }
func (m *ManualApproval) GetTimer() *time.Timer        { return m.timer }
func (m *ManualApproval) SetTimer(t *time.Timer)       { m.timer = t }
func (m *ManualApproval) Format() string                { return "Manual" }

type AutomaticApproval struct {
	ExpiresAt  time.Time
	ApprovedAt time.Time
	KeyName    string
	timer      *time.Timer
}

func (a *AutomaticApproval) GetExpiresAt() time.Time { return a.ExpiresAt }
func (a *AutomaticApproval) GetApprovedAt() time.Time { return a.ApprovedAt }
func (a *AutomaticApproval) GetTimer() *time.Timer        { return a.timer }
func (a *AutomaticApproval) SetTimer(t *time.Timer)       { a.timer = t }
func (a *AutomaticApproval) Format() string {
	return fmt.Sprintf("Automatic (%s)", a.KeyName)
}

// IP struct - all fields private except via methods
type IP struct {
	ip       string
	lastSeen time.Time
	state    State
}

// IP methods (state transitions)

func (ip *IP) CanRequest() bool {
	switch ip.state.(type) {
	case *PendingState:
		return false
	case *AllowedState:
		return false
	case *DoneState:
		return ip.state.(*DoneState).Reason != DoneDenied
	}
	return true
}

func (ip *IP) IsCurrentlyAllowed(now time.Time) bool {
	if as, ok := ip.state.(*AllowedState); ok {
		return now.Before(as.approval.GetExpiresAt())
	}
	return false
}

func (ip *IP) Request(expiresAt time.Time, timer *time.Timer) {
	now := time.Now()
	ip.state = &PendingState{RequestedAt: now, ExpiresAt: expiresAt, timer: timer}
}

func (ip *IP) Approve(approval Approval) {
	if ps, ok := ip.state.(*PendingState); ok && ps.timer != nil {
		ps.timer.Stop()
	}
	ip.state = &AllowedState{approval: approval}
}

func (ip *IP) Deny() error {
	if _, ok := ip.state.(*PendingState); !ok {
		return fmt.Errorf("IP must be in Pending state to deny")
	}
	if ps, ok := ip.state.(*PendingState); ok && ps.timer != nil {
		ps.timer.Stop()
	}
	ip.state = &DoneState{DoneAt: time.Now(), Reason: DoneDenied}
	return nil
}

func (ip *IP) Revoke() error {
	if _, ok := ip.state.(*AllowedState); !ok {
		return fmt.Errorf("IP must be in Allowed state to revoke")
	}
	if as, ok := ip.state.(*AllowedState); ok && as.approval.GetTimer() != nil {
		as.approval.GetTimer().Stop()
	}
	ip.state = &DoneState{DoneAt: time.Now(), Reason: DoneManualRevoke}
	return nil
}

func (ip *IP) Timeout() {
	switch s := ip.state.(type) {
	case *PendingState:
		if s.timer != nil {
			s.timer.Stop()
		}
	case *AllowedState:
		if s.approval.GetTimer() != nil {
			s.approval.GetTimer().Stop()
		}
	}
	ip.state = &DoneState{DoneAt: time.Now(), Reason: DoneAutoRevoke}
}

func (ip *IP) UpdateLastSeen() { ip.lastSeen = time.Now() }

// Getter methods

func (ip *IP) GetIP() string { return ip.ip }

func (ip *IP) GetLastSeen() time.Time { return ip.lastSeen }

func (ip *IP) GetApproval() (Approval, bool) {
	if as, ok := ip.state.(*AllowedState); ok {
		return as.approval, true
	}
	return nil, false
}

func (ip *IP) GetDoneReason() (DoneReason, bool) {
	if ds, ok := ip.state.(*DoneState); ok {
		return ds.Reason, true
	}
	return "", false
}

func (ip *IP) GetPendingRequestedAt() (time.Time, bool) {
	if ps, ok := ip.state.(*PendingState); ok {
		return ps.RequestedAt, true
	}
	return time.Time{}, false
}

func (ip *IP) GetPendingExpiresAt() (time.Time, bool) {
	if ps, ok := ip.state.(*PendingState); ok {
		return ps.ExpiresAt, true
	}
	return time.Time{}, false
}

// TTLOption represents a TTL choice for the dropdown
type TTLOption struct {
	Value    string
	Label    string
	Duration time.Duration
}

// AllowRequest for JSON parsing
type AllowRequest struct {
	IP     string `json:"ip"`
	Action string `json:"action"`
	TTL    string `json:"ttl,omitempty"`
}

// Global State
var (
	ips = make(map[string]*IP)
	rateLimiter     = make(map[string][]time.Time)
	mu              sync.Mutex

	// Environment Variables
	RequestTTLMinutes    int
	RateLimitWindowSec   int
	RateLimitMaxRequests int
	ServerPort           string
	MaxTTL               time.Duration
	PermanentKeys        map[string]string
	PermanentKeyAuthTTL  time.Duration
	PermanentKeyMaxIPs   int
	PermanentKeyIPs      map[string]map[string]bool
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

	// PERMANENT_KEYS (format: "key1:name1,key2:name2")
	PermanentKeys = make(map[string]string)
	if v := os.Getenv("PERMANENT_KEYS"); v != "" {
		pairs := strings.Split(v, ",")
		seenNames := make(map[string]bool)
		for _, pair := range pairs {
			parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				name := strings.TrimSpace(parts[1])

				if _, exists := PermanentKeys[key]; exists {
					log.Fatalf("Duplicate permanent key detected: %s", key)
				}

				if seenNames[name] {
					log.Fatalf("Duplicate permanent key name detected: %s", name)
				}
				seenNames[name] = true

				if len(key) < 64 {
					log.Printf("WARNING: Permanent key for '%s' is shorter than 64 characters (%d chars) - consider using a longer key", name, len(key))
				}
				PermanentKeys[key] = name
			}
		}
		log.Printf("Loaded %d permanent keys", len(PermanentKeys))
	}

	// PERMANENT_KEY_AUTH_TTL (default 4h)
	PermanentKeyAuthTTL = 4 * time.Hour
	if v := os.Getenv("PERMANENT_KEY_AUTH_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			PermanentKeyAuthTTL = d
		} else {
			log.Printf("Invalid PERMANENT_KEY_AUTH_TTL: %v, using default 4h", err)
		}
	}

	// PERMANENT_KEY_MAX_IPS (default 1)
	PermanentKeyMaxIPs = 1
	if v := os.Getenv("PERMANENT_KEY_MAX_IPS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			PermanentKeyMaxIPs = n
		} else {
			log.Printf("Invalid PERMANENT_KEY_MAX_IPS: %v, using default 1", err)
		}
	}

	PermanentKeyIPs = make(map[string]map[string]bool)

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

	// Clean IPs in Pending or Allowed state that have expired
	for _, ip := range ips {
		switch s := ip.state.(type) {
		case *PendingState:
			if now.After(s.ExpiresAt) {
				ip.Timeout()
			}
		case *AllowedState:
			if now.After(s.approval.GetExpiresAt()) {
				ip.Timeout()
			}
		}
	}

	// Clean rate limiter (all entries)
	for ipStr, timestamps := range rateLimiter {
		var valid []time.Time
		window := time.Duration(RateLimitWindowSec) * time.Second
		for _, t := range timestamps {
			if now.Sub(t) < window {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rateLimiter, ipStr)
		} else {
			rateLimiter[ipStr] = valid
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
func AddKnockRequest(ipStr string) bool {
	mu.Lock()
	defer mu.Unlock()

	ip, exists := ips[ipStr]
	if !exists {
		ip = &IP{ip: ipStr}
		ips[ipStr] = ip
	}

	if !ip.CanRequest() {
		return false
	}

	ttl := time.Duration(RequestTTLMinutes) * time.Minute
	expiresAt := time.Now().Add(ttl)

	timer := time.AfterFunc(ttl, func() {
		mu.Lock()
		defer mu.Unlock()
		if ip, exists := ips[ipStr]; exists {
			ip.Timeout()
		}
	})

	ip.Request(expiresAt, timer)
	return true
}

// ApproveIP approves an IP with given TTL, returns error if TTL invalid
func ApproveIP(ipStr string, ttl string) error {
	mu.Lock()
	defer mu.Unlock()

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

	ip, exists := ips[ipStr]
	if !exists || ip == nil {
		return fmt.Errorf("IP %s has no pending request", ipStr)
	}

	if _, ok := ip.state.(*PendingState); !ok {
		return fmt.Errorf("IP %s has no pending request", ipStr)
	}

	expiresAt := time.Now().Add(duration)

	approval := &ManualApproval{ExpiresAt: expiresAt, ApprovedAt: time.Now()}

	timer := time.AfterFunc(duration, func() {
		mu.Lock()
		defer mu.Unlock()
		if ip, exists := ips[ipStr]; exists {
			ip.Timeout()
		}
	})
	approval.SetTimer(timer)

	ip.Approve(approval)
	return nil
}

// ApproveIPByKey approves an IP via permanent key authentication
func ApproveIPByKey(ipStr string, keyName string) error {
	mu.Lock()
	defer mu.Unlock()

	// Check IP limit for key
	if keyIPs, exists := PermanentKeyIPs[keyName]; exists && len(keyIPs) >= PermanentKeyMaxIPs {
		// Find oldest approved IP to revoke
		var oldestIP *IP
		var oldestIPStr string
		for ipStr, _ := range keyIPs {
			if ip, exists := ips[ipStr]; exists {
				if as, ok := ip.state.(*AllowedState); ok {
					if oldestIP == nil {
						oldestIP = ip
						oldestIPStr = ipStr
					} else {
						oldestApproval, _ := oldestIP.GetApproval()
						if as.approval.GetApprovedAt().Before(oldestApproval.GetApprovedAt()) {
							oldestIP = ip
							oldestIPStr = ipStr
						}
					}
				}
			}
		}
		if oldestIP != nil {
			oldestIP.Revoke()
			delete(PermanentKeyIPs[keyName], oldestIPStr)
		}
	}

	ip, exists := ips[ipStr]
	if !exists {
		ip = &IP{ip: ipStr}
		ips[ipStr] = ip
	}

	now := time.Now()
	expiresAt := now.Add(PermanentKeyAuthTTL)

	approval := &AutomaticApproval{ExpiresAt: expiresAt, ApprovedAt: now, KeyName: keyName}

	timer := time.AfterFunc(PermanentKeyAuthTTL, func() {
		mu.Lock()
		defer mu.Unlock()
		if ip, exists := ips[ipStr]; exists {
			ip.Timeout()
		}
	})
	approval.SetTimer(timer)

	if PermanentKeyIPs[keyName] == nil {
		PermanentKeyIPs[keyName] = make(map[string]bool)
	}
	PermanentKeyIPs[keyName][ipStr] = true

	ip.Approve(approval)
	return nil
}

// DenyIP removes an IP from pending requests, returns error if no pending request
func DenyIP(ip string) error {
	mu.Lock()
	defer mu.Unlock()

	ipObj, exists := ips[ip]
	if !exists {
		return fmt.Errorf("IP %s has no pending request", ip)
	}

	return ipObj.Deny()
}

// GetPendingRequests returns a list of non-expired pending knock requests
func GetPendingRequests() []map[string]interface{} {
	mu.Lock()
	defer mu.Unlock()

	now := time.Now()
	var pending []map[string]interface{}
	for ipStr, ip := range ips {
		if ps, ok := ip.state.(*PendingState); ok && now.Before(ps.ExpiresAt) {
			pending = append(pending, map[string]interface{}{
				"ip":           ipStr,
				"requested_at": ps.RequestedAt,
				"expires_at":   ps.ExpiresAt,
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
	for ipStr, ip := range ips {
		if as, ok := ip.state.(*AllowedState); ok && now.Before(as.approval.GetExpiresAt()) {
			approved = append(approved, map[string]interface{}{
				"ip":          ipStr,
				"expires_at":  as.approval.GetExpiresAt(),
				"approved_by": as.approval.Format(),
				"approved_at": as.approval.GetApprovedAt(),
				"last_seen":   ip.lastSeen,
			})
		}
	}
	return approved
}

// CheckIPAllowed returns true if the IP is approved and not expired
func CheckIPAllowed(ipStr string) bool {
	mu.Lock()
	defer mu.Unlock()

	ip, exists := ips[ipStr]
	if !exists {
		return false
	}

	if ip.IsCurrentlyAllowed(time.Now()) {
		ip.UpdateLastSeen()
		return true
	}
	return false
}

// RevokeIP removes an approved IP, returns error if IP is not approved
func RevokeIP(ip string) error {
	mu.Lock()
	defer mu.Unlock()

	ipObj, exists := ips[ip]
	if !exists {
		return fmt.Errorf("IP %s is not approved", ip)
	}

	return ipObj.Revoke()
}
