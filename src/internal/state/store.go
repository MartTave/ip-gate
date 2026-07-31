package state

import (
	"fmt"
	"log"
	"sync"
	"time"

	"ttl-allow-service/src/internal/config"
	"ttl-allow-service/src/internal/logger"
	"ttl-allow-service/src/internal/ratelimit"
)

type IPAuthStatus struct {
	Authorized   bool
	ExpiresAt    time.Time
	KeyName      string
	ApprovalType string
}

type AllowRequest struct {
	IP     string `json:"ip"`
	Action string `json:"action"`
	TTL    string `json:"ttl,omitempty"`
}

var (
	ips = make(map[string]*IP)
	mu  sync.Mutex

	keyIPs = make(map[string]map[string]bool)

	knockLimiter *ratelimit.RateLimiter
	authLimiter  *ratelimit.RateLimiter
)

func Init(cfg *config.Config) {
	config.Set(cfg)
	if err := logger.Init(logger.Config{
		FilePath:   cfg.Logging.FilePath,
		MaxSizeMB:  cfg.Logging.MaxSizeMB,
		MaxAgeDays: cfg.Logging.MaxAgeDays,
		MaxFiles:   cfg.Logging.MaxFiles,
	}); err != nil {
		log.Printf("WARNING: Logger initialization failed: %v", err)
	}

	knockLimiter = ratelimit.New(
		time.Duration(cfg.Rate.KnockWindowSec)*time.Second,
		cfg.Rate.KnockMaxRequests,
	)
	authLimiter = ratelimit.New(
		time.Duration(cfg.Rate.AuthWindowSec)*time.Second,
		cfg.Rate.AuthMaxRequests,
	)
}

func LookupKey(key string) (string, bool) {
	return config.Get().LookupKey(key)
}

func HasPermanentKeys() bool {
	return config.Get().HasPermanentKeys()
}

func CheckRateLimit(ip string) bool {
	if knockLimiter == nil {
		return true
	}
	return knockLimiter.Allow(ip)
}

func CheckAuthRateLimit(ip string) bool {
	if authLimiter == nil {
		return true
	}
	return authLimiter.Allow(ip)
}

func CleanupExpired() {
	mu.Lock()

	now := time.Now()
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

	mu.Unlock()

	if knockLimiter != nil {
		knockLimiter.Cleanup()
	}
	if authLimiter != nil {
		authLimiter.Cleanup()
	}
}

func GetIPAuthStatus(ipStr string) *IPAuthStatus {
	mu.Lock()
	defer mu.Unlock()

	ip, exists := ips[ipStr]
	if !exists {
		return &IPAuthStatus{Authorized: false}
	}

	if as, ok := ip.state.(*AllowedState); ok {
		now := time.Now()
		if now.Before(as.approval.GetExpiresAt()) {
			ip.UpdateLastSeen()
			keyName := ""
			if aa, ok := as.approval.(*AutomaticApproval); ok {
				keyName = aa.KeyName
			}
			return &IPAuthStatus{
				Authorized:   true,
				ExpiresAt:    as.approval.GetExpiresAt(),
				KeyName:      keyName,
				ApprovalType: as.approval.Format(),
			}
		}
	}

	return &IPAuthStatus{Authorized: false}
}

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

	ttl := time.Duration(config.Get().TTL.RequestTTLMinutes) * time.Minute
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

func ApproveIP(ipStr string, ttl string) error {
	mu.Lock()
	defer mu.Unlock()

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

func ApproveIPByKey(ipStr string, keyName string) error {
	mu.Lock()
	defer mu.Unlock()

	maxIPs := config.Get().Keys.MaxIPs
	authTTL := time.Duration(config.Get().KeyAuthTTL(keyName))
	if trackedIPs, exists := keyIPs[keyName]; exists && len(trackedIPs) >= maxIPs {
		var oldestIP *IP
		var oldestIPStr string
		for trackedIP := range trackedIPs {
			if ipObj, exists := ips[trackedIP]; exists {
				if as, ok := ipObj.state.(*AllowedState); ok {
					if oldestIP == nil {
						oldestIP = ipObj
						oldestIPStr = trackedIP
					} else {
						oldestApproval, _ := oldestIP.GetApproval()
						if as.approval.GetApprovedAt().Before(oldestApproval.GetApprovedAt()) {
							oldestIP = ipObj
							oldestIPStr = trackedIP
						}
					}
				}
			}
		}
		if oldestIP != nil {
			oldestIP.Revoke()
			delete(keyIPs[keyName], oldestIPStr)
		}
	}

	ip, exists := ips[ipStr]
	if !exists {
		ip = &IP{ip: ipStr}
		ips[ipStr] = ip
	}

	now := time.Now()
	expiresAt := now.Add(authTTL)

	approval := &AutomaticApproval{ExpiresAt: expiresAt, ApprovedAt: now, KeyName: keyName}

	timer := time.AfterFunc(authTTL, func() {
		mu.Lock()
		defer mu.Unlock()
		if ip, exists := ips[ipStr]; exists {
			ip.Timeout()
		}
	})
	approval.SetTimer(timer)

	if keyIPs[keyName] == nil {
		keyIPs[keyName] = make(map[string]bool)
	}
	keyIPs[keyName][ipStr] = true

	ip.Approve(approval)
	return nil
}

func RevokeIPByKey(ipStr string, keyName string) error {
	mu.Lock()
	defer mu.Unlock()

	ipObj, exists := ips[ipStr]
	if !exists {
		return fmt.Errorf("IP %s is not approved", ipStr)
	}

	if err := ipObj.Revoke(); err != nil {
		return err
	}

	if ips, exists := keyIPs[keyName]; exists {
		delete(ips, ipStr)
	}

	return nil
}

func DenyIP(ip string) error {
	mu.Lock()
	defer mu.Unlock()

	ipObj, exists := ips[ip]
	if !exists {
		return fmt.Errorf("IP %s has no pending request", ip)
	}

	return ipObj.Deny()
}

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

func RevokeIP(ip string) error {
	mu.Lock()
	defer mu.Unlock()

	ipObj, exists := ips[ip]
	if !exists {
		return fmt.Errorf("IP %s is not approved", ip)
	}

	return ipObj.Revoke()
}
