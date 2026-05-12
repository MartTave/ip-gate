package store

import (
	"testing"
	"time"
)

// resetTestState resets all global state for testing
func resetTestState() {
	ips = make(map[string]*IP)
	rateLimiter = make(map[string][]time.Time)
	PermanentKeys = make(map[string]string)
	PermanentKeyIPs = make(map[string]map[string]bool)
	PermanentKeyAuthTTL = 4 * time.Hour
	PermanentKeyMaxIPs = 1
	RequestTTLMinutes = 5
	RateLimitWindowSec = 60
	RateLimitMaxRequests = 20
	MaxTTL = 48 * time.Hour
}

// createPendingIP creates an IP in Pending state
func createPendingIP(ipStr string, expiresIn time.Duration) *IP {
	ip := &IP{ip: ipStr}
	timer := time.AfterFunc(expiresIn, func() {})
	ip.Request(time.Now().Add(expiresIn), timer)
	ips[ipStr] = ip
	return ip
}

// createAllowedIPManual creates an IP in Allowed state with ManualApproval
func createAllowedIPManual(ipStr string, expiresIn time.Duration) *IP {
	ip := createPendingIP(ipStr, expiresIn)
	approval := &ManualApproval{
		ExpiresAt: time.Now().Add(expiresIn),
		ApprovedAt: time.Now(),
	}
	timer := time.AfterFunc(expiresIn, func() {})
	approval.SetTimer(timer)
	ip.Approve(approval)
	return ip
}

// createAllowedIPAutomatic creates an IP in Allowed state with AutomaticApproval
func createAllowedIPAutomatic(ipStr string, keyName string, expiresIn time.Duration) *IP {
	ip := &IP{ip: ipStr}
	ips[ipStr] = ip

	approval := &AutomaticApproval{
		ExpiresAt: time.Now().Add(expiresIn),
		ApprovedAt: time.Now(),
		KeyName:    keyName,
	}
	timer := time.AfterFunc(expiresIn, func() {})
	approval.SetTimer(timer)

	if PermanentKeyIPs[keyName] == nil {
		PermanentKeyIPs[keyName] = make(map[string]bool)
	}
	PermanentKeyIPs[keyName][ipStr] = true

	ip.Approve(approval)
	return ip
}

// createDoneIP creates an IP in Done state
func createDoneIP(ipStr string, reason DoneReason) *IP {
	ip := &IP{ip: ipStr}
	ips[ipStr] = ip
	ip.state = &DoneState{DoneAt: time.Now(), Reason: reason}
	return ip
}

// Test: AddKnockRequest success
func TestAddKnockRequest_Success(t *testing.T) {
	resetTestState()
	defer resetTestState()

	result := AddKnockRequest("1.2.3.4")
	if !result {
		t.Error("Expected knock request to succeed")
	}

	ip, exists := ips["1.2.3.4"]
	if !exists {
		t.Fatal("IP not found in map")
	}
	if _, ok := ip.state.(*PendingState); !ok {
		t.Errorf("Expected Pending state, got %T", ip.state)
	}
}

// Test: AddKnockRequest duplicate
func TestAddKnockRequest_Duplicate(t *testing.T) {
	resetTestState()
	defer resetTestState()

	AddKnockRequest("1.2.3.4")
	result := AddKnockRequest("1.2.3.4")
	if result {
		t.Error("Expected duplicate knock request to fail")
	}
}

// Test: AddKnockRequest after revoke (should succeed)
func TestAddKnockRequest_AfterRevoke(t *testing.T) {
	resetTestState()
	defer resetTestState()

	// Create allowed IP and then revoke it
	createAllowedIPManual("1.2.3.4", time.Hour)
	RevokeIP("1.2.3.4")

	result := AddKnockRequest("1.2.3.4")
	if !result {
		t.Error("Expected knock request after revoke to succeed")
	}

	ip := ips["1.2.3.4"]
	if _, ok := ip.state.(*PendingState); !ok {
		t.Errorf("Expected Pending state after re-request, got %T", ip.state)
	}
}

// Test: AddKnockRequest after deny (should fail)
func TestAddKnockRequest_AfterDeny(t *testing.T) {
	resetTestState()
	defer resetTestState()

	AddKnockRequest("1.2.3.4")
	DenyIP("1.2.3.4")

	result := AddKnockRequest("1.2.3.4")
	if result {
		t.Error("Expected knock request after deny to fail")
	}
}

// Test: ApproveIP success
func TestApproveIP_Success(t *testing.T) {
	resetTestState()
	defer resetTestState()

	AddKnockRequest("1.2.3.4")
	err := ApproveIP("1.2.3.4", "1h")
	if err != nil {
		t.Errorf("Expected approve to succeed, got: %v", err)
	}

	ip := ips["1.2.3.4"]
	if _, ok := ip.state.(*AllowedState); !ok {
		t.Errorf("Expected Allowed state, got %T", ip.state)
	}

	if approval, ok := ip.GetApproval(); ok {
		if approval.Format() != "Manual" {
			t.Errorf("Expected Manual approval, got: %s", approval.Format())
		}
	} else {
		t.Error("Expected approval to exist")
	}
}

// Test: ApproveIP invalid TTL
func TestApproveIP_InvalidTTL(t *testing.T) {
	resetTestState()
	defer resetTestState()

	AddKnockRequest("1.2.3.4")
	err := ApproveIP("1.2.3.4", "99h")
	if err == nil {
		t.Error("Expected error for invalid TTL")
	}
}

// Test: ApproveIP no pending request
func TestApproveIP_NoPending(t *testing.T) {
	resetTestState()
	defer resetTestState()

	err := ApproveIP("1.2.3.4", "1h")
	if err == nil {
		t.Error("Expected error for no pending request")
	}
}

// Test: DenyIP success
func TestDenyIP_Success(t *testing.T) {
	resetTestState()
	defer resetTestState()

	AddKnockRequest("1.2.3.4")
	err := DenyIP("1.2.3.4")
	if err != nil {
		t.Errorf("Expected deny to succeed, got: %v", err)
	}

	ip := ips["1.2.3.4"]
	if ds, ok := ip.state.(*DoneState); ok {
		if ds.Reason != DoneDenied {
			t.Errorf("Expected DoneDenied, got: %s", ds.Reason)
		}
	} else {
		t.Errorf("Expected Done state, got %T", ip.state)
	}
}

// Test: DenyIP not pending
func TestDenyIP_NotPending(t *testing.T) {
	resetTestState()
	defer resetTestState()

	err := DenyIP("1.2.3.4")
	if err == nil {
		t.Error("Expected error for IP not in pending")
	}
}

// Test: RevokeIP success
func TestRevokeIP_Success(t *testing.T) {
	resetTestState()
	defer resetTestState()

	createAllowedIPManual("1.2.3.4", time.Hour)
	err := RevokeIP("1.2.3.4")
	if err != nil {
		t.Errorf("Expected revoke to succeed, got: %v", err)
	}

	ip := ips["1.2.3.4"]
	if ds, ok := ip.state.(*DoneState); ok {
		if ds.Reason != DoneManualRevoke {
			t.Errorf("Expected DoneManualRevoke, got: %s", ds.Reason)
		}
	} else {
		t.Errorf("Expected Done state, got %T", ip.state)
	}
}

// Test: RevokeIP not allowed
func TestRevokeIP_NotAllowed(t *testing.T) {
	resetTestState()
	defer resetTestState()

	err := RevokeIP("1.2.3.4")
	if err == nil {
		t.Error("Expected error for IP not allowed")
	}
}

// Test: CheckIPAllowed allowed IP
func TestCheckIPAllowed_AllowedIP(t *testing.T) {
	resetTestState()
	defer resetTestState()

	createAllowedIPManual("1.2.3.4", time.Hour)

	result := CheckIPAllowed("1.2.3.4")
	if !result {
		t.Error("Expected IP to be allowed")
	}

	// Check LastSeen was updated
	ip := ips["1.2.3.4"]
	if ip.lastSeen.IsZero() {
		t.Error("Expected LastSeen to be updated")
	}
}

// Test: CheckIPAllowed expired
func TestCheckIPAllowed_Expired(t *testing.T) {
	resetTestState()
	defer resetTestState()

	ip := createAllowedIPManual("1.2.3.4", time.Hour)
	// Manually expire
	if as, ok := ip.state.(*AllowedState); ok {
		manual := as.approval.(*ManualApproval)
		manual.ExpiresAt = time.Now().Add(-time.Hour)
	}

	result := CheckIPAllowed("1.2.3.4")
	if result {
		t.Error("Expected IP to not be allowed (expired)")
	}
}

// Test: CheckIPAllowed not in list
func TestCheckIPAllowed_NotInList(t *testing.T) {
	resetTestState()
	defer resetTestState()

	result := CheckIPAllowed("1.2.3.4")
	if result {
		t.Error("Expected false for unknown IP")
	}
}

// Test: ApproveIPByKey success
func TestApproveIPByKey_Success(t *testing.T) {
	resetTestState()
	defer resetTestState()

	PermanentKeys["abc123"] = "test-key"

	err := ApproveIPByKey("1.2.3.4", "abc123")
	if err != nil {
		t.Errorf("Expected key auth to succeed, got: %v", err)
	}

	ip := ips["1.2.3.4"]
	if _, ok := ip.state.(*AllowedState); !ok {
		t.Errorf("Expected Allowed state, got %T", ip.state)
	}

	if approval, ok := ip.GetApproval(); ok {
		if approval.Format() != "Automatic (test-key)" {
			t.Errorf("Expected Automatic (test-key), got: %s", approval.Format())
		} else {
			t.Logf("Got: %s", approval.Format())
		}
	}
}

// Test: ApproveIPByKey invalid key
func TestApproveIPByKey_InvalidKey(t *testing.T) {
	resetTestState()
	defer resetTestState()

	// Don't add the key to PermanentKeys
	err := ApproveIPByKey("1.2.3.4", "nonexistent")
	if err == nil {
		t.Error("Expected error for invalid key")
	}
}

// Test: ApproveIPByKey IP rotation
func TestApproveIPByKey_IPRotation(t *testing.T) {
	resetTestState()
	defer resetTestState()

	PermanentKeys["abc123"] = "test-key"
	PermanentKeyMaxIPs = 1

	// First IP
	ApproveIPByKey("1.2.3.4", "abc123")

	// Second IP (should revoke first)
	ApproveIPByKey("5.6.7.8", "abc123")

	if CheckIPAllowed("1.2.3.4") {
		t.Error("Expected first IP to be revoked")
	}
	if !CheckIPAllowed("5.6.7.8") {
		t.Error("Expected second IP to be allowed")
	}
}

// Test: State transitions table-driven
func TestStateTransitions(t *testing.T) {
	tests := []struct {
		name       string
		setup      func() string
		action     func(string) error
		checkState func(*IP) bool
		wantErr    bool
	}{
		{
			name: "Pending to Allowed",
			setup: func() string {
				ip := "1.2.3.4"
				createPendingIP(ip, time.Hour)
				return ip
			},
			action: func(ip string) error {
				return ApproveIP(ip, "1h")
			},
			checkState: func(ip *IP) bool {
				_, ok := ip.state.(*AllowedState)
				return ok
			},
			wantErr: false,
		},
		{
			name: "Pending to Denied",
			setup: func() string {
				ip := "1.2.3.4"
				createPendingIP(ip, time.Hour)
				return ip
			},
			action: func(ip string) error {
				return DenyIP(ip)
			},
			checkState: func(ip *IP) bool {
				if ds, ok := ip.state.(*DoneState); ok {
					return ds.Reason == DoneDenied
				}
				return false
			},
			wantErr: false,
		},
		{
			name: "Allowed to Revoked",
			setup: func() string {
				ip := "1.2.3.4"
				createAllowedIPManual(ip, time.Hour)
				return ip
			},
			action: func(ip string) error {
				return RevokeIP(ip)
			},
			checkState: func(ip *IP) bool {
				if ds, ok := ip.state.(*DoneState); ok {
					return ds.Reason == DoneManualRevoke
				}
				return false
			},
			wantErr: false,
		},
		{
			name: "Denied cannot re-request",
			setup: func() string {
				ip := "1.2.3.4"
				createDoneIP(ip, DoneDenied)
				return ip
			},
			action: func(ip string) error {
				result := AddKnockRequest(ip)
				if !result {
					return nil // This is expected
				}
				return nil
			},
			checkState: func(ip *IP) bool {
				_, ok := ip.state.(*DoneState)
				return ok
			},
			wantErr: false,
		},
		{
			name: "Revoked can re-request",
			setup: func() string {
				ip := "1.2.3.4"
				createDoneIP(ip, DoneManualRevoke)
				return ip
			},
			action: func(ip string) error {
				result := AddKnockRequest(ip)
				if !result {
					t.Errorf("Expected re-request after revoke to succeed")
				}
				return nil
			},
			checkState: func(ip *IP) bool {
				_, ok := ip.state.(*PendingState)
				return ok
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetTestState()
			defer resetTestState()

			ipStr := tt.setup()
			err := tt.action(ipStr)

			if (err != nil) != tt.wantErr {
				t.Errorf("action() error = %v, wantErr %v", err, tt.wantErr)
			}

			ip := ips[ipStr]
			if !tt.checkState(ip) {
				t.Errorf("State check failed for: %s", tt.name)
			}
		})
	}
}

// Test: Rate limiting
func TestCheckRateLimit(t *testing.T) {
	resetTestState()
	defer resetTestState()

	// First request - should pass
	if !CheckRateLimit("1.2.3.4") {
		t.Error("Expected first request to pass rate limit")
	}

	// Second request - should pass
	if !CheckRateLimit("1.2.3.4") {
		t.Error("Expected second request to pass rate limit")
	}

	// Third request - should pass (limit is 5)
	if !CheckRateLimit("1.2.3.4") {
		t.Error("Expected third request to pass rate limit")
	}

	// Fourth request - should pass (limit is 5)
	if !CheckRateLimit("1.2.3.4") {
		t.Error("Expected fourth request to pass rate limit")
	}

	// Fifth request - should pass (limit is 5)
	if !CheckRateLimit("1.2.3.4") {
		t.Error("Expected fifth request to pass rate limit")
	}

	// Sixth request - should fail
	if CheckRateLimit("1.2.3.4") {
		t.Error("Expected sixth request to fail rate limit")
	}
}

// Test: GetPendingRequests
func TestGetPendingRequests(t *testing.T) {
	resetTestState()
	defer resetTestState()

	AddKnockRequest("1.2.3.4")
	AddKnockRequest("5.6.7.8")

	pending := GetPendingRequests()
	if len(pending) != 2 {
		t.Errorf("Expected 2 pending requests, got %d", len(pending))
	}
}

// Test: GetApprovedIPs
func TestGetApprovedIPs(t *testing.T) {
	resetTestState()
	defer resetTestState()

	createAllowedIPManual("1.2.3.4", time.Hour)

	approved := GetApprovedIPs()
	if len(approved) != 1 {
		t.Errorf("Expected 1 approved IP, got %d", len(approved))
	}

	if approved[0]["approved_by"] != "Manual" {
		t.Errorf("Expected approved_by=Manual, got: %v", approved[0]["approved_by"])
	}
}

// Test: CanRequest logic
func TestCanRequest(t *testing.T) {
	resetTestState()
	defer resetTestState()

	// New IP (no state) - can request
	ip := &IP{ip: "1.2.3.4"}
	ips["1.2.3.4"] = ip
	if !ip.CanRequest() {
		t.Error("Expected new IP to be able to request")
	}

	// Reset and test pending
	resetTestState()
	ip = createPendingIP("1.2.3.4", time.Hour)
	if ip.CanRequest() {
		t.Error("Expected pending IP to not be able to request")
	}

	// Reset and test allowed
	resetTestState()
	ip = createAllowedIPManual("1.2.3.4", time.Hour)
	if ip.CanRequest() {
		t.Error("Expected allowed IP to not be able to request")
	}

	// Reset and test done (denied)
	resetTestState()
	ip = createDoneIP("1.2.3.4", DoneDenied)
	if ip.CanRequest() {
		t.Error("Expected denied IP to not be able to request")
	}

	// Reset and test done (revoked)
	resetTestState()
	ip = createDoneIP("1.2.3.4", DoneManualRevoke)
	if !ip.CanRequest() {
		t.Error("Expected revoked IP to be able to request")
	}
}

// Test: Timeout pending
func TestTimeout_Pending(t *testing.T) {
	resetTestState()
	defer resetTestState()

	ip := createPendingIP("1.2.3.4", time.Hour)
	ip.Timeout()

	if ds, ok := ip.state.(*DoneState); ok {
		if ds.Reason != DoneAutoRevoke {
			t.Errorf("Expected DoneAutoRevoke, got: %s", ds.Reason)
		}
	} else {
		t.Errorf("Expected Done state after timeout, got %T", ip.state)
	}
}

// Test: Timeout allowed
func TestTimeout_Allowed(t *testing.T) {
	resetTestState()
	defer resetTestState()

	ip := createAllowedIPManual("1.2.3.4", time.Hour)
	ip.Timeout()

	if ds, ok := ip.state.(*DoneState); ok {
		if ds.Reason != DoneAutoRevoke {
			t.Errorf("Expected DoneAutoRevoke, got: %s", ds.Reason)
		}
	} else {
		t.Errorf("Expected Done state after timeout, got %T", ip.state)
	}
}

// Test: CleanupExpired
func TestCleanupExpired(t *testing.T) {
	resetTestState()
	defer resetTestState()

	// Create expired pending IP
	ip1 := createPendingIP("1.2.3.4", time.Hour)
	if ps, ok := ip1.state.(*PendingState); ok {
		ps.ExpiresAt = time.Now().Add(-time.Hour)
	}

	// Create expired allowed IP
	ip2 := createAllowedIPManual("5.6.7.8", time.Hour)
	if as, ok := ip2.state.(*AllowedState); ok {
		if manual, ok := as.approval.(*ManualApproval); ok {
			manual.ExpiresAt = time.Now().Add(-time.Hour)
		}
	}

	// Add rate limiter entry with only expired timestamps
	rateLimiter["9.10.11.12"] = []time.Time{
		time.Now().Add(-time.Hour * 2), // expired
		time.Now().Add(-time.Hour * 3), // expired
	}

	CleanupExpired()

	// Check pending IP is now Done
	if ds, ok := ip1.state.(*DoneState); !ok || ds.Reason != DoneAutoRevoke {
		t.Error("Expected pending IP to be timed out")
	}

	// Check allowed IP is now Done
	if ds, ok := ip2.state.(*DoneState); !ok || ds.Reason != DoneAutoRevoke {
		t.Error("Expected allowed IP to be timed out")
	}

	// Check rate limiter cleaned up (all timestamps expired)
	if _, exists := rateLimiter["9.10.11.12"]; exists {
		t.Error("Expected rate limiter entry to be cleaned up")
	}
}

// Test: CleanupExpired preserves non-expired entries
func TestCleanupExpired_PreservesValid(t *testing.T) {
	resetTestState()
	defer resetTestState()

	// Create non-expired pending IP
	createPendingIP("1.2.3.4", time.Hour)

	// Create non-expired allowed IP
	createAllowedIPManual("5.6.7.8", time.Hour)

	// Add rate limiter entry with valid timestamp
	rateLimiter["9.10.11.12"] = []time.Time{
		time.Now(), // valid
	}

	CleanupExpired()

	// Check pending IP is still pending
	if _, ok := ips["1.2.3.4"].state.(*PendingState); !ok {
		t.Error("Expected pending IP to remain")
	}

	// Check allowed IP is still allowed
	if _, ok := ips["5.6.7.8"].state.(*AllowedState); !ok {
		t.Error("Expected allowed IP to remain")
	}

	// Check rate limiter preserved
	if _, exists := rateLimiter["9.10.11.12"]; !exists {
		t.Error("Expected rate limiter entry to be preserved")
	}
}
