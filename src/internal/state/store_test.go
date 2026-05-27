package state

import (
	"testing"
	"time"

	"ttl-allow-service/src/internal/config"
	"ttl-allow-service/src/internal/ratelimit"
)

func setTestConfig(keys []config.KeyEntry, maxIPs int) {
	cfg := config.LoadDefaults()
	cfg.Keys.Entries = keys
	if maxIPs >= 0 {
		cfg.Keys.MaxIPs = maxIPs
	}
	cfg.AfterLoad()
	config.Set(cfg)
}

func resetTestState() {
	ips = make(map[string]*IP)
	keyIPs = make(map[string]map[string]bool)
	knockLimiter = ratelimit.New(time.Minute, 20)
	authLimiter = ratelimit.New(time.Minute, 1000)
	config.Set(config.LoadDefaults())
}

func createPendingIP(ipStr string, expiresIn time.Duration) *IP {
	ip := &IP{ip: ipStr}
	timer := time.AfterFunc(expiresIn, func() {})
	ip.Request(time.Now().Add(expiresIn), timer)
	ips[ipStr] = ip
	return ip
}

func createAllowedIPManual(ipStr string, expiresIn time.Duration) *IP {
	ip := createPendingIP(ipStr, expiresIn)
	approval := &ManualApproval{
		ExpiresAt:  time.Now().Add(expiresIn),
		ApprovedAt: time.Now(),
	}
	timer := time.AfterFunc(expiresIn, func() {})
	approval.SetTimer(timer)
	ip.Approve(approval)
	return ip
}

func createAllowedIPAutomatic(ipStr string, keyName string, expiresIn time.Duration) *IP {
	ip := &IP{ip: ipStr}
	ips[ipStr] = ip

	approval := &AutomaticApproval{
		ExpiresAt:  time.Now().Add(expiresIn),
		ApprovedAt: time.Now(),
		KeyName:    keyName,
	}
	timer := time.AfterFunc(expiresIn, func() {})
	approval.SetTimer(timer)

	if keyIPs[keyName] == nil {
		keyIPs[keyName] = make(map[string]bool)
	}
	keyIPs[keyName][ipStr] = true

	ip.Approve(approval)
	return ip
}

func createDoneIP(ipStr string, reason DoneReason) *IP {
	ip := &IP{ip: ipStr}
	ips[ipStr] = ip
	ip.state = &DoneState{DoneAt: time.Now(), Reason: reason}
	return ip
}

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

func TestAddKnockRequest_Duplicate(t *testing.T) {
	resetTestState()
	defer resetTestState()

	AddKnockRequest("1.2.3.4")
	result := AddKnockRequest("1.2.3.4")
	if result {
		t.Error("Expected duplicate knock request to fail")
	}
}

func TestAddKnockRequest_AfterRevoke(t *testing.T) {
	resetTestState()
	defer resetTestState()

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

func TestApproveIP_InvalidTTL(t *testing.T) {
	resetTestState()
	defer resetTestState()

	AddKnockRequest("1.2.3.4")
	err := ApproveIP("1.2.3.4", "99h")
	if err == nil {
		t.Error("Expected error for invalid TTL")
	}
}

func TestApproveIP_NoPending(t *testing.T) {
	resetTestState()
	defer resetTestState()

	err := ApproveIP("1.2.3.4", "1h")
	if err == nil {
		t.Error("Expected error for no pending request")
	}
}

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

func TestDenyIP_NotPending(t *testing.T) {
	resetTestState()
	defer resetTestState()

	err := DenyIP("1.2.3.4")
	if err == nil {
		t.Error("Expected error for IP not in pending")
	}
}

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

func TestRevokeIP_NotAllowed(t *testing.T) {
	resetTestState()
	defer resetTestState()

	err := RevokeIP("1.2.3.4")
	if err == nil {
		t.Error("Expected error for IP not allowed")
	}
}

func TestCheckIPAllowed_AllowedIP(t *testing.T) {
	resetTestState()
	defer resetTestState()

	createAllowedIPManual("1.2.3.4", time.Hour)

	result := CheckIPAllowed("1.2.3.4")
	if !result {
		t.Error("Expected IP to be allowed")
	}

	ip := ips["1.2.3.4"]
	if ip.lastSeen.IsZero() {
		t.Error("Expected LastSeen to be updated")
	}
}

func TestCheckIPAllowed_Expired(t *testing.T) {
	resetTestState()
	defer resetTestState()

	ip := createAllowedIPManual("1.2.3.4", time.Hour)
	if as, ok := ip.state.(*AllowedState); ok {
		manual := as.approval.(*ManualApproval)
		manual.ExpiresAt = time.Now().Add(-time.Hour)
	}

	result := CheckIPAllowed("1.2.3.4")
	if result {
		t.Error("Expected IP to not be allowed (expired)")
	}
}

func TestCheckIPAllowed_NotInList(t *testing.T) {
	resetTestState()
	defer resetTestState()

	result := CheckIPAllowed("1.2.3.4")
	if result {
		t.Error("Expected false for unknown IP")
	}
}

func TestApproveIPByKey_Success(t *testing.T) {
	resetTestState()
	defer resetTestState()

	setTestConfig([]config.KeyEntry{{Key: "abc123", Name: "test-key"}}, -1)

	err := ApproveIPByKey("1.2.3.4", "test-key")
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

func TestApproveIPByKey_AnyName(t *testing.T) {
	resetTestState()
	defer resetTestState()

	err := ApproveIPByKey("1.2.3.4", "any-name")
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if !CheckIPAllowed("1.2.3.4") {
		t.Error("Expected IP to be allowed")
	}
}

func TestApproveIPByKey_IPRotation(t *testing.T) {
	resetTestState()
	defer resetTestState()

	setTestConfig([]config.KeyEntry{{Key: "abc123", Name: "test-key"}}, 1)

	ApproveIPByKey("1.2.3.4", "test-key")

	ApproveIPByKey("5.6.7.8", "test-key")

	if CheckIPAllowed("1.2.3.4") {
		t.Error("Expected first IP to be revoked")
	}
	if !CheckIPAllowed("5.6.7.8") {
		t.Error("Expected second IP to be allowed")
	}
}

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
					return nil
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

func TestCheckRateLimit(t *testing.T) {
	resetTestState()
	defer resetTestState()

	cfg := config.LoadDefaults()
	cfg.Rate.KnockMaxRequests = 5
	config.Set(cfg)

	knockLimiter = ratelimit.New(
		time.Duration(cfg.Rate.KnockWindowSec)*time.Second,
		cfg.Rate.KnockMaxRequests,
	)

	for i := 1; i <= 5; i++ {
		if !CheckRateLimit("1.2.3.4") {
			t.Errorf("Expected request %d to pass rate limit", i)
		}
	}

	if CheckRateLimit("1.2.3.4") {
		t.Error("Expected sixth request to fail rate limit")
	}
}

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

func TestCanRequest(t *testing.T) {
	resetTestState()
	defer resetTestState()

	ip := &IP{ip: "1.2.3.4"}
	ips["1.2.3.4"] = ip
	if !ip.CanRequest() {
		t.Error("Expected new IP to be able to request")
	}

	resetTestState()
	ip = createPendingIP("1.2.3.4", time.Hour)
	if ip.CanRequest() {
		t.Error("Expected pending IP to not be able to request")
	}

	resetTestState()
	ip = createAllowedIPManual("1.2.3.4", time.Hour)
	if ip.CanRequest() {
		t.Error("Expected allowed IP to not be able to request")
	}

	resetTestState()
	ip = createDoneIP("1.2.3.4", DoneDenied)
	if ip.CanRequest() {
		t.Error("Expected denied IP to not be able to request")
	}

	resetTestState()
	ip = createDoneIP("1.2.3.4", DoneManualRevoke)
	if !ip.CanRequest() {
		t.Error("Expected revoked IP to be able to request")
	}
}

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

func TestCleanupExpired(t *testing.T) {
	resetTestState()
	defer resetTestState()

	ip1 := createPendingIP("1.2.3.4", time.Hour)
	if ps, ok := ip1.state.(*PendingState); ok {
		ps.ExpiresAt = time.Now().Add(-time.Hour)
	}

	ip2 := createAllowedIPManual("5.6.7.8", time.Hour)
	if as, ok := ip2.state.(*AllowedState); ok {
		if manual, ok := as.approval.(*ManualApproval); ok {
			manual.ExpiresAt = time.Now().Add(-time.Hour)
		}
	}

	CleanupExpired()

	if ds, ok := ip1.state.(*DoneState); !ok || ds.Reason != DoneAutoRevoke {
		t.Error("Expected pending IP to be timed out")
	}

	if ds, ok := ip2.state.(*DoneState); !ok || ds.Reason != DoneAutoRevoke {
		t.Error("Expected allowed IP to be timed out")
	}
}

func TestCheckAuthRateLimit(t *testing.T) {
	resetTestState()
	defer resetTestState()

	cfg := config.LoadDefaults()
	cfg.Rate.AuthMaxRequests = 3
	config.Set(cfg)

	authLimiter = ratelimit.New(
		time.Duration(cfg.Rate.AuthWindowSec)*time.Second,
		cfg.Rate.AuthMaxRequests,
	)

	for i := 1; i <= 3; i++ {
		if !CheckAuthRateLimit("1.2.3.4") {
			t.Errorf("Expected request %d to pass auth rate limit", i)
		}
	}

	if CheckAuthRateLimit("1.2.3.4") {
		t.Error("Expected fourth request to fail auth rate limit")
	}

	if !CheckAuthRateLimit("9.9.9.9") {
		t.Error("Expected different IP to pass")
	}
}

func TestGetIPAuthStatus_NotExists(t *testing.T) {
	resetTestState()
	defer resetTestState()

	status := GetIPAuthStatus("1.2.3.4")
	if status.Authorized {
		t.Error("Expected not authorized for unknown IP")
	}
}

func TestGetIPAuthStatus_AuthorizedManual(t *testing.T) {
	resetTestState()
	defer resetTestState()

	createAllowedIPManual("1.2.3.4", time.Hour)

	status := GetIPAuthStatus("1.2.3.4")
	if !status.Authorized {
		t.Error("Expected authorized")
	}
	if status.ApprovalType != "Manual" {
		t.Errorf("Expected Manual, got %s", status.ApprovalType)
	}
	if !status.ExpiresAt.After(time.Now()) {
		t.Error("Expected ExpiresAt in the future")
	}
}

func TestGetIPAuthStatus_AuthorizedAutomatic(t *testing.T) {
	resetTestState()
	defer resetTestState()

	createAllowedIPAutomatic("1.2.3.4", "test-key", time.Hour)

	status := GetIPAuthStatus("1.2.3.4")
	if !status.Authorized {
		t.Error("Expected authorized")
	}
	if status.KeyName != "test-key" {
		t.Errorf("Expected key name 'test-key', got %s", status.KeyName)
	}
	if status.ApprovalType != "Automatic (test-key)" {
		t.Errorf("Expected 'Automatic (test-key)', got %s", status.ApprovalType)
	}
}

func TestGetIPAuthStatus_Expired(t *testing.T) {
	resetTestState()
	defer resetTestState()

	ip := createAllowedIPManual("1.2.3.4", -time.Hour)

	status := GetIPAuthStatus("1.2.3.4")
	if status.Authorized {
		t.Error("Expected not authorized for expired IP")
	}
	_ = ip
}

func TestRevokeIPByKey_Success(t *testing.T) {
	resetTestState()
	defer resetTestState()

	setTestConfig([]config.KeyEntry{{Key: "k", Name: "n"}}, -1)
	ApproveIPByKey("1.2.3.4", "test-key")

	if !CheckIPAllowed("1.2.3.4") {
		t.Fatal("Expected IP to be allowed before revoke")
	}

	err := RevokeIPByKey("1.2.3.4", "test-key")
	if err != nil {
		t.Errorf("Expected revoke to succeed, got: %v", err)
	}

	if CheckIPAllowed("1.2.3.4") {
		t.Error("Expected IP to not be allowed after revoke")
	}
}

func TestRevokeIPByKey_NotExists(t *testing.T) {
	resetTestState()
	defer resetTestState()

	err := RevokeIPByKey("1.2.3.4", "test-key")
	if err == nil {
		t.Error("Expected error for IP not in map")
	}
}

func TestRevokeIPByKey_NotAllowed(t *testing.T) {
	resetTestState()
	defer resetTestState()

	AddKnockRequest("1.2.3.4")

	err := RevokeIPByKey("1.2.3.4", "test-key")
	if err == nil {
		t.Error("Expected error for IP in Pending state")
	}
}

func TestLookupKey_Wrapper(t *testing.T) {
	resetTestState()
	defer resetTestState()

	setTestConfig([]config.KeyEntry{{Key: "mykey", Name: "myname"}}, -1)

	result, ok := LookupKey("mykey")
	if !ok {
		t.Error("expected ok=true")
	}
	if result != "myname" {
		t.Errorf("expected 'myname', got %q", result)
	}

	result, ok = LookupKey("nonexistent")
	if ok {
		t.Error("expected ok=false")
	}
	if result != "" {
		t.Errorf("expected empty for unknown key, got %q", result)
	}
}

func TestHasPermanentKeys_Wrapper(t *testing.T) {
	resetTestState()
	defer resetTestState()

	if HasPermanentKeys() {
		t.Error("expected false with no keys")
	}

	setTestConfig([]config.KeyEntry{{Key: "k", Name: "n"}}, -1)

	if !HasPermanentKeys() {
		t.Error("expected true with keys")
	}
}

func TestCleanupExpired_PreservesValid(t *testing.T) {
	resetTestState()
	defer resetTestState()

	createPendingIP("1.2.3.4", time.Hour)

	createAllowedIPManual("5.6.7.8", time.Hour)

	CleanupExpired()

	if _, ok := ips["1.2.3.4"].state.(*PendingState); !ok {
		t.Error("Expected pending IP to remain")
	}

	if _, ok := ips["5.6.7.8"].state.(*AllowedState); !ok {
		t.Error("Expected allowed IP to remain")
	}
}
