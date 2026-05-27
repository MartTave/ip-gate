package config

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg := LoadDefaults()
	if cfg.Server.Port != 8080 {
		t.Errorf("expected 8080, got %d", cfg.Server.Port)
	}
	if cfg.Rate.KnockMaxRequests != 20 {
		t.Errorf("expected 20, got %d", cfg.Rate.KnockMaxRequests)
	}
	if cfg.Rate.AuthMaxRequests != 1000 {
		t.Errorf("expected 1000, got %d", cfg.Rate.AuthMaxRequests)
	}
	if cfg.TTL.RequestTTLMinutes != 5 {
		t.Errorf("expected 5, got %d", cfg.TTL.RequestTTLMinutes)
	}
	if cfg.TTL.MaxTTL != 48*time.Hour {
		t.Errorf("expected 48h, got %v", cfg.TTL.MaxTTL)
	}
	if cfg.Keys.AuthTTL != 4*time.Hour {
		t.Errorf("expected 4h, got %v", cfg.Keys.AuthTTL)
	}
	if cfg.Keys.MaxIPs != 1 {
		t.Errorf("expected 1, got %d", cfg.Keys.MaxIPs)
	}
	if cfg.Worker.IntervalMinutes != 5 {
		t.Errorf("expected 5, got %d", cfg.Worker.IntervalMinutes)
	}
}

func TestApplyDefaults(t *testing.T) {
	cfg := &Config{}
	ApplyDefaults(cfg)

	if cfg.Server.Port != 8080 {
		t.Errorf("expected 8080, got %d", cfg.Server.Port)
	}
	if cfg.Rate.KnockWindowSec != 60 {
		t.Errorf("expected 60, got %d", cfg.Rate.KnockWindowSec)
	}
	if cfg.Logging.MaxSizeMB != 10 {
		t.Errorf("expected 10, got %d", cfg.Logging.MaxSizeMB)
	}
}

func TestApplyDefaults_NoOverwrite(t *testing.T) {
	cfg := &Config{}
	cfg.Server.Port = 9090
	ApplyDefaults(cfg)

	if cfg.Server.Port != 9090 {
		t.Errorf("expected 9090 (preserved), got %d", cfg.Server.Port)
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("REQUEST_TTL_MINUTES", "15")
	t.Setenv("MAX_TTL", "72h")
	t.Setenv("PERMANENT_KEYS", "key1:name1,key2:name2")
	t.Setenv("WORKER_INTERVAL_MINUTES", "10")

	cfg := LoadDefaults()
	ApplyEnvOverrides(cfg)

	if cfg.Server.Port != 9090 {
		t.Errorf("expected 9090, got %d", cfg.Server.Port)
	}
	if cfg.TTL.RequestTTLMinutes != 15 {
		t.Errorf("expected 15, got %d", cfg.TTL.RequestTTLMinutes)
	}
	if cfg.TTL.MaxTTL != 72*time.Hour {
		t.Errorf("expected 72h, got %v", cfg.TTL.MaxTTL)
	}
	if len(cfg.Keys.Entries) != 2 {
		t.Errorf("expected 2 key entries, got %d", len(cfg.Keys.Entries))
	}
	if cfg.Keys.Entries[0].Key != "key1" || cfg.Keys.Entries[0].Name != "name1" {
		t.Errorf("expected key1:name1, got %s:%s", cfg.Keys.Entries[0].Key, cfg.Keys.Entries[0].Name)
	}
	if cfg.Worker.IntervalMinutes != 10 {
		t.Errorf("expected 10, got %d", cfg.Worker.IntervalMinutes)
	}
}

func TestApplyEnvOverrides_RateLimiting(t *testing.T) {
	t.Setenv("RATE_LIMIT_WINDOW_SEC", "30")
	t.Setenv("RATE_LIMIT_MAX_REQUESTS", "50")
	t.Setenv("AUTH_RATE_LIMIT_WINDOW_SEC", "120")
	t.Setenv("AUTH_RATE_LIMIT_MAX_REQUESTS", "5000")

	cfg := LoadDefaults()
	ApplyEnvOverrides(cfg)

	if cfg.Rate.KnockWindowSec != 30 {
		t.Errorf("expected 30, got %d", cfg.Rate.KnockWindowSec)
	}
	if cfg.Rate.KnockMaxRequests != 50 {
		t.Errorf("expected 50, got %d", cfg.Rate.KnockMaxRequests)
	}
	if cfg.Rate.AuthWindowSec != 120 {
		t.Errorf("expected 120, got %d", cfg.Rate.AuthWindowSec)
	}
	if cfg.Rate.AuthMaxRequests != 5000 {
		t.Errorf("expected 5000, got %d", cfg.Rate.AuthMaxRequests)
	}
}

func TestValidate_Valid(t *testing.T) {
	cfg := LoadDefaults()
	if err := Validate(cfg); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestValidate_PortOutOfRange(t *testing.T) {
	cfg := LoadDefaults()
	cfg.Server.Port = 0
	if err := Validate(cfg); err == nil {
		t.Error("expected error for port 0")
	}
	cfg.Server.Port = 70000
	if err := Validate(cfg); err == nil {
		t.Error("expected error for port 70000")
	}
}

func TestValidate_RateWindowZero(t *testing.T) {
	cfg := LoadDefaults()
	cfg.Rate.KnockWindowSec = 0
	if err := Validate(cfg); err == nil {
		t.Error("expected error for knock_window_sec = 0")
	}
}

func TestValidate_RateMaxRequestsZero(t *testing.T) {
	cfg := LoadDefaults()
	cfg.Rate.KnockMaxRequests = 0
	if err := Validate(cfg); err == nil {
		t.Error("expected error for knock_max_requests = 0")
	}
}

func TestValidate_AuthRateWindowZero(t *testing.T) {
	cfg := LoadDefaults()
	cfg.Rate.AuthWindowSec = -1
	if err := Validate(cfg); err == nil {
		t.Error("expected error for auth_window_sec = -1")
	}
}

func TestValidate_TTLMaxZero(t *testing.T) {
	cfg := LoadDefaults()
	cfg.TTL.MaxTTL = 0
	if err := Validate(cfg); err == nil {
		t.Error("expected error for max_ttl = 0")
	}
}

func TestValidate_KeysDuplicate(t *testing.T) {
	cfg := LoadDefaults()
	cfg.Keys.Entries = []KeyEntry{
		{Key: "abc", Name: "one"},
		{Key: "abc", Name: "two"},
	}
	if err := Validate(cfg); err == nil {
		t.Error("expected error for duplicate key")
	}
}

func TestValidate_KeysDuplicateName(t *testing.T) {
	cfg := LoadDefaults()
	cfg.Keys.Entries = []KeyEntry{
		{Key: "abc", Name: "same"},
		{Key: "xyz", Name: "same"},
	}
	if err := Validate(cfg); err == nil {
		t.Error("expected error for duplicate name")
	}
}

func TestValidate_KeysEmptyKey(t *testing.T) {
	cfg := LoadDefaults()
	cfg.Keys.Entries = []KeyEntry{
		{Key: "", Name: "test"},
	}
	if err := Validate(cfg); err == nil {
		t.Error("expected error for empty key")
	}
}

func TestValidate_KeysEmptyName(t *testing.T) {
	cfg := LoadDefaults()
	cfg.Keys.Entries = []KeyEntry{
		{Key: "abc", Name: ""},
	}
	if err := Validate(cfg); err == nil {
		t.Error("expected error for empty name")
	}
}

func TestValidate_WorkerIntervalZero(t *testing.T) {
	cfg := LoadDefaults()
	cfg.Worker.IntervalMinutes = 0
	if err := Validate(cfg); err == nil {
		t.Error("expected error for interval = 0")
	}
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := []byte(`
server:
  port: 9090
rate_limiting:
  knock_max_requests: 50
ttl:
  request_ttl_minutes: 10
permanent_keys:
  entries:
    - key: "test-key"
      name: "test-name"
`)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("expected 9090, got %d", cfg.Server.Port)
	}
	if cfg.Rate.KnockMaxRequests != 50 {
		t.Errorf("expected 50, got %d", cfg.Rate.KnockMaxRequests)
	}
	if cfg.TTL.RequestTTLMinutes != 10 {
		t.Errorf("expected 10, got %d", cfg.TTL.RequestTTLMinutes)
	}
	if len(cfg.Keys.Entries) != 1 {
		t.Errorf("expected 1 key entry, got %d", len(cfg.Keys.Entries))
	}
}

func TestLoad_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent.yaml")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Server.Port)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte(": : invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestHasPermanentKeys(t *testing.T) {
	cfg := LoadDefaults()
	cfg.AfterLoad()
	Set(cfg)
	if cfg.HasPermanentKeys() {
		t.Error("expected false with no keys")
	}

	cfg.Keys.Entries = []KeyEntry{{Key: "k", Name: "n"}}
	cfg.AfterLoad()
	Set(cfg)
	if !cfg.HasPermanentKeys() {
		t.Error("expected true with keys")
	}
}

func TestLookupKey(t *testing.T) {
	cfg := LoadDefaults()
	cfg.Keys.Entries = []KeyEntry{{Key: "mykey", Name: "mykeyname"}}
	cfg.AfterLoad()
	Set(cfg)

	name, ok := cfg.LookupKey("mykey")
	if !ok {
		t.Error("expected key to be found")
	}
	if name != "mykeyname" {
		t.Errorf("expected 'mykeyname', got '%s'", name)
	}

	if _, ok := cfg.LookupKey("nonexistent"); ok {
		t.Error("expected nonexistent key to not be found")
	}
}

func TestServerPort(t *testing.T) {
	cfg := LoadDefaults()
	cfg.Server.Port = 8080
	if s := cfg.ServerPort(); s != "8080" {
		t.Errorf("expected '8080', got '%s'", s)
	}
}

func TestGetSet(t *testing.T) {
	cfg1 := LoadDefaults()
	cfg1.Server.Port = 1111
	Set(cfg1)

	got := Get()
	if got.Server.Port != 1111 {
		t.Errorf("expected 1111, got %d", got.Server.Port)
	}

	cfg2 := LoadDefaults()
	cfg2.Server.Port = 2222
	Set(cfg2)

	got = Get()
	if got.Server.Port != 2222 {
		t.Errorf("expected 2222, got %d", got.Server.Port)
	}
}

func TestGet_Nil(t *testing.T) {
	current = atomic.Value{}
	cfg := Get()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Server.Port)
	}
}

func TestAfterLoad(t *testing.T) {
	cfg := LoadDefaults()
	cfg.Keys.Entries = []KeyEntry{
		{Key: "k1", Name: "n1"},
		{Key: "k2", Name: "n2"},
	}
	cfg.AfterLoad()

	name, ok := cfg.LookupKey("k1")
	if !ok || name != "n1" {
		t.Errorf("expected n1, got %s", name)
	}
	name, ok = cfg.LookupKey("k2")
	if !ok || name != "n2" {
		t.Errorf("expected n2, got %s", name)
	}
	if _, ok := cfg.LookupKey("k3"); ok {
		t.Error("expected k3 to not be found")
	}
}

func TestValidate_MaxIPsNegative(t *testing.T) {
	cfg := LoadDefaults()
	cfg.Keys.MaxIPs = -1
	if err := Validate(cfg); err == nil {
		t.Error("expected error for MaxIPs = -1")
	}
}

func TestValidate_MaxIPsZero(t *testing.T) {
	cfg := LoadDefaults()
	cfg.Keys.MaxIPs = 0
	if err := Validate(cfg); err != nil {
		t.Errorf("expected no error for MaxIPs = 0, got: %v", err)
	}
}
