package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ttl-allow-service/src/internal/config"
	"ttl-allow-service/src/internal/state"
)

func TestPWAHandler_NoKeys(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest("GET", "/pwa", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	w := httptest.NewRecorder()
	PWAHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html" {
		t.Errorf("expected text/html, got %s", ct)
	}
	if !strings.Contains(w.Body.String(), "no keys configured") &&
		!strings.Contains(w.Body.String(), "No Keys") &&
		!strings.Contains(w.Body.String(), "not configured") {
		t.Errorf("expected no-keys message, got: %s", w.Body.String()[:200])
	}
}

func setupPWAKeys(t *testing.T) {
	t.Helper()
	state.ResetTestState()
	cfg := config.LoadDefaults()
	cfg.Keys.Entries = []config.KeyEntry{{Key: "valid-key-123", Name: "test-key"}}
	cfg.Keys.MaxIPs = 5
	cfg.Keys.AuthTTL = config.Duration(time.Hour)
	cfg.AfterLoad()
	state.Init(cfg)
}

func TestPWAHandler_WithKeys(t *testing.T) {
	setupPWAKeys(t)
	req := httptest.NewRequest("GET", "/pwa", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	w := httptest.NewRecorder()
	PWAHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html" {
		t.Errorf("expected text/html, got %s", ct)
	}
}

func TestPWAStatusHandler_NoKey(t *testing.T) {
	setupPWAKeys(t)
	req := httptest.NewRequest("POST", "/pwa/status", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	w := httptest.NewRecorder()
	PWAStatusHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if resp["client_ip"] != "1.2.3.4" {
		t.Errorf("expected client_ip 1.2.3.4, got %v", resp["client_ip"])
	}
}

func TestPWAStatusHandler_ValidKey(t *testing.T) {
	setupPWAKeys(t)
	body := strings.NewReader("key=valid-key-123")
	req := httptest.NewRequest("POST", "/pwa/status", body)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	PWAStatusHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if resp["key_valid"] != true {
		t.Errorf("expected key_valid true, got %v", resp["key_valid"])
	}
	if resp["key_name"] != "test-key" {
		t.Errorf("expected key_name test-key, got %v", resp["key_name"])
	}
}

func TestPWAStatusHandler_InvalidKey(t *testing.T) {
	setupPWAKeys(t)
	body := strings.NewReader("key=bad-key")
	req := httptest.NewRequest("POST", "/pwa/status", body)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	PWAStatusHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if resp["error"] != "invalid_key" {
		t.Errorf("expected error invalid_key, got %v", resp["error"])
	}
}

func TestPWAAuthHandler_ValidKey(t *testing.T) {
	setupPWAKeys(t)
	body := strings.NewReader("key=valid-key-123")
	req := httptest.NewRequest("POST", "/pwa/auth", body)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	PWAAuthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if resp["authorized"] != true {
		t.Errorf("expected authorized true, got %v", resp["authorized"])
	}
	if !state.CheckIPAllowed("1.2.3.4") {
		t.Error("expected IP to be allowed after key auth")
	}
}

func TestPWAAuthHandler_InvalidKey(t *testing.T) {
	setupPWAKeys(t)
	body := strings.NewReader("key=bad-key")
	req := httptest.NewRequest("POST", "/pwa/auth", body)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	PWAAuthHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestPWARevokeHandler_ValidKey(t *testing.T) {
	setupPWAKeys(t)
	state.AddKnockRequest("1.2.3.4")
	state.ApproveIPByKey("1.2.3.4", "test-key")

	if !state.CheckIPAllowed("1.2.3.4") {
		t.Fatal("expected IP to be allowed before revoke")
	}

	body := strings.NewReader("key=valid-key-123")
	req := httptest.NewRequest("POST", "/pwa/revoke", body)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	PWARevokeHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if resp["status"] != "revoked" {
		t.Errorf("expected status 'revoked', got %v", resp["status"])
	}
	if state.CheckIPAllowed("1.2.3.4") {
		t.Error("expected IP to not be allowed after revoke")
	}
}

func TestManifestHandler(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest("GET", "/pwa/manifest.json", nil)
	w := httptest.NewRecorder()
	ManifestHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}
}

func TestServiceWorkerHandler(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest("GET", "/pwa/service-worker.js", nil)
	w := httptest.NewRecorder()
	ServiceWorkerHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/javascript" {
		t.Errorf("expected application/javascript, got %s", ct)
	}
}

func TestPwaIconHandler(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest("GET", "/pwa/pwa-icon.svg", nil)
	w := httptest.NewRecorder()
	PwaIconHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/svg+xml" {
		t.Errorf("expected image/svg+xml, got %s", ct)
	}
}
