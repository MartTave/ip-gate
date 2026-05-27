package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ttl-allow-service/src/internal/config"
	"ttl-allow-service/src/internal/state"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		expected   string
	}{
		{"with port", "1.2.3.4:56789", "1.2.3.4"},
		{"without port", "1.2.3.4", "1.2.3.4"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			got := getClientIP(req)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestExtractClientIPFromHeaders(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		xrip       string
		remoteAddr string
		expected   string
	}{
		{"xff", "10.0.0.1", "", "", "10.0.0.1"},
		{"x-real-ip", "", "10.0.0.2", "", "10.0.0.2"},
		{"xff over xri", "10.0.0.3", "10.0.0.4", "", "10.0.0.3"},
		{"xff with multiple", "10.0.0.1, 10.0.0.2", "", "", "10.0.0.1"},
		{"xff over remote", "10.0.0.1", "", "10.0.0.5:8080", "10.0.0.1"},
		{"fallback to remote", "", "", "10.0.0.5:8080", "10.0.0.5"},
		{"no source", "", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xrip != "" {
				req.Header.Set("X-Real-IP", tt.xrip)
			}
			got := ExtractClientIPFromHeaders(req)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestWriteKeysDisabled(t *testing.T) {
	w := httptest.NewRecorder()
	writeKeysDisabled(w)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if resp["error"] != "not_configured" {
		t.Errorf("expected 'not_configured', got %v", resp["error"])
	}
}

func TestRequireKeysActivated(t *testing.T) {
	t.Run("no keys", func(t *testing.T) {
		state.ResetTestState()
		cfg := config.LoadDefaults()
		cfg.AfterLoad()
		state.Init(cfg)

		w := httptest.NewRecorder()
		result := requireKeysActivated(w)
		if result {
			t.Error("expected false without keys")
		}
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
		var resp map[string]interface{}
		json.NewDecoder(w.Body).Decode(&resp)
		if resp["error"] != "not_configured" {
			t.Errorf("expected 'not_configured', got %v", resp["error"])
		}
	})

	t.Run("with keys", func(t *testing.T) {
		state.ResetTestState()
		cfg := config.LoadDefaults()
		cfg.Keys.Entries = []config.KeyEntry{{Key: "k", Name: "n"}}
		cfg.Keys.MaxIPs = 5
		cfg.AfterLoad()
		state.Init(cfg)

		w := httptest.NewRecorder()
		result := requireKeysActivated(w)
		if !result {
			t.Error("expected true with keys")
		}
		if w.Body.Len() != 0 {
			t.Error("expected empty body when keys active")
		}
	})
}

func TestRequirePOST(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		want       bool
		wantStatus int
	}{
		{"POST", http.MethodPost, true, 0},
		{"GET", http.MethodGet, false, http.StatusMethodNotAllowed},
		{"PUT", http.MethodPut, false, http.StatusMethodNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/", nil)
			w := httptest.NewRecorder()
			got := requirePOST(req, w)
			if got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
			if !tt.want && w.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, w.Code)
			}
		})
	}
}

func TestRequireClientIP(t *testing.T) {
	t.Run("xff", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		w := httptest.NewRecorder()
		ip, ok := requireClientIP(req, w)
		if !ok {
			t.Error("expected ok=true")
		}
		if ip != "10.0.0.1" {
			t.Errorf("expected '10.0.0.1', got %q", ip)
		}
	})

	t.Run("x-real-ip", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Real-IP", "10.0.0.2")
		w := httptest.NewRecorder()
		ip, ok := requireClientIP(req, w)
		if !ok {
			t.Error("expected ok=true")
		}
		if ip != "10.0.0.2" {
			t.Errorf("expected '10.0.0.2', got %q", ip)
		}
	})

	t.Run("remote addr fallback", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.3:8080"
		w := httptest.NewRecorder()
		ip, ok := requireClientIP(req, w)
		if !ok {
			t.Error("expected ok=true")
		}
		if ip != "10.0.0.3" {
			t.Errorf("expected '10.0.0.3', got %q", ip)
		}
	})

	t.Run("no ip", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = ""
		w := httptest.NewRecorder()
		ip, ok := requireClientIP(req, w)
		if ok {
			t.Error("expected ok=false")
		}
		if ip != "" {
			t.Errorf("expected empty ip, got %q", ip)
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403, got %d", w.Code)
		}
	})
}

func TestRequireRateLimit(t *testing.T) {
	state.ResetTestState()
	cfg := config.LoadDefaults()
	cfg.Rate.KnockMaxRequests = 2
	cfg.Rate.KnockWindowSec = 60
	cfg.AfterLoad()
	state.Init(cfg)
	defer state.ResetTestState()

	t.Run("under limit", func(t *testing.T) {
		w := httptest.NewRecorder()
		result := requireRateLimit("1.2.3.4", "/knock", w)
		if !result {
			t.Error("expected true under limit")
		}
		if w.Body.Len() != 0 {
			t.Error("expected empty body when not rate limited")
		}
	})

	t.Run("over limit", func(t *testing.T) {
		w1 := httptest.NewRecorder()
		requireRateLimit("1.2.3.4", "/knock", w1)

		w2 := httptest.NewRecorder()
		result := requireRateLimit("1.2.3.4", "/knock", w2)
		if result {
			t.Error("expected false over limit")
		}
		if w2.Code != http.StatusTooManyRequests {
			t.Errorf("expected 429, got %d", w2.Code)
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w2.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode JSON: %v", err)
		}
		if resp["error"] != "rate_limited" {
			t.Errorf("expected 'rate_limited', got %v", resp["error"])
		}
		if resp["client_ip"] != "1.2.3.4" {
			t.Errorf("expected client_ip '1.2.3.4', got %v", resp["client_ip"])
		}
	})
}

func TestRequireFormKey(t *testing.T) {
	t.Run("with key", func(t *testing.T) {
		body := strings.NewReader("key=valid-key")
		req := httptest.NewRequest("POST", "/", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		got, ok := requireFormKey(req, w, "1.2.3.4")
		if !ok {
			t.Error("expected ok=true")
		}
		if got != "valid-key" {
			t.Errorf("expected 'valid-key', got %q", got)
		}
	})

	t.Run("without key", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/", nil)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		got, ok := requireFormKey(req, w, "1.2.3.4")
		if ok {
			t.Error("expected ok=false")
		}
		if got != "" {
			t.Errorf("expected empty, got %q", got)
		}
		if w.Code != http.StatusBadRequest {
			t.Errorf("expected 400, got %d", w.Code)
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode JSON: %v", err)
		}
		if resp["error"] != "missing_key" {
			t.Errorf("expected 'missing_key', got %v", resp["error"])
		}
		if resp["client_ip"] != "1.2.3.4" {
			t.Errorf("expected client_ip '1.2.3.4', got %v", resp["client_ip"])
		}
		if resp["authorized"] != false {
			t.Errorf("expected authorized false, got %v", resp["authorized"])
		}
	})
}

func TestLookupValidKey(t *testing.T) {
	state.ResetTestState()
	cfg := config.LoadDefaults()
	cfg.Keys.Entries = []config.KeyEntry{{Key: "valid-key", Name: "test-name"}}
	cfg.Keys.MaxIPs = 5
	cfg.AfterLoad()
	state.Init(cfg)
	defer state.ResetTestState()

	t.Run("found", func(t *testing.T) {
		w := httptest.NewRecorder()
		name, ok := lookupValidKey("valid-key", w, nil)
		if !ok {
			t.Error("expected ok=true")
		}
		if name != "test-name" {
			t.Errorf("expected 'test-name', got %q", name)
		}
		if w.Body.Len() != 0 {
			t.Error("expected empty body on success")
		}
	})

	t.Run("not found", func(t *testing.T) {
		w := httptest.NewRecorder()
		extra := map[string]interface{}{"client_ip": "1.2.3.4"}
		_, ok := lookupValidKey("bad-key", w, extra)
		if ok {
			t.Error("expected ok=false")
		}
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401, got %d", w.Code)
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode JSON: %v", err)
		}
		if resp["error"] != "invalid_key" {
			t.Errorf("expected 'invalid_key', got %v", resp["error"])
		}
		if resp["client_ip"] != "1.2.3.4" {
			t.Errorf("expected client_ip in response, got %v", resp["client_ip"])
		}
	})
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]interface{}{"status": "ok", "value": 42}
	writeJSON(w, http.StatusCreated, data)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected 'ok', got %v", resp["status"])
	}
	if n, ok := resp["value"].(float64); !ok || n != 42 {
		t.Errorf("expected value 42, got %v", resp["value"])
	}
}
