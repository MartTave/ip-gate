package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ttl-allow-service/src/internal/state"
)

func TestAllowHandler_GetJSON(t *testing.T) {
	setupTest(t)
	state.AddKnockRequest("1.2.3.4")
	state.AddKnockRequest("5.6.7.8")
	state.ApproveIP("5.6.7.8", "1h")

	req := httptest.NewRequest("GET", "/allow", nil)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	AllowHandler(w, req)

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
	pending := resp["pending"].([]interface{})
	approved := resp["approved"].([]interface{})
	if len(pending) != 1 {
		t.Errorf("expected 1 pending, got %d", len(pending))
	}
	if len(approved) != 1 {
		t.Errorf("expected 1 approved, got %d", len(approved))
	}
}

func TestAllowHandler_GetHTML(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest("GET", "/allow", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	AllowHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/html" {
		t.Errorf("expected text/html, got %s", ct)
	}
	if !strings.Contains(w.Body.String(), "Pending") {
		t.Errorf("expected HTML to contain 'Pending', got: %s", w.Body.String()[:200])
	}
}

func TestAllowHandler_PostAllow(t *testing.T) {
	setupTest(t)
	state.AddKnockRequest("1.2.3.4")

	body := strings.NewReader("ip=1.2.3.4&action=allow&ttl=1h")
	req := httptest.NewRequest("POST", "/allow", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	AllowHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "allowed") {
		t.Errorf("expected 'allowed', got '%s'", w.Body.String())
	}
	if !state.CheckIPAllowed("1.2.3.4") {
		t.Error("expected IP to be allowed")
	}
}

func TestAllowHandler_PostDeny(t *testing.T) {
	setupTest(t)
	state.AddKnockRequest("1.2.3.4")

	body := strings.NewReader("ip=1.2.3.4&action=deny")
	req := httptest.NewRequest("POST", "/allow", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	AllowHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "denied") {
		t.Errorf("expected 'denied', got '%s'", w.Body.String())
	}
	if state.CheckIPAllowed("1.2.3.4") {
		t.Error("expected IP to not be allowed")
	}
}

func TestAllowHandler_PostRevoke(t *testing.T) {
	setupTest(t)
	state.AddKnockRequest("1.2.3.4")
	state.ApproveIP("1.2.3.4", "1h")

	body := strings.NewReader("ip=1.2.3.4&action=revoke")
	req := httptest.NewRequest("POST", "/allow", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	AllowHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "revoked") {
		t.Errorf("expected 'revoked', got '%s'", w.Body.String())
	}
	if state.CheckIPAllowed("1.2.3.4") {
		t.Error("expected IP to not be allowed after revoke")
	}
}

func TestAllowHandler_PostAllowJSON(t *testing.T) {
	setupTest(t)
	state.AddKnockRequest("1.2.3.4")

	body := strings.NewReader(`{"ip":"1.2.3.4","action":"allow","ttl":"1h"}`)
	req := httptest.NewRequest("POST", "/allow", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	AllowHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !state.CheckIPAllowed("1.2.3.4") {
		t.Error("expected IP to be allowed")
	}
}

func TestAllowHandler_PostMissingFields(t *testing.T) {
	setupTest(t)
	body := strings.NewReader("ip=&action=")
	req := httptest.NewRequest("POST", "/allow", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	AllowHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAllowHandler_PostInvalidAction(t *testing.T) {
	setupTest(t)
	body := strings.NewReader("ip=1.2.3.4&action=invalid")
	req := httptest.NewRequest("POST", "/allow", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	AllowHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAllowHandler_WrongMethod(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest("PUT", "/allow", nil)
	w := httptest.NewRecorder()
	AllowHandler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestAllowHandler_PostAllow_JSON_InvalidBody(t *testing.T) {
	setupTest(t)
	body := strings.NewReader(`not json`)
	req := httptest.NewRequest("POST", "/allow", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	AllowHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestAllowHandler_PostAllow_JSON_Deny(t *testing.T) {
	setupTest(t)
	state.AddKnockRequest("1.2.3.4")

	body := strings.NewReader(`{"ip":"1.2.3.4","action":"deny"}`)
	req := httptest.NewRequest("POST", "/allow", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	AllowHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "denied") {
		t.Errorf("expected 'denied', got '%s'", w.Body.String())
	}
}

func TestAllowHandler_PostAllow_JSON_MissingTTL(t *testing.T) {
	setupTest(t)
	state.AddKnockRequest("1.2.3.4")

	body := strings.NewReader(`{"ip":"1.2.3.4","action":"allow"}`)
	req := httptest.NewRequest("POST", "/allow", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	AllowHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing TTL, got %d", w.Code)
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"-1h", "expired"},
		{"0", "0m"},
		{"30m", "30m"},
		{"1h", "1h 0m"},
		{"2h30m", "2h 30m"},
		{"48h", "48h 0m"},
		{"24h1m", "24h 1m"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			d, err := time.ParseDuration(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			got := formatDuration(d)
			if got != tt.expected {
				t.Errorf("formatDuration(%s) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
