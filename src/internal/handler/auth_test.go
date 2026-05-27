package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ttl-allow-service/src/internal/config"
	"ttl-allow-service/src/internal/state"
)

func setupTest(t *testing.T) {
	t.Helper()
	state.ResetTestState()
	cfg := config.LoadDefaults()
	state.Init(cfg)
}

func TestHealthHandler_Get(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	HealthHandler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHealthHandler_WrongMethod(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest("POST", "/health", nil)
	w := httptest.NewRecorder()
	HealthHandler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestAuthHandler_Allowed(t *testing.T) {
	setupTest(t)
	state.AddKnockRequest("1.2.3.4")
	state.ApproveIP("1.2.3.4", "1h")

	req := httptest.NewRequest("GET", "/auth", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	w := httptest.NewRecorder()
	AuthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "allowed") {
		t.Errorf("expected 'allowed', got '%s'", w.Body.String())
	}
}

func TestAuthHandler_Denied(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest("GET", "/auth", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	w := httptest.NewRecorder()
	AuthHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "denied") {
		t.Errorf("expected 'denied', got '%s'", w.Body.String())
	}
}

func TestAuthHandler_WrongMethod(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest("POST", "/auth", nil)
	w := httptest.NewRecorder()
	AuthHandler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestKnockHandler_Success(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest("GET", "/knock", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	w := httptest.NewRecorder()
	KnockHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "request received") {
		t.Errorf("expected 'request received', got '%s'", w.Body.String())
	}
}

func TestKnockHandler_AlreadyAllowed(t *testing.T) {
	setupTest(t)
	state.AddKnockRequest("1.2.3.4")
	state.ApproveIP("1.2.3.4", "1h")

	req := httptest.NewRequest("GET", "/knock", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	w := httptest.NewRecorder()
	KnockHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "already allowed") {
		t.Errorf("expected 'already allowed', got '%s'", w.Body.String())
	}
}

func TestKnockHandler_CannotRequest(t *testing.T) {
	setupTest(t)
	state.AddKnockRequest("1.2.3.4")

	req := httptest.NewRequest("GET", "/knock", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	w := httptest.NewRecorder()
	KnockHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "cannot request") {
		t.Errorf("expected 'cannot request', got '%s'", w.Body.String())
	}
}

func TestKnockHandler_WrongMethod(t *testing.T) {
	setupTest(t)
	req := httptest.NewRequest("POST", "/knock", nil)
	w := httptest.NewRecorder()
	KnockHandler(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}
