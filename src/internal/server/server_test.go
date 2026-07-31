package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ttl-allow-service/src/internal/config"
	"ttl-allow-service/src/internal/state"
)

func setupIntegration(t *testing.T, opts ...func(*config.Config)) (*httptest.Server, func()) {
	t.Helper()
	state.ResetTestState()
	cfg := config.LoadDefaults()
	cfg.Server.Port = 0
	cfg.Rate.KnockMaxRequests = 20
	cfg.Rate.KnockWindowSec = 60
	cfg.Rate.AuthMaxRequests = 100
	cfg.Rate.AuthWindowSec = 60
	cfg.TTL.RequestTTLMinutes = 5
	cfg.TTL.MaxTTL = 48 * time.Hour
	cfg.Keys.AuthTTL = config.Duration(4 * time.Hour)
	cfg.Keys.MaxIPs = 5
	for _, opt := range opts {
		opt(cfg)
	}
	cfg.AfterLoad()
	state.Init(cfg)

	mux := NewHandler(cfg)
	srv := httptest.NewServer(mux)
	return srv, func() {
		srv.Close()
		state.ResetTestState()
	}
}

func withKnockRate(max int, windowSec int) func(*config.Config) {
	return func(cfg *config.Config) {
		cfg.Rate.KnockMaxRequests = max
		cfg.Rate.KnockWindowSec = windowSec
	}
}

func withAuthRate(max int, windowSec int) func(*config.Config) {
	return func(cfg *config.Config) {
		cfg.Rate.AuthMaxRequests = max
		cfg.Rate.AuthWindowSec = windowSec
	}
}

func withKeys(entries []config.KeyEntry, maxIPs int) func(*config.Config) {
	return func(cfg *config.Config) {
		cfg.Keys.Entries = entries
		cfg.Keys.MaxIPs = maxIPs
		cfg.Keys.AuthTTL = config.Duration(time.Hour)
	}
}

func request(t *testing.T, method, url string, body io.Reader, headers ...string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	for i := 0; i < len(headers); i += 2 {
		if headers[i+1] != "" {
			req.Header.Set(headers[i], headers[i+1])
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func assertStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Errorf("expected status %d, got %d", want, resp.StatusCode)
	}
}

func assertContentType(t *testing.T, resp *http.Response, want string) {
	t.Helper()
	if ct := resp.Header.Get("Content-Type"); ct != want {
		t.Errorf("expected Content-Type %q, got %q", want, ct)
	}
}

func bodyString(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	return string(b)
}

func bodyJSON(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("failed to decode JSON body: %v (body: %s)", err, bodyString(t, resp))
	}
	return m
}

func TestHealth_Get(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	resp := request(t, "GET", srv.URL+"/health", nil)
	assertStatus(t, resp, http.StatusOK)
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if len(b) != 0 {
		t.Errorf("expected empty body, got %q", string(b))
	}
}

func TestHealth_WrongMethod(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		resp := request(t, method, srv.URL+"/health", nil)
		assertStatus(t, resp, http.StatusMethodNotAllowed)
	}
}

func TestKnock_Success(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	resp := request(t, "GET", srv.URL+"/knock", nil,
		"X-Forwarded-For", "1.2.3.4",
	)
	assertStatus(t, resp, http.StatusOK)
	if body := bodyString(t, resp); body != "request received" {
		t.Errorf("expected 'request received', got %q", body)
	}
}

func TestKnock_AlreadyAllowed(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	request(t, "GET", srv.URL+"/knock", nil, "X-Forwarded-For", "1.2.3.4")
	request(t, "POST", srv.URL+"/allow", strings.NewReader("ip=1.2.3.4&action=allow&ttl=1h"),
		"Content-Type", "application/x-www-form-urlencoded",
	)

	resp := request(t, "GET", srv.URL+"/knock", nil, "X-Forwarded-For", "1.2.3.4")
	assertStatus(t, resp, http.StatusOK)
	if body := bodyString(t, resp); body != "already allowed" {
		t.Errorf("expected 'already allowed', got %q", body)
	}
}

func TestKnock_CannotRequest(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	request(t, "GET", srv.URL+"/knock", nil, "X-Forwarded-For", "1.2.3.4")
	request(t, "POST", srv.URL+"/allow", strings.NewReader("ip=1.2.3.4&action=deny"),
		"Content-Type", "application/x-www-form-urlencoded",
	)

	resp := request(t, "GET", srv.URL+"/knock", nil, "X-Forwarded-For", "1.2.3.4")
	assertStatus(t, resp, http.StatusOK)
	if body := bodyString(t, resp); body != "cannot request" {
		t.Errorf("expected 'cannot request', got %q", body)
	}
}

func TestKnock_RateLimited(t *testing.T) {
	srv, cleanup := setupIntegration(t, withKnockRate(3, 60))
	defer cleanup()

	ip := "1.2.3.4"
	for i := 0; i < 3; i++ {
		resp := request(t, "GET", srv.URL+"/knock", nil, "X-Forwarded-For", ip)
		assertStatus(t, resp, http.StatusOK)
	}

	resp := request(t, "GET", srv.URL+"/knock", nil, "X-Forwarded-For", ip)
	assertStatus(t, resp, http.StatusTooManyRequests)

	resp2 := request(t, "GET", srv.URL+"/knock", nil, "X-Forwarded-For", "9.9.9.9")
	assertStatus(t, resp2, http.StatusOK)
}

func TestKnock_FallbackIP(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	resp := request(t, "GET", srv.URL+"/knock", nil)
	assertStatus(t, resp, http.StatusOK)
	if body := bodyString(t, resp); body != "request received" {
		t.Errorf("expected 'request received', got %q", body)
	}
}

func TestKnock_WrongMethod(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	for _, method := range []string{"POST", "PUT", "DELETE"} {
		resp := request(t, method, srv.URL+"/knock", nil,
			"X-Forwarded-For", "1.2.3.4",
		)
		assertStatus(t, resp, http.StatusMethodNotAllowed)
	}
}

func TestAuth_Allowed(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	request(t, "GET", srv.URL+"/knock", nil, "X-Forwarded-For", "1.2.3.4")
	request(t, "POST", srv.URL+"/allow", strings.NewReader("ip=1.2.3.4&action=allow&ttl=1h"),
		"Content-Type", "application/x-www-form-urlencoded",
	)

	resp := request(t, "GET", srv.URL+"/auth", nil, "X-Forwarded-For", "1.2.3.4")
	assertStatus(t, resp, http.StatusOK)
	if body := bodyString(t, resp); body != "allowed" {
		t.Errorf("expected 'allowed', got %q", body)
	}
}

func TestAuth_Denied(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	resp := request(t, "GET", srv.URL+"/auth", nil, "X-Forwarded-For", "1.2.3.4")
	assertStatus(t, resp, http.StatusForbidden)
	if body := bodyString(t, resp); body != "denied" {
		t.Errorf("expected 'denied', got %q", body)
	}
}

func TestAuth_RateLimited(t *testing.T) {
	srv, cleanup := setupIntegration(t, withAuthRate(2, 60))
	defer cleanup()

	ip := "1.2.3.4"
	for i := 0; i < 2; i++ {
		resp := request(t, "GET", srv.URL+"/auth", nil, "X-Forwarded-For", ip)
		assertStatus(t, resp, http.StatusForbidden)
	}

	resp := request(t, "GET", srv.URL+"/auth", nil, "X-Forwarded-For", ip)
	assertStatus(t, resp, http.StatusTooManyRequests)
}

func TestAllow_GetJSON(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	request(t, "GET", srv.URL+"/knock", nil, "X-Forwarded-For", "1.2.3.4")
	request(t, "GET", srv.URL+"/knock", nil, "X-Forwarded-For", "5.6.7.8")
	request(t, "POST", srv.URL+"/allow", strings.NewReader("ip=5.6.7.8&action=allow&ttl=1h"),
		"Content-Type", "application/x-www-form-urlencoded",
	)

	resp := request(t, "GET", srv.URL+"/allow", nil)
	assertStatus(t, resp, http.StatusOK)
	assertContentType(t, resp, "application/json")

	m := bodyJSON(t, resp)
	pending := m["pending"].([]interface{})
	approved := m["approved"].([]interface{})
	if len(pending) != 1 {
		t.Errorf("expected 1 pending, got %d", len(pending))
	}
	if len(approved) != 1 {
		t.Errorf("expected 1 approved, got %d", len(approved))
	}
}

func TestAllow_GetHTML(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	resp := request(t, "GET", srv.URL+"/allow", nil, "Accept", "text/html")
	assertStatus(t, resp, http.StatusOK)
	assertContentType(t, resp, "text/html")
}

func TestAllow_PostAllow(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	request(t, "GET", srv.URL+"/knock", nil, "X-Forwarded-For", "1.2.3.4")

	body := strings.NewReader("ip=1.2.3.4&action=allow&ttl=1h")
	resp := request(t, "POST", srv.URL+"/allow", body,
		"Content-Type", "application/x-www-form-urlencoded",
	)
	assertStatus(t, resp, http.StatusOK)
	if b := bodyString(t, resp); b != "allowed" {
		t.Errorf("expected 'allowed', got %q", b)
	}
}

func TestAllow_PostDeny(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	request(t, "GET", srv.URL+"/knock", nil, "X-Forwarded-For", "1.2.3.4")

	resp := request(t, "POST", srv.URL+"/allow", strings.NewReader("ip=1.2.3.4&action=deny"),
		"Content-Type", "application/x-www-form-urlencoded",
	)
	assertStatus(t, resp, http.StatusOK)
	if b := bodyString(t, resp); b != "denied" {
		t.Errorf("expected 'denied', got %q", b)
	}
}

func TestAllow_PostRevoke(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	request(t, "GET", srv.URL+"/knock", nil, "X-Forwarded-For", "1.2.3.4")
	request(t, "POST", srv.URL+"/allow", strings.NewReader("ip=1.2.3.4&action=allow&ttl=1h"),
		"Content-Type", "application/x-www-form-urlencoded",
	)

	resp := request(t, "POST", srv.URL+"/allow", strings.NewReader("ip=1.2.3.4&action=revoke"),
		"Content-Type", "application/x-www-form-urlencoded",
	)
	assertStatus(t, resp, http.StatusOK)
	if b := bodyString(t, resp); b != "revoked" {
		t.Errorf("expected 'revoked', got %q", b)
	}

	authResp := request(t, "GET", srv.URL+"/auth", nil, "X-Forwarded-For", "1.2.3.4")
	assertStatus(t, authResp, http.StatusForbidden)
}

func TestAllow_MissingFields(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	resp := request(t, "POST", srv.URL+"/allow", nil,
		"Content-Type", "application/x-www-form-urlencoded",
	)
	assertStatus(t, resp, http.StatusBadRequest)
}

func TestAllow_InvalidAction(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	resp := request(t, "POST", srv.URL+"/allow", strings.NewReader("ip=1.2.3.4&action=bogus"),
		"Content-Type", "application/x-www-form-urlencoded",
	)
	assertStatus(t, resp, http.StatusBadRequest)
}

func TestAllow_WrongMethod(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	for _, method := range []string{"PUT", "DELETE", "PATCH"} {
		resp := request(t, method, srv.URL+"/allow", nil)
		assertStatus(t, resp, http.StatusMethodNotAllowed)
	}
}

func TestPWA_NoKeys_Endpoints(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"status", "POST", "/pwa/status"},
		{"auth", "POST", "/pwa/auth"},
		{"revoke", "POST", "/pwa/revoke"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.method == "POST" {
				body = strings.NewReader("key=anything")
			}
			resp := request(t, tt.method, srv.URL+tt.path, body,
				"Content-Type", "application/x-www-form-urlencoded",
				"X-Forwarded-For", "1.2.3.4",
			)
			assertStatus(t, resp, http.StatusOK)
			assertContentType(t, resp, "application/json")
			m := bodyJSON(t, resp)
			if m["error"] != "not_configured" {
				t.Errorf("expected error 'not_configured', got %v", m["error"])
			}
		})
	}
}

func TestPWAHandler_NoKeys(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	resp := request(t, "GET", srv.URL+"/pwa", nil, "X-Forwarded-For", "1.2.3.4")
	assertStatus(t, resp, http.StatusOK)
	assertContentType(t, resp, "text/html")
	body := bodyString(t, resp)
	if !strings.Contains(body, "no keys configured") &&
		!strings.Contains(body, "No Keys") &&
		!strings.Contains(body, "not configured") {
		t.Errorf("expected no-keys message, got: %s", body[:200])
	}
}

func TestPWA_KeyLifecycle(t *testing.T) {
	srv, cleanup := setupIntegration(t, withKeys([]config.KeyEntry{
		{Key: "valid-key", Name: "test-key"},
	}, 5))
	defer cleanup()

	t.Run("status_no_key", func(t *testing.T) {
		resp := request(t, "POST", srv.URL+"/pwa/status", nil,
			"Content-Type", "application/x-www-form-urlencoded",
			"X-Forwarded-For", "1.2.3.4",
		)
		assertStatus(t, resp, http.StatusOK)
		assertContentType(t, resp, "application/json")
		m := bodyJSON(t, resp)
		if m["client_ip"] != "1.2.3.4" {
			t.Errorf("expected client_ip '1.2.3.4', got %v", m["client_ip"])
		}
	})

	t.Run("status_valid_key", func(t *testing.T) {
		resp := request(t, "POST", srv.URL+"/pwa/status",
			strings.NewReader("key=valid-key"),
			"Content-Type", "application/x-www-form-urlencoded",
			"X-Forwarded-For", "1.2.3.4",
		)
		assertStatus(t, resp, http.StatusOK)
		m := bodyJSON(t, resp)
		if m["key_valid"] != true {
			t.Errorf("expected key_valid true, got %v", m["key_valid"])
		}
		if m["key_name"] != "test-key" {
			t.Errorf("expected key_name 'test-key', got %v", m["key_name"])
		}
	})

	t.Run("status_invalid_key", func(t *testing.T) {
		resp := request(t, "POST", srv.URL+"/pwa/status",
			strings.NewReader("key=bad-key"),
			"Content-Type", "application/x-www-form-urlencoded",
			"X-Forwarded-For", "1.2.3.4",
		)
		assertStatus(t, resp, http.StatusUnauthorized)
		m := bodyJSON(t, resp)
		if m["error"] != "invalid_key" {
			t.Errorf("expected error 'invalid_key', got %v", m["error"])
		}
	})

	t.Run("auth_valid_key", func(t *testing.T) {
		resp := request(t, "POST", srv.URL+"/pwa/auth",
			strings.NewReader("key=valid-key"),
			"Content-Type", "application/x-www-form-urlencoded",
			"X-Forwarded-For", "1.2.3.4",
		)
		assertStatus(t, resp, http.StatusOK)
		m := bodyJSON(t, resp)
		if m["authorized"] != true {
			t.Errorf("expected authorized true, got %v", m["authorized"])
		}
	})

	t.Run("auth_duplicate_key", func(t *testing.T) {
		resp := request(t, "POST", srv.URL+"/pwa/auth",
			strings.NewReader("key=valid-key"),
			"Content-Type", "application/x-www-form-urlencoded",
			"X-Forwarded-For", "1.2.3.4",
		)
		assertStatus(t, resp, http.StatusOK)
	})

	t.Run("status_after_auth", func(t *testing.T) {
		resp := request(t, "POST", srv.URL+"/pwa/status",
			strings.NewReader("key=valid-key"),
			"Content-Type", "application/x-www-form-urlencoded",
			"X-Forwarded-For", "1.2.3.4",
		)
		assertStatus(t, resp, http.StatusOK)
		m := bodyJSON(t, resp)
		if m["authorized"] != true {
			t.Errorf("expected authorized true after auth, got %v", m["authorized"])
		}
	})

	t.Run("revoke", func(t *testing.T) {
		resp := request(t, "POST", srv.URL+"/pwa/revoke",
			strings.NewReader("key=valid-key"),
			"Content-Type", "application/x-www-form-urlencoded",
			"X-Forwarded-For", "1.2.3.4",
		)
		assertStatus(t, resp, http.StatusOK)
		m := bodyJSON(t, resp)
		if m["status"] != "revoked" {
			t.Errorf("expected status 'revoked', got %v", m["status"])
		}
		if m["authorized"] != false {
			t.Errorf("expected authorized false after revoke, got %v", m["authorized"])
		}
	})

	t.Run("status_after_revoke", func(t *testing.T) {
		resp := request(t, "POST", srv.URL+"/pwa/status",
			strings.NewReader("key=valid-key"),
			"Content-Type", "application/x-www-form-urlencoded",
			"X-Forwarded-For", "1.2.3.4",
		)
		assertStatus(t, resp, http.StatusOK)
		m := bodyJSON(t, resp)
		if m["authorized"] == true {
			t.Errorf("expected authorized false after revoke, got %v", m["authorized"])
		}
	})

	t.Run("re_auth_after_revoke", func(t *testing.T) {
		resp := request(t, "POST", srv.URL+"/pwa/auth",
			strings.NewReader("key=valid-key"),
			"Content-Type", "application/x-www-form-urlencoded",
			"X-Forwarded-For", "1.2.3.4",
		)
		assertStatus(t, resp, http.StatusOK)
		m := bodyJSON(t, resp)
		if m["authorized"] != true {
			t.Errorf("expected authorized true after re-auth, got %v", m["authorized"])
		}
	})
}

func TestPWAStaticFiles(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	t.Run("manifest", func(t *testing.T) {
		resp := request(t, "GET", srv.URL+"/pwa/manifest.json", nil)
		assertStatus(t, resp, http.StatusOK)
		assertContentType(t, resp, "application/json")
	})

	t.Run("service_worker", func(t *testing.T) {
		resp := request(t, "GET", srv.URL+"/pwa/service-worker.js", nil)
		assertStatus(t, resp, http.StatusOK)
		assertContentType(t, resp, "application/javascript")
	})

	t.Run("icon", func(t *testing.T) {
		resp := request(t, "GET", srv.URL+"/pwa/pwa-icon.svg", nil)
		assertStatus(t, resp, http.StatusOK)
		assertContentType(t, resp, "image/svg+xml")
	})
}

func TestXForwardedFor_XRealIP(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	t.Run("x-forwarded-for", func(t *testing.T) {
		resp := request(t, "GET", srv.URL+"/knock", nil,
			"X-Forwarded-For", "10.0.0.1",
		)
		assertStatus(t, resp, http.StatusOK)

		resp2 := request(t, "GET", srv.URL+"/auth", nil,
			"X-Forwarded-For", "10.0.0.1",
		)
		assertStatus(t, resp2, http.StatusForbidden)

		request(t, "POST", srv.URL+"/allow",
			strings.NewReader("ip=10.0.0.1&action=allow&ttl=1h"),
			"Content-Type", "application/x-www-form-urlencoded",
			"X-Forwarded-For", "192.168.1.1",
		)

		resp3 := request(t, "GET", srv.URL+"/auth", nil,
			"X-Forwarded-For", "10.0.0.1",
		)
		assertStatus(t, resp3, http.StatusOK)
	})

	t.Run("x-real-ip", func(t *testing.T) {
		resp := request(t, "GET", srv.URL+"/knock", nil,
			"X-Real-IP", "10.0.0.2",
		)
		assertStatus(t, resp, http.StatusOK)
	})

	t.Run("xff_precedence_over_xri", func(t *testing.T) {
		resp := request(t, "GET", srv.URL+"/knock", nil,
			"X-Forwarded-For", "10.0.0.3",
			"X-Real-IP", "10.0.0.4",
		)
		assertStatus(t, resp, http.StatusOK)
	})
}

func TestConcurrentRequests(t *testing.T) {
	srv, cleanup := setupIntegration(t)
	defer cleanup()

	errs := make(chan error, 10)
	for i := 0; i < 5; i++ {
		go func(id int) {
			ip := fmt.Sprintf("10.0.0.%d", id)
			resp := request(t, "GET", srv.URL+"/knock", nil,
				"X-Forwarded-For", ip,
			)
			if resp.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("request %d: expected 200, got %d", id, resp.StatusCode)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "request received" {
				errs <- fmt.Errorf("request %d: expected 'request received', got %q", id, string(body))
				return
			}
			errs <- nil
		}(i)
	}

	for i := 0; i < 5; i++ {
		select {
		case err := <-errs:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent requests")
		}
	}
}
