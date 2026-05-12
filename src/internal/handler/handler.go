package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"ttl-allow-service/src/internal/assets"
	"ttl-allow-service/src/internal/gui"
	"ttl-allow-service/src/internal/pwa"
	"ttl-allow-service/src/internal/store"
)

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ExtractClientIPFromHeaders extracts client IP, preferring proxy headers (X-Forwarded-For, X-Real-IP)
func ExtractClientIPFromHeaders(r *http.Request) string {
	// Prefer X-Forwarded-For (Caddy forwards original client IP here)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	// Fallback to X-Real-IP
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	return getClientIP(r)
}

// HealthHandler handles GET /health (health check endpoint)
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// AuthHandler handles GET /auth (Caddy auth endpoint)
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := ExtractClientIPFromHeaders(r)
	if ip == "" {
		http.Error(w, "Could not determine client IP", http.StatusBadRequest)
		return
	}

	if store.CheckIPAllowed(ip) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "allowed")
	} else {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "denied")
	}
}

// KnockHandler handles GET /knock (public endpoint)
func KnockHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := ExtractClientIPFromHeaders(r)
	if ip == "" {
		http.Error(w, "Could not determine client IP", http.StatusBadRequest)
		return
	}

	// Rate limiting (applied to all /knock requests)
	if !store.CheckRateLimit(ip) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	// Check if IP is already approved
	if store.CheckIPAllowed(ip) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "already allowed")
		return
	}

	// Add knock request
	if !store.AddKnockRequest(ip) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "cannot request")
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "request received")
}

// AllowHandler handles GET/POST /allow (admin endpoint)
func AllowHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleAllowGet(w, r)
	case http.MethodPost:
		handleAllowPost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAllowGet serves the admin GUI or JSON based on Accept header
func handleAllowGet(w http.ResponseWriter, r *http.Request) {
	accept := r.Header.Get("Accept")

	// If client accepts HTML, render GUI
	if strings.Contains(accept, "text/html") {
		gui.RenderGUI(w, r)
		return
	}

	// Otherwise return JSON (API mode)
	pending := store.GetPendingRequests()
	approved := store.GetApprovedIPs()

	response := map[string]interface{}{
		"pending":  pending,
		"approved": approved,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAllowPost handles approval/denial of IPs (JSON or form-encoded)
func handleAllowPost(w http.ResponseWriter, r *http.Request) {
	var req store.AllowRequest

	// Try to parse as JSON first, fall back to form data
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
	} else {
		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		req.IP = r.FormValue("ip")
		req.Action = r.FormValue("action")
		req.TTL = r.FormValue("ttl")
	}

	if req.IP == "" || req.Action == "" {
		http.Error(w, "Missing ip or action", http.StatusBadRequest)
		return
	}

	switch req.Action {
	case "deny":
		err := store.DenyIP(req.IP)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "denied")

	case "allow":
		if req.TTL == "" {
			http.Error(w, "TTL required for allow action", http.StatusBadRequest)
			return
		}
		err := store.ApproveIP(req.IP, req.TTL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "allowed")

	case "revoke":
		err := store.RevokeIP(req.IP)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "revoked")

	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	// No redirect - AJAX handles the UI update
}

// PWAHandler handles GET /pwa (PWA status page)
func PWAHandler(w http.ResponseWriter, r *http.Request) {
	ip := ExtractClientIPFromHeaders(r)
	if ip == "" {
		http.Error(w, "Could not determine client IP", http.StatusForbidden)
		return
	}
	if !store.CheckRateLimit(ip) {
		writeAPIError(w, ErrRateLimited, map[string]interface{}{"client_ip": ip})
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !store.HasPermanentKeys() {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, assets.NoKeysHTML)
		return
	}
	pwa.RenderPWA(w)
}

// writeKeysDisabled sends a JSON error response when no keys are configured
func writeKeysDisabled(w http.ResponseWriter) {
	writeAPIError(w, ErrNotConfigured, nil)
}

// PWAStatusHandler handles POST /pwa/status (get authorization status, key in body)
func PWAStatusHandler(w http.ResponseWriter, r *http.Request) {
	ip := ExtractClientIPFromHeaders(r)
	if ip == "" {
		writeAPIError(w, ErrNoIP, nil)
		return
	}
	if !store.CheckRateLimit(ip) {
		writeAPIError(w, ErrRateLimited, map[string]interface{}{"client_ip": ip})
		return
	}
	if r.Method != http.MethodPost {
		writeAPIError(w, ErrMethodNotAllowed, nil)
		return
	}
	if !store.HasPermanentKeys() {
		writeKeysDisabled(w)
		return
	}

	if err := r.ParseForm(); err != nil {
		writeAPIError(w, ErrInvalidForm, nil)
		return
	}

	key := r.FormValue("key")

	// No key provided
	if key == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"client_ip": ip,
		})
		return
	}

	// Validate key
	name, exists := store.PermanentKeys[key]
	if !exists {
		// Invalid key
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"client_ip": ip,
			"key_valid": false,
			"error":     "invalid_key",
		})
		return
	}

	// Valid key

	// Check auth status
	status := store.GetIPAuthStatus(ip)
	resp := map[string]interface{}{
		"client_ip": ip,
		"key_valid": true,
		"key_name":  name,
	}
	if status.Authorized {
		resp["authorized"] = true
		resp["expires_at"] = status.ExpiresAt.Format(time.RFC3339)
		resp["expires_in_seconds"] = int(time.Until(status.ExpiresAt).Seconds())
	} else {
		resp["authorized"] = false
	}
	writeJSON(w, http.StatusOK, resp)
}

// PWAAuthHandler handles POST /pwa/auth (authorize current IP using key in body)
func PWAAuthHandler(w http.ResponseWriter, r *http.Request) {
	ip := ExtractClientIPFromHeaders(r)
	if ip == "" {
		writeAPIError(w, ErrNoIP, nil)
		return
	}
	if !store.CheckRateLimit(ip) {
		writeAPIError(w, ErrRateLimited, map[string]interface{}{"client_ip": ip})
		return
	}
	if r.Method != http.MethodPost {
		writeAPIError(w, ErrMethodNotAllowed, nil)
		return
	}
	if !store.HasPermanentKeys() {
		writeKeysDisabled(w)
		return
	}

	if err := r.ParseForm(); err != nil {
		writeAPIError(w, ErrInvalidForm, nil)
		return
	}

	key := r.FormValue("key")
	if key == "" {
		writeAPIError(w, ErrMissingKey, map[string]interface{}{
			"authorized": false,
			"client_ip":  ip,
		})
		return
	}

	name, exists := store.PermanentKeys[key]
	if !exists {
		writeAPIError(w, ErrInvalidKey, map[string]interface{}{
			"authorized": false,
			"client_ip":  ip,
		})
		return
	}

	// Authorize or re-authorize via key
	err := store.ApproveIPByKey(ip, name)
	if err != nil {
		writeAPIError(w, ErrApprovalFailed, map[string]interface{}{
			"authorized": false,
			"client_ip":  ip,
			"message":    err.Error(),
		})
		return
	}

	status := store.GetIPAuthStatus(ip)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":              "now_authorized",
		"authorized":          true,
		"expires_at":          status.ExpiresAt.Format(time.RFC3339),
		"expires_in_seconds":  int(time.Until(status.ExpiresAt).Seconds()),
		"key_name":            name,
		"client_ip":           ip,
		"message":             fmt.Sprintf("Authorized via key: %s", name),
	})
}

// PWARevokeHandler handles POST /pwa/revoke (remove authorization for current IP)
func PWARevokeHandler(w http.ResponseWriter, r *http.Request) {
	ip := ExtractClientIPFromHeaders(r)
	if ip == "" {
		writeAPIError(w, ErrNoIP, nil)
		return
	}
	if !store.CheckRateLimit(ip) {
		writeAPIError(w, ErrRateLimited, map[string]interface{}{"client_ip": ip})
		return
	}
	if r.Method != http.MethodPost {
		writeAPIError(w, ErrMethodNotAllowed, nil)
		return
	}
	if !store.HasPermanentKeys() {
		writeKeysDisabled(w)
		return
	}

	if err := r.ParseForm(); err != nil {
		writeAPIError(w, ErrInvalidForm, nil)
		return
	}

	key := r.FormValue("key")
	if key == "" {
		writeAPIError(w, ErrMissingKey, map[string]interface{}{
			"authorized": false,
			"client_ip":  ip,
		})
		return
	}

	name, exists := store.PermanentKeys[key]
	if !exists {
		writeAPIError(w, ErrInvalidKey, map[string]interface{}{
			"authorized": false,
			"client_ip":  ip,
		})
		return
	}

	if err := store.RevokeIPByKey(ip, name); err != nil {
		writeAPIError(w, ErrRevokeFailed, map[string]interface{}{
			"authorized": false,
			"client_ip":  ip,
			"message":    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "revoked",
		"authorized": false,
		"client_ip":  ip,
		"key_name":   name,
		"message":    "Authorization removed",
	})
}

// ManifestHandler serves the PWA manifest.json
func ManifestHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, assets.ManifestJSON)
}

// ServiceWorkerHandler serves the service worker script
func ServiceWorkerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, assets.ServiceWorkerJS)
}

// PwaIconHandler serves the PWA SVG icon
func PwaIconHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, assets.PwaIconSVG)
}

// writeJSON is a helper to write a JSON response
func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
