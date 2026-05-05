package handler

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"ttl-allow-service/src/internal/gui"
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

// extractClientIPForAuth extracts client IP, preferring proxy headers (X-Forwarded-For, X-Real-IP)
func ExtractClientIPForAuth(r *http.Request) string {
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

// AuthHandler handles GET /auth (Caddy auth endpoint)
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := ExtractClientIPForAuth(r)
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

	ip := getClientIP(r)
	if ip == "" {
		http.Error(w, "Could not determine client IP", http.StatusBadRequest)
		return
	}

	// Rate limiting
	if !store.CheckRateLimit(ip) {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	// Add knock request
	if !store.AddKnockRequest(ip) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "already requested")
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
		store.DenyIP(req.IP)
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
		store.RevokeIP(req.IP)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "revoked")

	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	// If this was a form submission (from GUI), redirect back to the GUI
	if !strings.Contains(r.Header.Get("Content-Type"), "application/json") && r.Header.Get("Accept") != "application/json" {
		http.Redirect(w, r, "/allow", http.StatusSeeOther)
	}
}
