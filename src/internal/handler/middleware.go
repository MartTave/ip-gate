package handler

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"ttl-allow-service/src/internal/logger"
	"ttl-allow-service/src/internal/state"
)

func getClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func ExtractClientIPFromHeaders(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	return getClientIP(r)
}

func writeKeysDisabled(w http.ResponseWriter) {
	writeAPIError(w, ErrNotConfigured, nil)
}

func requireKeysActivated(w http.ResponseWriter) bool {
	if !state.HasPermanentKeys() {
		writeKeysDisabled(w)
		return false
	}
	return true
}

func requirePOST(r *http.Request, w http.ResponseWriter) bool {
	if r.Method != http.MethodPost {
		writeAPIError(w, ErrMethodNotAllowed, nil)
		return false
	}
	return true
}

func requireClientIP(r *http.Request, w http.ResponseWriter) (string, bool) {
	ip := ExtractClientIPFromHeaders(r)
	if ip == "" {
		writeAPIError(w, ErrNoIP, nil)
		return "", false
	}
	return ip, true
}

func requireRateLimit(ip, path string, w http.ResponseWriter) bool {
	if !state.CheckRateLimit(ip) {
		logger.Warn("ip_rate_limited", "ip", ip, "path", path)
		writeAPIError(w, ErrRateLimited, map[string]interface{}{"client_ip": ip})
		return false
	}
	return true
}

func requireParseForm(r *http.Request, w http.ResponseWriter) bool {
	if err := r.ParseForm(); err != nil {
		writeAPIError(w, ErrInvalidForm, nil)
		return false
	}
	return true
}

func requireFormKey(r *http.Request, w http.ResponseWriter, ip string) (string, bool) {
	key := r.FormValue("key")
	if key == "" {
		writeAPIError(w, ErrMissingKey, map[string]interface{}{
			"authorized": false,
			"client_ip":  ip,
		})
		return "", false
	}
	return key, true
}

func lookupValidKey(key string, w http.ResponseWriter, extra map[string]interface{}) (string, bool) {
	name, exists := state.LookupKey(key)
	if !exists {
		writeAPIError(w, ErrInvalidKey, extra)
		return "", false
	}
	return name, true
}

func writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}
