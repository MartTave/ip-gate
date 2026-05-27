package handler

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"

	"ttl-allow-service/src/internal/assets"
	"ttl-allow-service/src/internal/logger"
	"ttl-allow-service/src/internal/state"
)

var pwaTemplate = template.Must(template.New("pwa").Parse(assets.PwaTemplate))

func PWAHandler(w http.ResponseWriter, r *http.Request) {
	ip, ok := requireClientIP(r, w)
	if !ok {
		return
	}
	if !requireRateLimit(ip, "/pwa", w) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !state.HasPermanentKeys() {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, assets.NoKeysHTML)
		return
	}
	w.Header().Set("Content-Type", "text/html")
	pwaTemplate.Execute(w, nil)
}

func PWAStatusHandler(w http.ResponseWriter, r *http.Request) {
	ip, ok := requireClientIP(r, w)
	if !ok {
		return
	}
	if !requireRateLimit(ip, "/pwa/status", w) {
		return
	}
	if !requirePOST(r, w) {
		return
	}
	if !requireKeysActivated(w) {
		return
	}
	if !requireParseForm(r, w) {
		return
	}

	key := r.FormValue("key")

	if key == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"client_ip": ip,
		})
		return
	}

	name, ok := lookupValidKey(key, w, map[string]interface{}{
		"client_ip": ip,
		"key_valid": false,
		"error":     "invalid_key",
	})
	if !ok {
		return
	}

	status := state.GetIPAuthStatus(ip)
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

func PWAAuthHandler(w http.ResponseWriter, r *http.Request) {
	ip, ok := requireClientIP(r, w)
	if !ok {
		return
	}
	if !requireRateLimit(ip, "/pwa/auth", w) {
		return
	}
	if !requirePOST(r, w) {
		return
	}
	if !requireKeysActivated(w) {
		return
	}
	if !requireParseForm(r, w) {
		return
	}

	key, ok := requireFormKey(r, w, ip)
	if !ok {
		return
	}
	name, ok := lookupValidKey(key, w, map[string]interface{}{
		"authorized": false,
		"client_ip":  ip,
	})
	if !ok {
		return
	}

	err := state.ApproveIPByKey(ip, name)
	if err != nil {
		writeAPIError(w, ErrApprovalFailed, map[string]interface{}{
			"authorized": false,
			"client_ip":  ip,
			"message":    err.Error(),
		})
		return
	}

	logger.Info("ip_allowed_by_key", "target_ip", ip, "key_name", name)

	status := state.GetIPAuthStatus(ip)
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

func PWARevokeHandler(w http.ResponseWriter, r *http.Request) {
	ip, ok := requireClientIP(r, w)
	if !ok {
		return
	}
	if !requireRateLimit(ip, "/pwa/revoke", w) {
		return
	}
	if !requirePOST(r, w) {
		return
	}
	if !requireKeysActivated(w) {
		return
	}
	if !requireParseForm(r, w) {
		return
	}

	key, ok := requireFormKey(r, w, ip)
	if !ok {
		return
	}
	name, ok := lookupValidKey(key, w, map[string]interface{}{
		"authorized": false,
		"client_ip":  ip,
	})
	if !ok {
		return
	}

	if err := state.RevokeIPByKey(ip, name); err != nil {
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

func ManifestHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, assets.ManifestJSON)
}

func ServiceWorkerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, assets.ServiceWorkerJS)
}

func PwaIconHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, assets.PwaIconSVG)
}
