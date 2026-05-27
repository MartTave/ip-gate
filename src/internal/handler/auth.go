package handler

import (
	"fmt"
	"net/http"

	"ttl-allow-service/src/internal/logger"
	"ttl-allow-service/src/internal/state"
)

func HealthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
}

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

	if !state.CheckAuthRateLimit(ip) {
		logger.Warn("ip_rate_limited", "ip", ip, "path", "/auth")
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	if state.CheckIPAllowed(ip) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "allowed")
	} else {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "denied")
	}
}

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

	if !state.CheckRateLimit(ip) {
		logger.Warn("ip_rate_limited", "ip", ip, "path", "/knock")
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	if state.CheckIPAllowed(ip) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "already allowed")
		return
	}

	if !state.AddKnockRequest(ip) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "cannot request")
		return
	}

	logger.Info("ip_knocked", "ip", ip)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "request received")
}
