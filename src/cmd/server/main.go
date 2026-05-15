package main

import (
	"log"
	"net/http"

	"ttl-allow-service/src/internal/handler"
	"ttl-allow-service/src/internal/logger"
	"ttl-allow-service/src/internal/store"
	"ttl-allow-service/src/internal/worker"
)

func main() {
	// Load environment variables
	store.LoadEnv()

	// Startup
	logger.Info("starting_server")
	logger.Info("rate_limit_config",
		"knock_max", store.RateLimitMaxRequests,
		"knock_window_sec", store.RateLimitWindowSec,
		"auth_max", store.AuthRateLimitMaxRequests,
		"auth_window_sec", store.AuthRateLimitWindowSec,
	)

	if !store.HasPermanentKeys() {
		logger.Warn("no_permanent_keys", "info", "PWA endpoints disabled")
	}

	// Start background worker
	go worker.StartBackgroundWorker()

	// Setup routes
	http.HandleFunc("/health", handler.HealthHandler)
	http.HandleFunc("/knock", handler.KnockHandler)
	http.HandleFunc("/allow", handler.AllowHandler)
	http.HandleFunc("/auth", handler.AuthHandler)
	http.HandleFunc("/pwa", handler.PWAHandler)
	http.HandleFunc("/pwa/status", handler.PWAStatusHandler)
	http.HandleFunc("/pwa/auth", handler.PWAAuthHandler)
	http.HandleFunc("/pwa/revoke", handler.PWARevokeHandler)
	http.HandleFunc("/pwa/manifest.json", handler.ManifestHandler)
	http.HandleFunc("/pwa/service-worker.js", handler.ServiceWorkerHandler)
	http.HandleFunc("/pwa/pwa-icon.svg", handler.PwaIconHandler)

	// Start server
	logger.Info("server_listening", "port", store.ServerPort)
	if err := http.ListenAndServe(":"+store.ServerPort, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
