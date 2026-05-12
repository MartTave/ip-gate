package main

import (
	"log"
	"net/http"

	"ttl-allow-service/src/internal/handler"
	"ttl-allow-service/src/internal/store"
	"ttl-allow-service/src/internal/worker"
)

func main() {
	// Load environment variables
	store.LoadEnv()

	// Startup
	log.Println("Starting TTL IP Allow Service...")
	log.Printf("Rate limit: %d requests per %d seconds", store.RateLimitMaxRequests, store.RateLimitWindowSec)

	if !store.HasPermanentKeys() {
		log.Println("WARNING: No permanent keys loaded — PWA endpoints (/pwa, /pwa/status, /pwa/auth, /pwa/revoke) are disabled")
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
	http.HandleFunc("/manifest.json", handler.ManifestHandler)
	http.HandleFunc("/service-worker.js", handler.ServiceWorkerHandler)
	http.HandleFunc("/pwa-icon.svg", handler.PwaIconHandler)

	// Start server
	log.Printf("Server listening on :%s", store.ServerPort)
	if err := http.ListenAndServe(":"+store.ServerPort, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
