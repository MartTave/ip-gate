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

	// Start background worker
	go worker.StartBackgroundWorker()

	// Setup routes
	http.HandleFunc("/health", handler.HealthHandler)
	http.HandleFunc("/knock", handler.KnockHandler)
	http.HandleFunc("/key-auth", handler.KeyAuthHandler)
	http.HandleFunc("/allow", handler.AllowHandler)
	http.HandleFunc("/auth", handler.AuthHandler)

	// Start server
	log.Printf("Server listening on :%s", store.ServerPort)
	if err := http.ListenAndServe(":"+store.ServerPort, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
