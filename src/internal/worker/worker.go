package worker

import (
	"log"
	"time"

	"ttl-allow-service/src/internal/store"
)

// StartBackgroundWorker starts the periodic cleanup
func StartBackgroundWorker() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	log.Println("Background worker started (60s interval)")
	for range ticker.C {
		store.CleanupExpired()
	}
}
