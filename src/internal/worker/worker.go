package worker

import (
	"log"
	"time"

	"ttl-allow-service/src/internal/store"
)

// StartBackgroundWorker starts the periodic cleanup (safety net)
func StartBackgroundWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	log.Println("Background worker started (safety net, 5min interval)")
	for range ticker.C {
		store.CleanupExpired()
	}
}
