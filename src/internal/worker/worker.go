package worker

import (
	"time"

	"ttl-allow-service/src/internal/logger"
	"ttl-allow-service/src/internal/store"
)

// StartBackgroundWorker starts the periodic cleanup (safety net)
func StartBackgroundWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	logger.Info("background_worker_started", "interval", "5m")
	for range ticker.C {
		store.CleanupExpired()
	}
}
