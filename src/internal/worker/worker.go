package worker

import (
	"time"

	"ttl-allow-service/src/internal/logger"
	"ttl-allow-service/src/internal/state"
)

// StartBackgroundWorker starts the periodic cleanup (safety net)
func StartBackgroundWorker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	logger.Info("background_worker_started", "interval", interval.String())
	for range ticker.C {
		state.CleanupExpired()
	}
}
