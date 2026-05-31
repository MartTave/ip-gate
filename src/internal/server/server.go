package server

import (
	"log"
	"net/http"
	"os"
	"time"

	"ttl-allow-service/src/internal/config"
	"ttl-allow-service/src/internal/handler"
	"ttl-allow-service/src/internal/logger"
	"ttl-allow-service/src/internal/state"
	"ttl-allow-service/src/internal/worker"
)

func NewHandler(cfg *config.Config) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handler.HealthHandler)
	mux.HandleFunc("/knock", handler.KnockHandler)
	mux.HandleFunc("/allow", handler.AllowHandler)
	mux.HandleFunc("/auth", handler.AuthHandler)
	mux.HandleFunc("/pwa", handler.PWAHandler)
	mux.HandleFunc("/pwa/status", handler.PWAStatusHandler)
	mux.HandleFunc("/pwa/auth", handler.PWAAuthHandler)
	mux.HandleFunc("/pwa/revoke", handler.PWARevokeHandler)
	mux.HandleFunc("/pwa/manifest.json", handler.ManifestHandler)
	mux.HandleFunc("/pwa/service-worker.js", handler.ServiceWorkerHandler)
	mux.HandleFunc("/pwa/pwa-icon.svg", handler.PwaIconHandler)
	return mux
}

func Start(configPath string) {
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	logger.Info("config_loaded", "path", configPath)
	state.Init(cfg)

	logger.Info("starting_server")
	logger.Info("rate_limit_config",
		"knock_max", cfg.Rate.KnockMaxRequests,
		"knock_window_sec", cfg.Rate.KnockWindowSec,
		"auth_max", cfg.Rate.AuthMaxRequests,
		"auth_window_sec", cfg.Rate.AuthWindowSec,
	)

	if !state.HasPermanentKeys() {
		logger.Warn("no_permanent_keys", "info", "PWA endpoints disabled")
	}

	go worker.StartBackgroundWorker(time.Duration(cfg.Worker.IntervalMinutes) * time.Minute)
	go watchConfig(configPath)

	mux := NewHandler(cfg)
	port := cfg.ServerPort()
	logger.Info("server_listening", "port", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func watchConfig(path string) {
	var lastModTime time.Time
	if info, err := os.Stat(path); err == nil {
		lastModTime = info.ModTime()
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		mt := info.ModTime()
		if mt.After(lastModTime) {
			lastModTime = mt
			newCfg, err := config.Load(path)
			if err != nil {
				logger.Error("config_reload_failed", "error", err)
				continue
			}
			config.Set(newCfg)
			logger.Info("config_reloaded")
		}
	}
}
