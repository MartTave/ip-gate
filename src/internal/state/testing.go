package state

import (
	"time"

	"ttl-allow-service/src/internal/config"
	"ttl-allow-service/src/internal/ratelimit"
)

func ResetTestState() {
	ips = make(map[string]*IP)
	keyIPs = make(map[string]map[string]bool)
	knockLimiter = ratelimit.New(time.Minute, 20)
	authLimiter = ratelimit.New(time.Minute, 1000)
	config.Set(config.LoadDefaults())
}

func SetTestConfig(keys []config.KeyEntry, maxIPs int) {
	cfg := config.LoadDefaults()
	cfg.Keys.Entries = keys
	if maxIPs >= 0 {
		cfg.Keys.MaxIPs = maxIPs
	}
	cfg.AfterLoad()
	config.Set(cfg)
}
