package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Port int `yaml:"port"`
}

type RateConfig struct {
	KnockWindowSec   int `yaml:"knock_window_sec"`
	KnockMaxRequests int `yaml:"knock_max_requests"`
	AuthWindowSec    int `yaml:"auth_window_sec"`
	AuthMaxRequests  int `yaml:"auth_max_requests"`
}

type TTLConfig struct {
	RequestTTLMinutes int           `yaml:"request_ttl_minutes"`
	MaxTTL            time.Duration `yaml:"max_ttl"`
}

type KeyEntry struct {
	Key  string `yaml:"key"`
	Name string `yaml:"name"`
}

type KeysConfig struct {
	Entries []KeyEntry     `yaml:"entries"`
	AuthTTL time.Duration  `yaml:"auth_ttl"`
	MaxIPs  int            `yaml:"max_ips"`
	keyMap  map[string]string
}

type LogConfig struct {
	FilePath   string `yaml:"file"`
	MaxSizeMB  int    `yaml:"max_size_mb"`
	MaxAgeDays int    `yaml:"max_age_days"`
	MaxFiles   int    `yaml:"max_files"`
}

type WorkerConfig struct {
	IntervalMinutes int `yaml:"interval_minutes"`
}

type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Rate    RateConfig    `yaml:"rate_limiting"`
	TTL     TTLConfig     `yaml:"ttl"`
	Keys    KeysConfig    `yaml:"permanent_keys"`
	Logging LogConfig     `yaml:"logging"`
	Worker  WorkerConfig  `yaml:"worker"`
}

var current atomic.Value

func Set(c *Config) {
	if c == nil {
		c = LoadDefaults()
	}
	current.Store(c)
}

func Get() *Config {
	c, _ := current.Load().(*Config)
	if c == nil {
		c = LoadDefaults()
		Set(c)
	}
	return c
}

func (c *Config) ServerPort() string {
	return strconv.Itoa(c.Server.Port)
}

func (c *Config) HasPermanentKeys() bool {
	return len(c.Keys.keyMap) > 0
}

func (c *Config) LookupKey(key string) (string, bool) {
	name, ok := c.Keys.keyMap[key]
	return name, ok
}

func Load(path string) (*Config, error) {
	cfg := &Config{}

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
	} else {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
	}

	ApplyDefaults(cfg)
	ApplyEnvOverrides(cfg)

	if err := Validate(cfg); err != nil {
		return nil, err
	}

	cfg.AfterLoad()

	return cfg, nil
}

func LoadDefaults() *Config {
	return &Config{
		Server: ServerConfig{
			Port: 8080,
		},
		Rate: RateConfig{
			KnockWindowSec:   60,
			KnockMaxRequests: 20,
			AuthWindowSec:    60,
			AuthMaxRequests:  1000,
		},
		TTL: TTLConfig{
			RequestTTLMinutes: 5,
			MaxTTL:            48 * time.Hour,
		},
		Keys: KeysConfig{
			AuthTTL: 4 * time.Hour,
			MaxIPs:  1,
		},
		Logging: LogConfig{
			MaxSizeMB:  10,
			MaxAgeDays: 7,
			MaxFiles:   5,
		},
		Worker: WorkerConfig{
			IntervalMinutes: 5,
		},
	}
}

func ApplyDefaults(cfg *Config) {
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8080
	}
	if cfg.Rate.KnockWindowSec == 0 {
		cfg.Rate.KnockWindowSec = 60
	}
	if cfg.Rate.KnockMaxRequests == 0 {
		cfg.Rate.KnockMaxRequests = 20
	}
	if cfg.Rate.AuthWindowSec == 0 {
		cfg.Rate.AuthWindowSec = 60
	}
	if cfg.Rate.AuthMaxRequests == 0 {
		cfg.Rate.AuthMaxRequests = 1000
	}
	if cfg.TTL.RequestTTLMinutes == 0 {
		cfg.TTL.RequestTTLMinutes = 5
	}
	if cfg.TTL.MaxTTL == 0 {
		cfg.TTL.MaxTTL = 48 * time.Hour
	}
	if cfg.Keys.AuthTTL == 0 {
		cfg.Keys.AuthTTL = 4 * time.Hour
	}
	if cfg.Keys.MaxIPs == 0 {
		cfg.Keys.MaxIPs = 1
	}
	if cfg.Logging.MaxSizeMB == 0 {
		cfg.Logging.MaxSizeMB = 10
	}
	if cfg.Logging.MaxAgeDays == 0 {
		cfg.Logging.MaxAgeDays = 7
	}
	if cfg.Logging.MaxFiles == 0 {
		cfg.Logging.MaxFiles = 5
	}
	if cfg.Worker.IntervalMinutes == 0 {
		cfg.Worker.IntervalMinutes = 5
	}
}

func ApplyEnvOverrides(cfg *Config) {
	if v := os.Getenv("PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = n
		}
	}

	if v := os.Getenv("REQUEST_TTL_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.TTL.RequestTTLMinutes = n
		}
	}

	if v := os.Getenv("RATE_LIMIT_WINDOW_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Rate.KnockWindowSec = n
		}
	}
	if v := os.Getenv("RATE_LIMIT_MAX_REQUESTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Rate.KnockMaxRequests = n
		}
	}
	if v := os.Getenv("AUTH_RATE_LIMIT_WINDOW_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Rate.AuthWindowSec = n
		}
	}
	if v := os.Getenv("AUTH_RATE_LIMIT_MAX_REQUESTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Rate.AuthMaxRequests = n
		}
	}

	if v := os.Getenv("MAX_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.TTL.MaxTTL = d
		}
	}

	if v := os.Getenv("PERMANENT_KEY_AUTH_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Keys.AuthTTL = d
		}
	}
	if v := os.Getenv("PERMANENT_KEY_MAX_IPS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Keys.MaxIPs = n
		}
	}

	if v := os.Getenv("PERMANENT_KEYS"); v != "" {
		pairs := strings.Split(v, ",")
		var entries []KeyEntry
		for _, pair := range pairs {
			parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
			if len(parts) == 2 {
				entries = append(entries, KeyEntry{
					Key:  strings.TrimSpace(parts[0]),
					Name: strings.TrimSpace(parts[1]),
				})
			}
		}
		cfg.Keys.Entries = entries
	}

	if v := os.Getenv("LOG_FILE"); v != "" {
		cfg.Logging.FilePath = v
	}
	if v := os.Getenv("LOG_MAX_SIZE_MB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Logging.MaxSizeMB = n
		}
	}
	if v := os.Getenv("LOG_MAX_AGE_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Logging.MaxAgeDays = n
		}
	}
	if v := os.Getenv("LOG_MAX_FILES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Logging.MaxFiles = n
		}
	}

	if v := os.Getenv("WORKER_INTERVAL_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Worker.IntervalMinutes = n
		}
	}
}

func Validate(cfg *Config) error {
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		return fmt.Errorf("server.port must be 1-65535, got %d", cfg.Server.Port)
	}
	if cfg.Rate.KnockWindowSec <= 0 {
		return fmt.Errorf("rate_limiting.knock_window_sec must be > 0")
	}
	if cfg.Rate.KnockMaxRequests <= 0 {
		return fmt.Errorf("rate_limiting.knock_max_requests must be > 0")
	}
	if cfg.Rate.AuthWindowSec <= 0 {
		return fmt.Errorf("rate_limiting.auth_window_sec must be > 0")
	}
	if cfg.Rate.AuthMaxRequests <= 0 {
		return fmt.Errorf("rate_limiting.auth_max_requests must be > 0")
	}
	if cfg.TTL.RequestTTLMinutes <= 0 {
		return fmt.Errorf("ttl.request_ttl_minutes must be > 0")
	}
	if cfg.TTL.MaxTTL <= 0 {
		return fmt.Errorf("ttl.max_ttl must be > 0")
	}
	if cfg.Keys.AuthTTL <= 0 {
		return fmt.Errorf("permanent_keys.auth_ttl must be > 0")
	}
	if cfg.Keys.MaxIPs < 0 {
		return fmt.Errorf("permanent_keys.max_ips must be >= 0")
	}
	if cfg.Logging.MaxSizeMB <= 0 {
		return fmt.Errorf("logging.max_size_mb must be > 0")
	}
	if cfg.Logging.MaxAgeDays <= 0 {
		return fmt.Errorf("logging.max_age_days must be > 0")
	}
	if cfg.Logging.MaxFiles <= 0 {
		return fmt.Errorf("logging.max_files must be > 0")
	}
	if cfg.Worker.IntervalMinutes <= 0 {
		return fmt.Errorf("worker.interval_minutes must be > 0")
	}

	seen := make(map[string]bool)
	seenNames := make(map[string]bool)
	for _, e := range cfg.Keys.Entries {
		if e.Key == "" {
			return fmt.Errorf("permanent_keys.entries: key must not be empty")
		}
		if e.Name == "" {
			return fmt.Errorf("permanent_keys.entries: name must not be empty")
		}
		if seen[e.Key] {
			return fmt.Errorf("permanent_keys.entries: duplicate key: %s", e.Key)
		}
		if seenNames[e.Name] {
			return fmt.Errorf("permanent_keys.entries: duplicate name: %s", e.Name)
		}
		seen[e.Key] = true
		seenNames[e.Name] = true
	}

	return nil
}

func (c *Config) AfterLoad() {
	c.Keys.keyMap = make(map[string]string, len(c.Keys.Entries))
	for _, e := range c.Keys.Entries {
		c.Keys.keyMap[e.Key] = e.Name
	}
}
