package state

import (
	"fmt"
	"sort"
	"time"

	"ttl-allow-service/src/internal/config"
)

type TTLOption struct {
	Value    string
	Label    string
	Duration time.Duration
}

func GetTTLOptions() []TTLOption {
	var options []TTLOption

	smallOptions := []time.Duration{
		5 * time.Minute,
		10 * time.Minute,
		20 * time.Minute,
		40 * time.Minute,
		1 * time.Hour,
		2 * time.Hour,
		4 * time.Hour,
		8 * time.Hour,
		12 * time.Hour,
		24 * time.Hour,
		48 * time.Hour,
	}

	maxTTL := config.Get().TTL.MaxTTL
	for _, d := range smallOptions {
		if d <= maxTTL {
			options = append(options, TTLOption{
				Value:    formatTTL(d),
				Label:    formatTTL(d),
				Duration: d,
			})
		}
	}

	sort.Slice(options, func(i, j int) bool {
		return options[i].Duration < options[j].Duration
	})

	return options
}

func formatTTL(d time.Duration) string {
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}
