package gui

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"time"

	"ttl-allow-service/src/internal/assets"
	"ttl-allow-service/src/internal/store"
)

var guiTemplate = template.Must(template.New("gui").Parse(assets.AdminTemplate))

// RenderGUI renders the responsive admin GUI
func RenderGUI(w http.ResponseWriter, r *http.Request) {
	pendingData := store.GetPendingRequests()
	approvedData := store.GetApprovedIPs()

	// Convert to GUI-friendly format
type guiIP struct {
	IP           string
	RequestedAt  string
	ExpiresAt    string
	TimeLeft     string
	ApprovedBy   string
	ApprovedAt   string
	LastSeen     string
}

	now := time.Now()

	// Process pending
	var pending []guiIP
	for _, p := range pendingData {
		ip := guiIP{
			IP:          p["ip"].(string),
			RequestedAt: p["requested_at"].(time.Time).Format("2006-01-02 15:04:05"),
			ExpiresAt:   p["expires_at"].(time.Time).Format("2006-01-02 15:04:05"),
		}
		expiresAt := p["expires_at"].(time.Time)
		diff := expiresAt.Sub(now)
		ip.TimeLeft = formatDuration(diff)
		pending = append(pending, ip)
	}

	// Process approved
	var approved []guiIP
	for _, a := range approvedData {
		ip := guiIP{
			IP:         a["ip"].(string),
			ExpiresAt:  a["expires_at"].(time.Time).Format("2006-01-02 15:04:05"),
			ApprovedBy:  a["approved_by"].(string),
			ApprovedAt:  a["approved_at"].(time.Time).Format("2006-01-02 15:04:05"),
		}
		if ls, ok := a["last_seen"].(time.Time); ok && !ls.IsZero() {
			ip.LastSeen = ls.Format("2006-01-02 15:04:05")
		}
		expiresAt := a["expires_at"].(time.Time)
		diff := expiresAt.Sub(now)
		ip.TimeLeft = formatDuration(diff)
		approved = append(approved, ip)
	}

	// Sort by IP
	sort.Slice(pending, func(i, j int) bool { return pending[i].IP < pending[j].IP })
	sort.Slice(approved, func(i, j int) bool { return approved[i].IP < approved[j].IP })

	// Get TTL options from store (already sorted by duration)
	ttlOptions := store.GetTTLOptions()

	data := map[string]interface{}{
		"Pending":    pending,
		"Approved":   approved,
		"TTLOptions": ttlOptions,
		"ServerTime": now.Format("2006-01-02 15:04:05"),
	}

	w.Header().Set("Content-Type", "text/html")
	guiTemplate.Execute(w, data)
}

// formatDuration formats a duration for display
func formatDuration(d time.Duration) string {
	if d < 0 {
		return "expired"
	}
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
