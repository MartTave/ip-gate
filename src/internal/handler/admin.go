package handler

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"ttl-allow-service/src/internal/assets"
	"ttl-allow-service/src/internal/logger"
	"ttl-allow-service/src/internal/state"
)

var guiTemplate = template.Must(template.New("gui").Parse(assets.AdminTemplate))

type guiIP struct {
	IP         string
	RequestedAt string
	ExpiresAt  string
	TimeLeft   string
	ApprovedBy string
	ApprovedAt string
	LastSeen   string
}

func AllowHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleAllowGet(w, r)
	case http.MethodPost:
		handleAllowPost(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleAllowGet(w http.ResponseWriter, r *http.Request) {
	accept := r.Header.Get("Accept")

	if strings.Contains(accept, "text/html") {
		renderGUI(w, r)
		return
	}

	pending := state.GetPendingRequests()
	approved := state.GetApprovedIPs()

	response := map[string]interface{}{
		"pending":  pending,
		"approved": approved,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleAllowPost(w http.ResponseWriter, r *http.Request) {
	var req state.AllowRequest

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
	} else {
		if !requireParseForm(r, w) {
			return
		}
		req.IP = r.FormValue("ip")
		req.Action = r.FormValue("action")
		req.TTL = r.FormValue("ttl")
	}

	if req.IP == "" || req.Action == "" {
		http.Error(w, "Missing ip or action", http.StatusBadRequest)
		return
	}

	switch req.Action {
	case "deny":
		err := state.DenyIP(req.IP)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "denied")

	case "allow":
		if req.TTL == "" {
			http.Error(w, "TTL required for allow action", http.StatusBadRequest)
			return
		}
		err := state.ApproveIP(req.IP, req.TTL)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		adminIP := ExtractClientIPFromHeaders(r)
		logger.Info("ip_allowed", "target_ip", req.IP, "admin_ip", adminIP, "ttl", req.TTL)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "allowed")

	case "revoke":
		err := state.RevokeIP(req.IP)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "revoked")

	default:
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}
}

func renderGUI(w http.ResponseWriter, r *http.Request) {
	pendingData := state.GetPendingRequests()
	approvedData := state.GetApprovedIPs()

	now := time.Now()

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

	var approved []guiIP
	for _, a := range approvedData {
		ip := guiIP{
			IP:         a["ip"].(string),
			ExpiresAt:  a["expires_at"].(time.Time).Format("2006-01-02 15:04:05"),
			ApprovedBy: a["approved_by"].(string),
			ApprovedAt: a["approved_at"].(time.Time).Format("2006-01-02 15:04:05"),
		}
		if ls, ok := a["last_seen"].(time.Time); ok && !ls.IsZero() {
			ip.LastSeen = ls.Format("2006-01-02 15:04:05")
		}
		expiresAt := a["expires_at"].(time.Time)
		diff := expiresAt.Sub(now)
		ip.TimeLeft = formatDuration(diff)
		approved = append(approved, ip)
	}

	sort.Slice(pending, func(i, j int) bool { return pending[i].IP < pending[j].IP })
	sort.Slice(approved, func(i, j int) bool { return approved[i].IP < approved[j].IP })

	ttlOptions := state.GetTTLOptions()

	data := map[string]interface{}{
		"Pending":    pending,
		"Approved":   approved,
		"TTLOptions": ttlOptions,
		"ServerTime": now.Format("2006-01-02 15:04:05"),
	}

	w.Header().Set("Content-Type", "text/html")
	guiTemplate.Execute(w, data)
}

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
