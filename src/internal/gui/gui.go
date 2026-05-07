package gui

import (
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"time"

	"ttl-allow-service/src/internal/store"
)

// GUITemplate is the responsive HTML template with inline CSS and JavaScript
const GUITemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TTL IP Allow - Admin</title>
    <style>
        * { box-sizing: border-box; margin:0; padding:0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; padding: 16px; }
        .container { max-width: 1200px; margin:0 auto; }
        h1 { font-size: 1.5rem; margin-bottom: 1rem; color: #2c3e50; }
        h2 { font-size: 1.2rem; margin: 1.5rem 0 0.75rem; color: #34495e; }
        .card { background: white; border-radius: 8px; padding: 16px; margin-bottom: 16px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .ip-item { border-bottom: 1px solid #eee; padding: 12px 0; transition: opacity 0.3s; }
        .ip-item:last-child { border-bottom: none; }
        .ip-address { font-family: monospace; font-size: 1.1rem; font-weight: bold; color: #2980b9; word-break: break-all; }
        .ip-meta { font-size: 0.85rem; color: #7f8c8d; margin: 4px 0; }
        .time-left { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        .time-left.ok { background: #d4edda; color: #155724; }
        .time-left.warn { background: #fff3cd; color: #856404; }
        .time-left.expired { background: #f8d7da; color: #721c24; }
        .actions { margin-top: 8px; display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
        .btn { display: inline-block; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9rem; text-decoration: none; min-height: 44px; min-width: 44px; display: inline-flex; align-items: center; justify-content: center; }
        .btn-approve { background: #27ae60; color: white; }
        .btn-approve:hover { background: #229954; }
        .btn-deny { background: #e74c3c; color: white; }
        .btn-deny:hover { background: #c0392b; }
        .btn-revoke { background: #e67e22; color: white; }
        .btn-revoke:hover { background: #d35400; }
        .btn-refresh { background: #3498db; color: white; margin-bottom: 16px; }
        .btn-refresh:hover { background: #2980b9; }
        select { padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 0.9rem; min-height: 44px; }
        .empty { color: #95a5a6; font-style: italic; padding: 16px 0; }
        .external-links { margin-top: 4px; font-size: 0.8rem; }
        .external-links a { color: #3498db; text-decoration: none; margin-right: 12px; }
        .external-links a:hover { text-decoration: underline; }
        .stats { background: #ecf0f1; padding: 8px 12px; border-radius: 4px; font-size: 0.85rem; margin-bottom: 16px; }
        .error-msg { color: #e74c3c; font-size: 0.85rem; margin-top: 8px; }
        
        /* Tablet and Desktop */
        @media (min-width: 768px) {
            body { padding: 24px; }
            h1 { font-size: 2rem; }
            h2 { font-size: 1.5rem; }
            .sections { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
            .card { padding: 24px; }
        }
        
        /* Desktop only */
        @media (min-width: 1024px) {
            .container { padding: 0 24px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>TTL IP Allow - Admin Panel</h1>
        
        <div class="stats">
            Pending: {{len .Pending}} | Approved: {{len .Approved}} | Server Time: {{.ServerTime}}
        </div>
        
        <a href="/allow" class="btn btn-refresh">Refresh</a>
        
        <div class="sections">
            <div>
                <h2>Pending Requests</h2>
                <div class="card">
                    {{if .Pending}}
                        {{range .Pending}}
                        <div class="ip-item" data-ip="{{.IP}}">
                            <div class="ip-address">{{.IP}}</div>
                            <div class="ip-meta">Requested: {{.RequestedAt}}</div>
                            <div class="ip-meta">Expires: {{.ExpiresAt}} ({{.TimeLeft}})</div>
                            <div class="external-links">
                                <a href="https://ipinfo.io/{{.IP}}" target="_blank">ipinfo.io</a>
                                <a href="https://www.abuseipdb.com/check/{{.IP}}" target="_blank">abuseipdb.com</a>
                                <a href="https://ip-api.com/#{{.IP}}" target="_blank">ip-api.com</a>
                            </div>
                            <form method="POST" action="/allow" class="actions" data-ip="{{.IP}}">
                                <input type="hidden" name="ip" value="{{.IP}}">
                                <input type="hidden" name="action" value="allow">
                                <select name="ttl" required>
                                    <option value="">Select TTL...</option>
                                    {{range $.TTLOptions}}
                                    <option value="{{.Value}}">{{.Label}}</option>
                                    {{end}}
                                </select>
                                <button type="submit" class="btn btn-approve">Approve</button>
                                <button type="submit" class="btn btn-deny" onclick="denyIP(event, this);">Deny</button>
                            </form>
                        </div>
                        {{end}}
                    {{else}}
                        <div class="empty">No pending requests</div>
                    {{end}}
                </div>
            </div>
            
            <div>
                <h2>Approved IPs</h2>
                <div class="card">
                    {{if .Approved}}
                        {{range .Approved}}
                        <div class="ip-item" data-ip="{{.IP}}">
                            <div class="ip-address">{{.IP}}</div>
                            <div class="ip-meta">Expires: {{.ExpiresAt}} ({{.TimeLeft}})</div>
                            <div class="ip-meta">Approved by: {{.ApprovedBy}}</div>
                            <div class="ip-meta">Approved at: {{.ApprovedAt}}</div>
                            {{if .LastSeen}}
                            <div class="ip-meta">Last seen: {{.LastSeen}}</div>
                            {{end}}
                            <div class="external-links">
                                <a href="https://ipinfo.io/{{.IP}}" target="_blank">ipinfo.io</a>
                                <a href="https://www.abuseipdb.com/check/{{.IP}}" target="_blank">abuseipdb.com</a>
                                <a href="https://ip-api.com/#{{.IP}}" target="_blank">ip-api.com</a>
                            </div>
                            <form method="POST" action="/allow" class="actions" data-ip="{{.IP}}">
                                <input type="hidden" name="ip" value="{{.IP}}">
                                <input type="hidden" name="action" value="revoke">
                                <button type="submit" class="btn btn-revoke">Revoke</button>
                            </form>
                        </div>
                        {{end}}
                    {{else}}
                        <div class="empty">No approved IPs</div>
                    {{end}}
                </div>
            </div>
        </div>
    </div>
    
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Intercept all form submissions
        document.querySelectorAll('.ip-item form').forEach(form => {
            form.addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const formData = new FormData(this);
                const action = formData.get('action');
                const ip = formData.get('ip');
                
                // Disable buttons during request
                const buttons = this.querySelectorAll('button');
                buttons.forEach(btn => btn.disabled = true);
                
                try {
                    const response = await fetch('/allow', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: new URLSearchParams(formData)
                    });
                    
                    if (response.ok) {
                        // Update UI after confirmation from server
                        updateUIAfterAction(action, ip, this);
                    } else {
                        const error = await response.text();
                        showError(this, error || 'Action failed');
                        // Re-enable buttons
                        buttons.forEach(btn => btn.disabled = false);
                    }
                } catch (err) {
                    showError(this, 'Network error: ' + err.message);
                    buttons.forEach(btn => btn.disabled = false);
                }
            });
        });
    });
    
    function denyIP(e, btn) {
        e.preventDefault();
        const form = btn.closest('form');
        form.elements['action'].value = 'deny';
        form.elements['ttl'].disabled = true;
        // Trigger form submission via requestSubmit (properly cancelable)
        form.requestSubmit();
    }
    
    function updateUIAfterAction(action, ip, form) {
        const ipItem = form.closest('.ip-item');
        
        if (action === 'deny' || action === 'revoke') {
            // Remove the IP item from the list with fade animation
            ipItem.style.opacity = '0';
            setTimeout(() => {
                ipItem.remove();
                updateStats();
            }, 300);
        } else if (action === 'allow') {
            // For approval, reload the page to show the IP in approved section
            setTimeout(() => location.reload(), 500);
        }
    }
    
    function showError(form, message) {
        // Remove existing error
        let errorDiv = form.querySelector('.error-msg');
        if (errorDiv) {
            errorDiv.remove();
        }
        
        errorDiv = document.createElement('div');
        errorDiv.className = 'error-msg';
        errorDiv.textContent = message;
        form.appendChild(errorDiv);
        
        // Auto-remove after 5 seconds
        setTimeout(() => errorDiv.remove(), 5000);
    }
    
    function updateStats() {
        // Simple reload to update stats (pending/approved counts)
        setTimeout(() => location.reload(), 500);
    }
    </script>
</body>
</html>`

var guiTemplate = template.Must(template.New("gui").Parse(GUITemplate))

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
