package pwa

import (
	"html/template"
	"net/http"

	"ttl-allow-service/src/internal/assets"
)

var pwaTemplate = template.Must(template.New("pwa").Parse(assets.PwaTemplate))

// RenderPWA renders the PWA status page
func RenderPWA(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	pwaTemplate.Execute(w, nil)
}
