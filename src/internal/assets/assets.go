package assets

import _ "embed"

//go:embed templates/pwa.html
var PwaTemplate string

//go:embed templates/admin.html
var AdminTemplate string

//go:embed static/no-keys.html
var NoKeysHTML string

//go:embed static/manifest.json
var ManifestJSON string

//go:embed static/service-worker.js
var ServiceWorkerJS string

//go:embed static/pwa-icon.svg
var PwaIconSVG string
