# TTL IP Allow Service (Go + Caddy Integration) — Implementation Plan

## 1. Goal

Build a minimal Go service that:

- Keeps an in-memory list of IP access requests
- Provides TTL-based "knock" requests
- Allows admin approval with selectable TTL durations
- Provides `/auth` endpoint for Caddy to check IP allow status
- Resets all state on startup (fail-safe deny-by-default)
- Includes rate limiting for `/knock`
- Uses minimal/no external libraries (prefer standard library only)

---

## 2. High-Level Architecture

```

Client (hotel / device)
|
v
/knock endpoint
|
In-memory request store
|
Admin panel (/allow)
|
Select TTL + approve
|
Approved IPs store  <------ /auth endpoint (queried by Caddy)
                                      |
                                      v
                                  Caddy enforces access
```

---

## 3. Key Design Principles

- Fail-safe: default = NO IP allowed
- No persistence (memory only)
- Restart wipes all state
- TTL-based approval system
- Simple HTTP JSON API
- Minimal dependencies
- External auth handled by reverse proxy (e.g. Authelia)

---

## 4. Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `REQUEST_TTL_MINUTES` | Default knock request TTL | 5 |
| `RATE_LIMIT_WINDOW_SEC` | Rate limit window | 60 |
| `RATE_LIMIT_MAX_REQUESTS` | Max knock requests per window | 3 |
| `PORT` | HTTP server port | 8080 |

---

## 5. Data Structures

### 5.1 Knock Request

```go
type KnockRequest struct {
    IP          string
    RequestedAt time.Time
    ExpiresAt   time.Time
}
````

---

### 5.2 Approved IP

```go
type ApprovedIP struct {
    IP        string
    ExpiresAt time.Time
}
```

---

### 5.3 Global State

Located in `src/internal/store/store.go`:

```go
var (
    knockRequests = make(map[string]KnockRequest)
    approvedIPs   = make(map[string]ApprovedIP)
    rateLimiter   = make(map[string][]time.Time)
    mu            sync.Mutex
)
```

---

## 6. Startup Behavior

On startup:

1. Initialize in-memory state
2. Clear all stored data (deny-by-default safety)
3. Start background cleanup goroutine:
   * remove expired knock requests
   * remove expired approvals

---

## 7. Routes

---

## 7.1 `/knock` (public)

### Purpose

Request temporary access.

### Behavior

* Extract client IP
* Apply rate limiting
* If IP already has pending request → return `"already requested"`
* Otherwise:

  * create KnockRequest
  * store in memory
* Return simple response:

  * `"request received"`

---

## 7.2 `/allow` (admin panel)

### Purpose

Review and manage IP requests + approvals.

---

### GET `/allow`

Returns:

```json
{
  "pending": [
    {
      "ip": "1.2.3.4",
      "requested_at": "...",
      "expires_at": "..."
    }
  ],
  "approved": [
    {
      "ip": "1.2.3.4",
      "expires_at": "..."
    }
  ]
}
```

Optional enhancement:

* include external IP lookup links:

  * ipinfo.io
  * abuseipdb.com
  * ip-api.com

---

### POST `/allow`

#### Action: approve IP with TTL

```json
{
  "ip": "1.2.3.4",
  "action": "allow",
  "ttl": "30m"
}
```

#### Action: deny IP

```json
{
  "ip": "1.2.3.4",
  "action": "deny"
}
```

---

## 8. TTL Options (IMPORTANT UPDATE)

Admin can choose from predefined TTL values:

### Allowed TTL values

| Label | Duration   |
| ----- | ---------- |
| 5m    | 5 minutes  |
| 30m   | 30 minutes |
| 1h    | 1 hour     |
| 2h    | 2 hours    |
| 5h    | 5 hours    |
| 12h   | 12 hours   |
| 24h   | 24 hours   |

---

### Implementation rule

* validate TTL against allowed list
* reject invalid values
* convert to `time.Duration`

Example:

```go
var allowedTTLs = map[string]time.Duration{
    "5m":  5 * time.Minute,
    "30m": 30 * time.Minute,
    "1h":  1 * time.Hour,
    "2h":  2 * time.Hour,
    "5h":  5 * time.Hour,
    "12h": 12 * time.Hour,
    "24h": 24 * time.Hour,
}
```

---

## 9. Rate Limiting (/knock only)

* per IP
* sliding window using timestamps
* configurable:

| Setting      | Default |
| ------------ | ------- |
| window       | 60s     |
| max requests | 3       |

If exceeded:

* return `429 Too Many Requests`

---

## 10. Caddy Integration Strategy

### Auth Endpoint Approach

* Caddy uses `auth_request` module to query `/auth` endpoint
* `/auth` checks in-memory approved IPs and returns:
  * `200 OK` - IP is allowed
  * `403 Forbidden` - IP is not allowed

### Caddy Configuration Example

```
# In Caddyfile
example.com {
    auth_request /auth {
        uri http://localhost:8080/auth
        copy_headers X-Forwarded-For
    }
    # Your protected app
    reverse_proxy localhost:3000
}
```

### Startup safety

* No IPs approved on startup = all requests denied by default

---

## 11. Background Worker

Runs every 60 seconds:

* remove expired knock requests
* remove expired approved IPs

---

## 12. Security Model

* `/allow` protected externally (Authelia / reverse proxy)
* `/knock` public but rate-limited
* `/auth` endpoint designed for internal Caddy communication

---

## 13. Docker Design

### Requirements

* single static binary
* minimal image (scratch or alpine)
* no runtime dependencies

---

## 14. Failure Model (CRITICAL)

* all state is in-memory
* restart = wipe everything
* Caddy is reset to empty allowlist on startup
* system defaults to DENY ALL

---

## 15. MVP Implementation Order

1. HTTP server skeleton
2. in-memory storage
3. `/knock` endpoint + rate limiting
4. `/allow` endpoint
5. TTL system
6. approved IP manager
7. Caddy sync layer
8. Dockerization

---

## 16. Future Extensions (optional)

* Web UI for admin panel
* persistent storage (SQLite/Redis)
* audit logs
* per-service IP policies
* IP geolocation enrichment
