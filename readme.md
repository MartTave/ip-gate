# TTL IP Allow Service

A lightweight Go service for managing temporary IP-based access control, designed to work with Caddy's `auth_request` module. Provides a simple knock endpoint for clients, an admin interface for approving requests with configurable TTL, and an auth endpoint for Caddy to query access decisions.

## Concept

This service implements a "knock-to-request" pattern:

1. **Client requests access** - Hits `/knock` endpoint (rate-limited)
2. **Request appears in admin panel** - Visible at `/allow` interface
3. **Admin approves** - Selects TTL duration, IP gets added to allowlist
4. **Caddy queries auth endpoint** - `/auth` returns 200/403 based on IP allow status
5. **Auto-expiry** - Per-IP timers remove entries when TTL expires

All state is in-memory; restarts clear everything (fail-safe deny-by-default).

## Configuration File

The service can be configured via a YAML file, environment variables, or both. Environment variables override corresponding YAML values.

The config file is located using the following order (first match wins):

1. `--config <path>` CLI flag
2. `CONFIG_FILE` environment variable
3. `config.yaml` in the current working directory

### Example

```yaml
# See example/config.yaml for a complete reference
server:
  port: 8080

rate_limiting:
  knock_window_sec: 60
  knock_max_requests: 20
  auth_window_sec: 60
  auth_max_requests: 1000

permanent_keys:
  entries:
    - key: "your-key-here"
      name: "office-vpn"
```

### Docker

Mount your config file into the container:

```bash
docker run -p 8080:8080 \
  -v ./config.yaml:/app/config.yaml \
  ttl-allow-service
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MAX_TTL` | Maximum allowed TTL for approvals (generates dropdown options) | `48h` |
| `REQUEST_TTL_MINUTES` | How long knock requests stay pending | `5` |
| `RATE_LIMIT_WINDOW_SEC` | Rate limit window for `/knock` and PWA endpoints | `60` |
| `RATE_LIMIT_MAX_REQUESTS` | Max requests per window per IP for `/knock` and PWA | `20` |
| `AUTH_RATE_LIMIT_WINDOW_SEC` | Rate limit window for `/auth` | `60` |
| `AUTH_RATE_LIMIT_MAX_REQUESTS` | Max requests per window per IP for `/auth` | `1000` |
| `PORT` | HTTP server port | `8080` |
| `WORKER_INTERVAL_MINUTES` | Background cleanup worker interval | `5` |
| `PERMANENT_KEYS` | Comma-separated `key:name` pairs for key-based auth | (empty) |
| `PERMANENT_KEY_AUTH_TTL` | TTL for key-authenticated approvals | `4h` |
| `PERMANENT_KEY_MAX_IPS` | Max IPs allowed per permanent key (0=unlimited) | `1` |
| `LOG_FILE` | Path to log file (empty = stdout only) | (empty) |
| `LOG_MAX_SIZE_MB` | Max MB per log file before rotation | `10` |
| `LOG_MAX_AGE_DAYS` | Delete rotated logs older than N days | `7` |
| `LOG_MAX_FILES` | Max rotated log files to keep | `5` |

### TTL Options

The service dynamically generates TTL options based on `MAX_TTL`:
- Options: 5m, 10m, 20m, 40m, 1h, 2h, 4h, 8h, 12h, 24h, 48h
- Options exceeding `MAX_TTL` are filtered out
- Default `MAX_TTL=48h` shows all 11 options

## Endpoints

### `GET /health`
Health check endpoint. Returns HTTP 200.

```bash
curl http://localhost:8080/health
```

### `GET /knock`
Request temporary access. Extracts client IP, applies rate limiting.

**Responses:**
- `200 already allowed` - IP is already approved
- `200 request received` - Knock request created
- `200 already requested` - Pending request exists
- `429 Too Many Requests` - Rate limit exceeded

```bash
curl http://localhost:8080/knock
```

### `GET /allow`
Admin panel - displays pending requests and approved IPs.

- **Browser:** Returns HTML GUI with AJAX-based actions
- **API:** Returns JSON when `Accept: application/json` header present

```bash
# GUI
curl http://localhost:8080/allow

# JSON API
curl -H "Accept: application/json" http://localhost:8080/allow
```

### `POST /allow`
Approve, deny, or revoke IPs (JSON or form-encoded).

**Approve IP:**
```bash
curl -X POST http://localhost:8080/allow \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4","action":"allow","ttl":"1h"}'
```

**Deny request:**
```bash
curl -X POST http://localhost:8080/allow \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4","action":"deny"}'
```

**Revoke approval:**
```bash
curl -X POST http://localhost:8080/allow \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4","action":"revoke"}'
```

### `GET /auth`
Auth endpoint for Caddy. Returns 200 if IP is allowed, 403 otherwise. Rate-limited separately with a generous threshold (1000 req/60s by default).

```bash
curl http://localhost:8080/auth
```

### `POST /pwa/status`
Check authorization status for an IP using a permanent key.

**Parameters (form-encoded):**
- `key` - The permanent key

**Responses:**
- `200` with JSON containing `authorized`, `key_valid`, `key_name`, `expires_at`

### `POST /pwa/auth`
Authorize the requesting IP using a permanent key.

**Parameters (form-encoded):**
- `key` - The permanent key

**Features:**
- Rate limited
- IP rotation: When `PERMANENT_KEY_MAX_IPS` is reached, oldest approved IP is revoked

**Responses:**
- `200` with JSON: `status: "now_authorized"`, `key_name`, `expires_at`
- `401` Invalid key
- `429` Rate limit exceeded

```bash
curl -X POST http://localhost:8080/pwa/auth -d "key=abc123"
```

### `POST /pwa/revoke`
Remove authorization for the requesting IP using a permanent key.

**Parameters (form-encoded):**
- `key` - The permanent key

**Admin UI displays:**
- **Approved by**: "Manual" or "Automatic (key-name)"
- **Approved at**: Timestamp when approved
- **Last seen**: Last time `/auth` was accessed from this IP

## Caddy Integration

Use Caddy's `auth_request` module to protect routes:

```caddy
example.com {
    # Protect everything except the knock endpoint
    @protected not path /knock
    auth_request @protected /auth {
        uri http://localhost:8080/auth
        copy_headers X-Forwarded-For
    }

    # Public knock endpoint
    handle_path /knock {
        reverse_proxy localhost:8080
    }

    # Your protected application
    reverse_proxy localhost:3000
}

# Admin panel (protect with additional auth like Authelia)
admin.example.com {
    # External authentication (recommended)
    forward_auth authelia:9091 {
        uri /api/verify?rd=https://login.example.com/
        copy_headers Remote-User Remote-Groups Remote-Name Remote-Email
    }

    reverse_proxy localhost:8080
}
```

### How it works:
1. Client requests `example.com/protected-page`
2. Caddy forwards client IP to `/auth` endpoint
3. Service checks if IP is in approved list
4. Returns 200 (allow) or 403 (deny)
5. Caddy grants or denies access based on response

## Building and Running

### Build from source:
```bash
cd src/cmd/server
go build -o ../../ttl-allow-service .
./ttl-allow-service
```

### Docker:
```bash
docker build -t ttl-allow-service .
docker run -p 8080:8080 -e MAX_TTL=24h ttl-allow-service
```

## Logging

The service uses structured JSON logging via Go's `log/slog`. Each log line is a JSON object written to stdout and optionally to a rotating file.

### Log Format

```json
{"time":"2026-05-15T12:34:56Z","level":"INFO","msg":"ip_knocked","ip":"10.0.0.1"}
{"time":"2026-05-15T12:34:57Z","level":"WARN","msg":"ip_rate_limited","ip":"10.0.0.1","path":"/knock"}
{"time":"2026-05-15T12:35:00Z","level":"INFO","msg":"ip_allowed","target_ip":"10.0.0.1","admin_ip":"192.168.1.100","ttl":"1h"}
{"time":"2026-05-15T12:35:01Z","level":"INFO","msg":"ip_allowed_by_key","target_ip":"10.0.0.2","key_name":"office-vpn"}
```

### Security Events Logged

| Event | Level | When |
|---|---|---|
| `ip_rate_limited` | WARN | An IP exceeded the rate limit on any endpoint |
| `ip_knocked` | INFO | A new knock request was created |
| `ip_allowed` | INFO | An admin approved an IP via `/allow` |
| `ip_allowed_by_key` | INFO | An IP was authorized via a permanent key |

### Log Rotation

When `LOG_FILE` is set, the service rotates logs automatically:
1. The active file grows until it reaches `LOG_MAX_SIZE_MB` (default 10MB)
2. It's then renamed with a timestamp suffix (e.g., `app.log.20260515-120000`)
3. A fresh file is created
4. Rotated files older than `LOG_MAX_AGE_DAYS` (default 7) are deleted
5. At most `LOG_MAX_FILES` (default 5) rotated files are kept

Maximum disk usage: 1 active × 10MB + 5 rotated × 10MB = ~60MB.

## Security Considerations

- **`/allow` endpoint** should be protected by external authentication (Authelia, OAuth, etc.) via Caddy
- **`/knock`** is public but rate-limited
- **`/auth`** is for internal Caddy communication; rate-limited generously (1000 req/60s by default)
- All state is in-memory; **restart = deny all** (fail-safe design)
- No persistence by design - ephemeral access control
