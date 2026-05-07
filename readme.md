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

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MAX_TTL` | Maximum allowed TTL for approvals (generates dropdown options) | `48h` |
| `REQUEST_TTL_MINUTES` | How long knock requests stay pending | `5` |
| `RATE_LIMIT_WINDOW_SEC` | Rate limit window for `/knock` | `60` |
| `RATE_LIMIT_MAX_REQUESTS` | Max knock requests per window per IP | `3` |
| `PORT` | HTTP server port | `8080` |
| `WORKER_INTERVAL_MINUTES` | Background cleanup worker interval | `5` |
| `PERMANENT_KEYS` | Comma-separated `key:name` pairs for key-based auth | (empty) |
| `PERMANENT_KEY_AUTH_TTL` | TTL for key-authenticated approvals | `4h` |
| `PERMANENT_KEY_MAX_IPS` | Max IPs allowed per permanent key (0=unlimited) | `1` |

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
Auth endpoint for Caddy. Returns 200 if IP is allowed, 403 otherwise.

```bash
curl http://localhost:8080/auth
```

### `GET /key-auth?key=<key>`
Permanent key authentication endpoint. Validates the key against configured `PERMANENT_KEYS`, and if valid, approves the requesting IP for a configurable duration (`PERMANENT_KEY_AUTH_TTL`).

**Features:**
- Rate limiting (same as `/knock` endpoint)
- IP rotation: When `PERMANENT_KEY_MAX_IPS` is reached, oldest approved IP is revoked
- Warning logged if key is shorter than 64 characters

**Parameters:**
- `key` - The permanent key to authenticate with

**Responses:**
- `200 allowed via key: <name>` - IP approved successfully
- `200 already allowed` - IP was already approved
- `401 Invalid key` - Key not found in configuration
- `400 Missing key parameter` - No key provided
- `429 Too Many Requests` - Rate limit exceeded

```bash
curl "http://localhost:8080/key-auth?key=abc123"
```

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

## Security Considerations

- **`/allow` endpoint** should be protected by external authentication (Authelia, OAuth, etc.) via Caddy
- **`/knock`** is public but rate-limited
- **`/auth`** is for internal Caddy communication; consider binding to localhost only
- All state is in-memory; **restart = deny all** (fail-safe design)
- No persistence by design - ephemeral access control
