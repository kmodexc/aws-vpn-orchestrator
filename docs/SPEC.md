# VPN Control Plane — Specification

This is the **binding contract** between backend, frontend and deployment. If you change an
interface, update this file in the same change.

## 1. Purpose

A control plane that runs on a public VPS. It manages one disposable ingress
server (AWS Lightsail or EC2) that runs sing-box with three protocols (VLESS+REALITY, Hysteria2,
Shadowsocks-2022) and optionally sends its traffic out through WireGuard to the VPS.

It can:

- show the status of the ingress, and start/stop it
- rotate the ingress public IPv4 without a reboot (swap Lightsail static IP / EC2 Elastic IP)
- serve a **subscription URL** for proxy clients (Hiddify, v2rayNG, …) that always contains the
  current IP
- serve the **sing-box server config** that the ingress pulls on boot
- show an audit/event log

```text
Browser (React SPA) ──cookie session──┐
Android app ───────── Bearer JWT ─────┤
Proxy client ──── /s/<SUB_TOKEN> ─────┼──► Apache2 on host (TLS) ──► vpn-control (Rust, axum) ──► AWS API
Ingress box ── /i/<INGRESS_TOKEN>/… ──┘                                     │
                                                                             └── OIDC: https://auth.kmode.dev (Keycloak)
```

## 2. Repository layout

```text
backend/            Rust crate `vpn-control` (axum REST API, also serves the built SPA)
frontend/           React + TypeScript + Vite SPA
deploy/apache/      Example Apache2 vhosts (vpn-control.conf: *:80 redirect, *:443 TLS reverse proxy)
deploy/iam/         Least-privilege IAM policies (lightsail.json, ec2.json)
Dockerfile          Multi-stage: frontend build → backend build → minimal runtime image
docker-compose.yml  app (published on 127.0.0.1:${APP_HOST_PORT} only)
.env.example        Every setting, documented
docs/               SPEC.md (this file), keycloak.md, security.md
README.md
```

## 3. Configuration — everything comes from `.env`

All configuration **and all secrets** come from environment variables, which docker compose
loads from `.env`. There are no other config files with secrets. The backend validates every
variable at startup and **refuses to start** on an invalid or missing value, naming the variable but
never printing its value. The config struct's `Debug` impl must redact secrets.

The backend binary `vpn-control` has these subcommands (no subcommand = `serve`):

- `serve`: run the server.
- `gen-env`: print a complete `.env` to stdout, with freshly generated values for every secret
  (tokens, VLESS UUID, REALITY x25519 keypair, short id, HY2 password, self-signed HY2 cert+key,
  SS key, WG keypair) and placeholders for the rest. It needs no other env vars. Usage:
  `docker compose run --rm --no-deps -T app gen-env > .env` (`-T`: no pseudo-TTY, so the output
  keeps LF line endings).
- `healthcheck`: GET `http://127.0.0.1:<BIND_ADDR port>/healthz`; exit 0 on 200, else 1. It needs
  no other env vars except an optional `BIND_ADDR`. Used by the compose healthcheck, because the
  distroless image has no curl.

| Variable | Req | Default | Notes |
|---|---|---|---|
| `DOMAIN` | yes | – | Public host name of the control plane (e.g. `vpn.kmode.dev`); used by the Apache vhost and backend validation |
| `PUBLIC_BASE_URL` | yes | – | `https://<DOMAIN>`; must be https; no trailing slash; its host must equal `DOMAIN` (an optional `:port` is allowed) |
| `BIND_ADDR` | no | `0.0.0.0:8080` | |
| `APP_HOST_PORT` | compose only | `11001` | host port on `127.0.0.1` that Apache forwards to (`1xxyy` convention: `xx` = stack id 01–99, `yy` = forwarded port 01–99); not read by the backend |
| `RUST_LOG` | no | `info` | |
| `LOG_FORMAT` | no | `json` | `json` or `pretty` |
| `TRUST_PROXY_HEADERS` | no | `false` | if `true`, client IP = right-most `X-Forwarded-For` entry (appended by Apache `mod_proxy`); forced `true` in compose |
| `STATE_DIR` | no | `/data` | persistent state (event log, burned IPs) |
| `STATIC_DIR` | no | `/app/static` | built SPA |
| `OIDC_ISSUER_URL` | yes | – | e.g. `https://auth.kmode.dev/realms/<realm>`; must be https |
| `OIDC_CLIENT_ID` | yes | – | confidential client used for the browser login |
| `OIDC_CLIENT_SECRET` | yes | – | secret |
| `OIDC_REQUIRED_ROLE` | no | `vpn-admin` | realm role **or** client role of `OIDC_CLIENT_ID` |
| `OIDC_ALLOWED_CLIENTS` | no | `<OIDC_CLIENT_ID>` | comma list; a Bearer token's `azp` must be in it |
| `OIDC_SCOPES` | no | `openid profile email` | |
| `SESSION_IDLE_TIMEOUT_S` | no | `1800` | |
| `SESSION_ABSOLUTE_TIMEOUT_S` | no | `43200` | |
| `PROVIDER` | no | `lightsail` | `lightsail`, `ec2`, `fake` (local dev only; logs a loud warning) |
| `AWS_REGION` | yes* | – | *not for `fake` |
| `AWS_ACCESS_KEY_ID` | yes* | – | secret; used by the AWS SDK default chain |
| `AWS_SECRET_ACCESS_KEY` | yes* | – | secret |
| `INGRESS_INSTANCE` | yes* | – | Lightsail instance name or EC2 instance id |
| `ROTATE_COOLDOWN_S` | no | `120` | |
| `SUB_TOKEN` | yes | – | secret, ≥ 32 chars, `[A-Za-z0-9_-]` |
| `INGRESS_TOKEN` | yes | – | secret, ≥ 32 chars, `[A-Za-z0-9_-]`, must differ from `SUB_TOKEN` |
| `PROFILE_NAME` | no | `travel` | `[A-Za-z0-9_-]{1,32}` |
| `SUB_UPDATE_HOURS` | no | `1` | |
| `REALITY_SNI` | no | `www.microsoft.com` | |
| `HY2_SNI` | no | `www.bing.com` | |
| `VLESS_PORT` / `HY2_PORT` / `SS_PORT` | no | `443` / `443` / `8443` | `SS_PORT` must differ from `VLESS_PORT` (both TCP); HY2 is UDP and may share 443 |
| `VLESS_UUID` | yes | – | secret |
| `REALITY_PRIVATE_KEY` | yes | – | secret, x25519, base64url no padding |
| `REALITY_PUBLIC_KEY` | yes | – | must match the private key (checked at startup) |
| `REALITY_SHORT_ID` | yes | – | 16 hex chars |
| `HY2_PASSWORD` | yes | – | secret |
| `HY2_CERT_PEM_B64` | yes | – | standard base64 of the PEM certificate (self-signed, CN/SAN = `HY2_SNI`) |
| `HY2_KEY_PEM_B64` | yes | – | secret, standard base64 of the PKCS#8 PEM private key (`-----BEGIN PRIVATE KEY-----`); must match the certificate (checked at startup) |
| `SS_PASSWORD` | yes | – | secret, standard base64 of exactly 16 random bytes |
| `WG_ENABLED` | no | `false` | |
| `WG_VPS_ENDPOINT` | if WG | – | `host:port` |
| `WG_VPS_PUBLIC_KEY` | if WG | – | standard base64 |
| `WG_INGRESS_PRIVATE_KEY` | if WG | – | secret, standard base64 |
| `WG_INGRESS_ADDRESS` | no | `10.66.0.2/32` | |
| `WG_MTU` | no | `1380` | |

## 4. Authentication and authorization

Identity provider is Keycloak at `https://auth.kmode.dev`. Discovery uses
`<OIDC_ISSUER_URL>/.well-known/openid-configuration`. Discovery and JWKS are fetched **lazily** and
cached. Startup must not fail if the IdP is unreachable; the request then gets 503 (for the
browser redirects `/auth/login` and `/auth/callback`: a 302 to `/?login_error=unavailable`). JWKS is
re-fetched when an unknown `kid` shows up, at most once per 60 s. The discovery document's `issuer`
must equal `OIDC_ISSUER_URL` and all its endpoints must be https.

### 4.1 Browser: BFF pattern (backend-for-frontend)

Tokens never reach the browser. The backend runs the Authorization Code flow with **PKCE (S256)**,
`state` and `nonce`, as a confidential client.

- `GET /auth/login?return_to=<path>`: creates a pending login (state, nonce, PKCE verifier,
  sanitized return_to, 10-minute TTL) stored server-side under a random id. It sets the cookie
  `__Host-vpncp_login` (HttpOnly, Secure, SameSite=Lax, Path=/, Max-Age=600) and answers 302 to the
  authorization endpoint. `return_to` must be a same-origin relative path that starts with a single
  `/` (no `//`, no `\`, no scheme); otherwise `/`.
- `GET /auth/callback?code&state`: the login cookie must exist and its pending login's `state`
  must match (constant-time). The pending entry is single-use. The backend exchanges the code
  (with the PKCE verifier and client secret) and verifies the **ID token** (signature via JWKS with
  only RS256/ES256/PS256 allowed, `iss`, `aud` contains the client id, `exp`, `nonce`). It verifies
  the **access token** with the JWT validator from §4.2 (here `azp` must be `OIDC_CLIENT_ID` itself)
  and checks the role. If the IdP sends an `iss` callback parameter (RFC 9207) it must equal
  `OIDC_ISSUER_URL`. A session cookie present before login is destroyed. On success it creates
  the session, sets the session cookie, clears the login cookie and redirects 302 to return_to. On
  failure it redirects 302 to `/?login_error=<code>`, where code is one of `denied`, `invalid`,
  `forbidden`, `unavailable`, with no details.
- Session cookie `__Host-vpncp_session`: HttpOnly, Secure, SameSite=Lax, Path=/, no Domain. Value
  is 256 bits from a CSPRNG, base64url. Sessions are stored **server-side in memory**, keyed by the
  SHA-256 of the cookie value. A session holds sub, username, email, roles, csrf_token,
  id_token (for logout), created_at and last_seen. It enforces the idle and absolute timeouts. A
  background task purges expired sessions and pending logins. Both maps are capped (10 000
  sessions, 1 000 pending logins; when full, evict the oldest).
- `POST /auth/logout`: requires the session and CSRF header. It destroys the session, clears the
  cookie and returns `200 {"logout_url": "<end_session_endpoint>?id_token_hint=…&post_logout_redirect_uri=<PUBLIC_BASE_URL>/&client_id=…"}`
  (or `PUBLIC_BASE_URL/` if the IdP has no end-session endpoint).

### 4.2 API clients: Bearer JWT

For `Authorization: Bearer <jwt>` (Keycloak access token, e.g. from the Android app), the backend
verifies the signature via JWKS (RS256/ES256/PS256 only; reject `none` and HS*), `iss` ==
`OIDC_ISSUER_URL`, `exp` and `nbf` with 30 s leeway, `typ` == `Bearer` when present, and `azp` ∈
`OIDC_ALLOWED_CLIENTS`. It requires the role. Bearer requests are exempt from CSRF and ignore
cookies. A structurally invalid token (not a JWT, disallowed `alg`, no `kid`) is rejected offline
with 401 (a failure, §10) before any discovery/JWKS request, so it is never a 503 and never
triggers outbound traffic.

### 4.3 Role check

The user is authorized if `OIDC_REQUIRED_ROLE` is in `realm_access.roles` or in
`resource_access.<OIDC_CLIENT_ID>.roles` of the access token. Authenticated but missing the role
→ 403.

### 4.4 CSRF

Every non-GET/HEAD `/api/*` and `/auth/logout` request authenticated by **cookie** must:

- send header `X-CSRF-Token` equal (constant-time) to the session's csrf_token, **and**
- send an `Origin` header that equals `PUBLIC_BASE_URL` (or, if Origin is absent, a `Referer`
  starting with `PUBLIC_BASE_URL/`).

Otherwise → 403 `csrf`.

### 4.5 Token-in-path endpoints

`/s/{token}` and `/i/{token}/config.json` compare in constant time against `SUB_TOKEN` /
`INGRESS_TOKEN`. A wrong token → **404** (identical to any unknown path) and counts as a failure
for the per-IP limiter. These paths must **never be logged with the token**: the request trace
layer logs a redacted path (`/s/<redacted>`, `/i/<redacted>/config.json`).

## 5. HTTP API

All `/api/*` responses are JSON with `Cache-Control: no-store`. Errors use the form
`{"error": "<code>", "message": "<human text>"}`, where code is one of `unauthorized`, `forbidden`,
`csrf`, `not_found`, `bad_request`, `cooldown`, `rate_limited`, `conflict`, `unavailable`,
`internal`. Internal errors never leak details (log them server-side with a request id and return
the request id in header `X-Request-Id`; every response carries a fresh server-generated
`X-Request-Id`). Request bodies are limited to 16 KiB and JSON must use `deny_unknown_fields`. A
wrong method on an `/api` route is `405`, an oversized body `413`; both use code `bad_request`.
A non-empty request body must be `Content-Type: application/json` and a JSON object (an array is
`400`). `POST /api/ingress/start` and `/stop` accept only an empty body or `{}`.

| Method & path | Auth | Response |
|---|---|---|
| `GET /healthz` | none | `200 ok` (text/plain); no other info |
| `GET /api/me` | session or bearer | `{ "sub", "username", "email": string\|null, "roles": [..], "csrf_token": string\|null }` (csrf_token null for bearer); 401 if not logged in |
| `GET /api/status` | yes | `{ "provider", "region", "instance", "state", "public_ip": string\|null, "cooldown_remaining_s": int, "last_rotation_at": int\|null (unix s) }` |
| `POST /api/ingress/start` | yes + CSRF | `202 {"ok": true}` |
| `POST /api/ingress/stop` | yes + CSRF | `202 {"ok": true}` |
| `POST /api/ingress/rotate` | yes + CSRF | body `{"reason"?: string ≤ 200 chars}` → `200 {"public_ip": "…"}`; `429 {"error":"cooldown","message", "retry_after_s": int}` + `Retry-After`; `409 conflict` if another operation is running |
| `GET /api/events?limit=N` | yes | `[{ "at": int, "action": "start"\|"stop"\|"rotate"\|"error", "ip": string\|null, "detail": string, "actor": string }]`, newest first, N ≤ 200, default 50 |
| `GET /api/subscription` | yes | `{ "url": "<PUBLIC_BASE_URL>/s/<SUB_TOKEN>", "links": [string, …] \| null }` (links null when there is no public IP) |
| `GET /api/wireguard` | yes | `{ "enabled": bool, "ingress_public_key": string\|null, "ingress_address": string, "vps_peer_snippet": string\|null }` |
| `GET /s/{token}` | path token | `200 text/plain` base64 subscription; headers `profile-update-interval: <SUB_UPDATE_HOURS>`, `profile-title: base64:<b64(PROFILE_NAME)>`, `Cache-Control: no-store`; `503` if the ingress has no public IP |
| `GET /i/{token}/config.json` | path token | `200 application/json` sing-box server config |
| `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout` | see §4 | |
| any other GET | none | SPA: existing file from `STATIC_DIR`, else `index.html` (for client-side routes). `/api/*`, `/auth/*`, `/s/*`, `/i/*` never fall back to index.html → 404 JSON / plain 404 |

Only one start/stop/rotate runs at a time (a mutex; if busy → 409). Rotation: refuse while in
cooldown. Remember the old IP as "burned". If AWS returns an IP that is burned or equal to the
old one, rotate again (max 3 attempts). Record the event with the actor. Status is cached for
15 s; the cache is invalidated by any operation. Operations run in their own task, so a client
disconnect or request timeout never aborts an AWS operation half-way.

## 6. Ingress providers (Rust trait)

```rust
#[async_trait]
trait IngressProvider: Send + Sync {
    async fn status(&self) -> Result<IngressStatus>;   // state: running|stopped|pending|stopping|…, public_ip
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
    async fn rotate_ip(&self) -> Result<Ipv4Addr>;     // returns new public IPv4
}
```

- **Lightsail** (`aws-sdk-lightsail`): find the static IP attached to the instance (paginate
  `GetStaticIps`). Allocate a new static IP named `vpn-orchestrator-<unix_ts_ms>` (milliseconds, so retries never collide), detach the old one,
  attach the new one. On attach failure: release the new IP, re-attach the old one, return the
  error. Once the new IP is attached, deal with the old IP **before** anything else can fail:
  release it **only if its name starts with `vpn-orchestrator-`**; otherwise log a warning and
  leave it. Then read the new address (`GetStaticIp`, falling back to the instance's public IP
  unless it still equals the old address; a few retries); error only if no IPv4 can be found.
- **EC2** (`aws-sdk-ec2`): `AllocateAddress` (domain vpc) with tag `vpn-orchestrator=managed`, then
  `AssociateAddress` to the instance (this replaces the current public IP/EIP). On failure, release
  the new address. Release previously associated addresses **only if tagged
  `vpn-orchestrator=managed`**.
- **Fake**: in-memory, returns addresses from 203.0.113.0/24 (TEST-NET-3). Used by tests and local
  dev. Starts "running" with 203.0.113.10.

AWS errors are logged with full detail server-side and surface to clients as `unavailable`.

## 7. sing-box server config (`/i/{token}/config.json`) — target sing-box ≥ 1.12

```json
{
  "log": {"level": "warn"},
  "dns": {"servers": [{"type": "local", "tag": "local"}]},
  "inbounds": [
    {"type": "vless", "tag": "vless-reality", "listen": "::", "listen_port": VLESS_PORT,
     "users": [{"uuid": VLESS_UUID, "flow": "xtls-rprx-vision"}],
     "tls": {"enabled": true, "server_name": REALITY_SNI,
             "reality": {"enabled": true, "handshake": {"server": REALITY_SNI, "server_port": 443},
                         "private_key": REALITY_PRIVATE_KEY, "short_id": [REALITY_SHORT_ID]}}},
    {"type": "hysteria2", "tag": "hysteria2", "listen": "::", "listen_port": HY2_PORT,
     "users": [{"password": HY2_PASSWORD}],
     "tls": {"enabled": true, "server_name": HY2_SNI, "alpn": ["h3"],
             "certificate": [<PEM lines>], "key": [<PEM lines>]}},
    {"type": "shadowsocks", "tag": "shadowsocks", "listen": "::", "listen_port": SS_PORT,
     "method": "2022-blake3-aes-128-gcm", "password": SS_PASSWORD}
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct", "default_domain_resolver": "local"}
}
```

If `WG_ENABLED`, add
`"endpoints": [{"type": "wireguard", "tag": "wg-exit", "mtu": WG_MTU, "address": [WG_INGRESS_ADDRESS], "private_key": WG_INGRESS_PRIVATE_KEY, "peers": [{"address": host, "port": port, "public_key": WG_VPS_PUBLIC_KEY, "allowed_ips": ["0.0.0.0/0", "::/0"], "persistent_keepalive_interval": 25}]}]`
and set `route.final = "wg-exit"`.

## 8. Client share links (subscription = base64 of the links joined by `\n`)

`NAME` = `PROFILE_NAME`. Percent-encode all values.

- `vless://<VLESS_UUID>@<ip>:<VLESS_PORT>?encryption=none&flow=xtls-rprx-vision&security=reality&sni=<REALITY_SNI>&fp=chrome&pbk=<REALITY_PUBLIC_KEY>&sid=<REALITY_SHORT_ID>&type=tcp#<NAME>-reality`
- `hysteria2://<HY2_PASSWORD>@<ip>:<HY2_PORT>?sni=<HY2_SNI>&insecure=1&pinSHA256=<hex sha256 of cert DER>#<NAME>-hy2`
- `ss://<urlencode("2022-blake3-aes-128-gcm:" + SS_PASSWORD)>@<ip>:<SS_PORT>#<NAME>-ss`

IPv6 public addresses are never published.

## 9. Persistent state

`STATE_DIR/state.json` holds `{ events: [... max 500], burned_ips: [... max 500], last_rotation_at }`.
Writes are atomic (temp file + rename) with file mode 0600. It holds no secrets.

## 10. Security requirements (non-negotiable)

- Every response carries `Strict-Transport-Security: max-age=63072000; includeSubDomains`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`,
  `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`,
  `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()`, and the CSP
  `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`.
  This means the SPA must have **no inline scripts or inline styles**, i.e. no `style=` attributes
  and no CSS-in-JS that injects `<style>`.
- No CORS layer at all (same-origin only).
- No `Server` header and no framework fingerprints. A generic 404 for unknown paths.
- Per-IP rate limiting with a token bucket: `/auth/*` 20/min, `/s/*` and `/i/*` 30/min, `/api/*`
  120/min. Also a failure limiter: 10 failed token/auth attempts in 10 min → 429 for 10 min.
  Bound the limiter's memory. IPv6 clients are keyed by their /64 prefix; IPv6 failures are also
  summed per /48, and 100 failures in 10 min from one /48 block the whole /48 for 10 min (so one
  allocation can neither multiply its guesses nor fill the table). A failure is never dropped:
  when the failure table is full, evict an unblocked entry (oldest last failure) first, else the
  block that expires soonest. Failures are: a wrong
  path token, an invalid Bearer token, and a callback with a bad `state`/`iss`/token (not a
  missing role, a user-cancelled login or an expired session cookie). While blocked, all
  `/auth`, `/s`, `/i` and `/api` requests from that client get 429 with `Retry-After`.
- Static files: `/assets/*` (content-hashed by Vite) get
  `Cache-Control: public, max-age=31536000, immutable`; everything else from `STATIC_DIR`
  (including `index.html`) gets `no-cache`. A missing path with a file extension, or under
  `/assets/`, is a plain 404 instead of `index.html`.
- Request timeout 30 s (rotate may take longer: 90 s) and body limit 16 KiB. Graceful shutdown on
  SIGTERM: drain in-flight requests, then wait up to 25 s for a running ingress operation.
  The compose `stop_grace_period` for the app is 120 s (> 90 s rotate + 25 s idle wait), so
  Docker never SIGKILLs a rotation half-way through its AWS call sequence.
- Outbound HTTP (OIDC) uses rustls and https only, with timeouts. No redirects are followed for
  token requests.
- Never log secrets, tokens, cookies, Authorization headers or token paths.
- `#![forbid(unsafe_code)]`. No `unwrap()`/`expect()` on request paths.
- The container runs as non-root with a read-only root filesystem, `cap_drop: ALL` and
  `no-new-privileges`. TLS terminates in the host's Apache2 (`deploy/apache/vpn-control.conf`,
  certificate via `certbot certonly --apache`, renewed by certbot's timer). The compose stack has
  only the `app` service, published on `127.0.0.1:${APP_HOST_PORT}` only, never on a public
  interface. Apache appends the real client address (IPv4 or IPv6) to `X-Forwarded-For`; the
  backend uses the right-most entry. Apache-generated responses (redirect, 502) carry a minimal
  `Server: Apache` header (`ServerTokens Prod`) and not the app's security headers. The `.env` file is never baked into an image (`.dockerignore`).
- The frontend has no tokens in localStorage/sessionStorage, no `dangerouslySetInnerHTML`, and no
  third-party CDNs or analytics; it uses `fetch` with `credentials: "same-origin"`.

## 11. Frontend

React 18+ with TypeScript (strict) and Vite, no UI framework required. Plain CSS files only
(CSP!). Mobile-first, works at 360 px wide, supports light and dark via `prefers-color-scheme`.

- On load: `GET /api/me`. 401 → login screen with a "Sign in" button → `window.location = "/auth/login?return_to=" + current path`.
  Show a `login_error` query param as a friendly message.
- Dashboard (403 → "Your account lacks the required role" screen with logout):
  - status card: state badge, public IP, provider/region/instance, cooldown countdown, last rotation;
    poll every 5 s while the state is transitional (pending/stopping/starting), else every 30 s
  - action buttons: Start, Stop, **Rotate IP** (asks for confirmation, optional reason input),
    disabled while busy or in cooldown, with errors shown inline
  - subscription card: the URL with a copy button, a QR code (`qrcode` npm package rendered to
    `<canvas>`), hidden behind a "Show" toggle; the links list (each copyable) behind a toggle
  - WireGuard card (only if enabled): ingress public key and VPS peer snippet in `<pre>` with copy
  - event log table (newest first, relative times)
  - header: username, Logout (POST /auth/logout with CSRF → navigate to logout_url)
    - only a successful logout or a 401 counts as signed out. On a `csrf` failure the client refreshes
      the token via `GET /api/me` and retries once; any other failure keeps the dashboard and shows
      "Sign-out failed: your session is still active" (never show the login screen while the
      session cookie may still be valid)
- All mutating fetches send `X-CSRF-Token` (from `/api/me`) and `Content-Type: application/json`.
- Every API fetch uses `mode: "same-origin"`, `credentials: "same-origin"` and
  `referrerPolicy: "same-origin"`. The last one is required: under the page's
  `Referrer-Policy: no-referrer` (§10), a non-`cors` POST would otherwise carry `Origin: null` and
  fail the CSRF Origin check (§4.4). Navigations keep `no-referrer`.
- On 401 after the first load (session expired), go back to the login screen.
