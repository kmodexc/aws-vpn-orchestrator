# Security

vpn-control is designed to run on a public server. This document describes what it protects,
against whom, how (mapped to [SPEC §10](SPEC.md#10-security-requirements-non-negotiable)), how to
operate it safely, and what risks remain.

## 1. Assets

| Asset | Where | Impact if compromised |
|---|---|---|
| Proxy credentials (VLESS UUID, REALITY keys/short id, HY2 password + cert key, SS key) | `.env`; served via `/s/<SUB_TOKEN>` (client part) and `/i/<INGRESS_TOKEN>/config.json` (server part) | Free use of your proxy; traffic attributed to you; easier fingerprinting/blocking of the ingress |
| `SUB_TOKEN`, `INGRESS_TOKEN` | `.env`, client apps, ingress `/etc/sing-box-fetch.env`, ingress user-data | Disclosure of the credentials above |
| AWS access key | `.env` | Start/stop/rotate the ingress, allocate/release static IPs/EIPs (IAM-limited); cost |
| OIDC client secret | `.env` | Impersonate the web client towards Keycloak (still needs a user login) |
| Admin session / Keycloak account | browser cookie / Keycloak | Full control of the ingress via the UI |
| Event log, burned-IP list | `app_state` volume | Low (no secrets); privacy of your usage pattern |
| TLS keys of the control plane | `/etc/letsencrypt` on the host (certbot) | MITM of the control plane |

## 2. Adversaries

- **Internet scanners and opportunistic attackers** — probe every public IP/host name for admin
  panels, known paths, default credentials, framework bugs.
- **Targeted attacker on the internet** — knows the domain, tries credential stuffing against
  Keycloak, brute-forces path tokens, attempts CSRF/XSS/clickjacking against a logged-in admin,
  tries to abuse the app for SSRF.
- **Network observer / restrictive network operator** — sees traffic to the ingress and the control plane,
  actively probes suspected proxies, blocks IPs and SNIs, may block the control-plane domain.
- **Stolen or lost phone** — has the subscription URL (and therefore all proxy credentials) and
  perhaps an unlocked Keycloak session in the Android app.
- **Compromised dependency / image** — malicious crate, npm package, base image or sing-box
  release.
- **Cloud-side mistakes** — over-privileged IAM keys, leaked `.env` in a backup or repository.

Out of scope: a fully compromised VPS host (root on the Docker host can read `.env`), a compromised
Keycloak, a compromised AWS account root.

## 3. Controls

### Application (SPEC §4, §5, §10)

| Control | Purpose |
|---|---|
| OIDC Authorization Code + **PKCE S256**, `state`, `nonce`; confidential client; BFF — tokens never reach the browser | No token theft via XSS; no code interception |
| ID-token + access-token validation: JWKS, only RS256/ES256/PS256, `iss`, `aud`/`azp` allow-list, `exp`/`nbf`, `typ` | No forged/foreign tokens, no `alg=none`/HS confusion |
| Role check `vpn-admin` (realm or client role) | Other realm users cannot use the app |
| Session cookie `__Host-vpncp_session`: 256-bit random, HttpOnly, Secure, SameSite=Lax, host-only; stored server-side as SHA-256; idle + absolute timeout; bounded maps | No session fixation/theft via JS or sibling domains; memory-exhaustion safe |
| CSRF: per-session token header **and** `Origin`/`Referer` == `PUBLIC_BASE_URL` | No cross-site requests that rotate/stop the ingress |
| Strict CSP (`default-src 'none'`, `script-src 'self'`, no inline), `frame-ancestors 'none'`, X-Frame-Options, COOP/CORP, nosniff, Referrer-Policy no-referrer, Permissions-Policy, HSTS 2 years | XSS mitigation, clickjacking, tokens never leak via Referer |
| No CORS at all | Other origins cannot read API responses |
| Path tokens: ≥ 32 chars, constant-time comparison, wrong token → plain 404 (same as any unknown path) | Not enumerable, no oracle |
| Per-IP token-bucket rate limits (`/auth` 20/min, `/s` `/i` 30/min, `/api` 120/min) + failure limiter (10 failures / 10 min → 429 for 10 min); bounded memory | Brute force and resource exhaustion |
| Client IP = right-most `X-Forwarded-For` entry (`TRUST_PROXY_HEADERS=true` forced in compose). Apache `mod_proxy` **appends** the real client address (IPv4 or IPv6) to XFF, so the right-most entry is the client as seen by Apache; client-supplied entries further left are ignored. Safe because the app port is reachable only from localhost | Rate limits cannot be evaded by spoofing headers |
| Body limit 16 KiB (Apache `LimitRequestBody 65536` as outer guard), `deny_unknown_fields`, request timeouts (30 s / 90 s rotate; Apache `ProxyTimeout 120`), Apache's request/header timeouts | Malformed input and slow-loris |
| Generic errors with request id, details only in server logs; AWS errors → `unavailable` | No information leakage |
| Never log secrets, tokens, cookies, Authorization, token paths (app redacts `/s/…` `/i/…`; the Apache access log replaces the request line of `/s/`, `/i/` and `/auth/callback` requests with a redacted line) | Logs are not a secret store |
| Outbound OIDC over rustls + https only, timeouts, no redirects on token requests | No SSRF/downgrade via IdP metadata |
| `#![forbid(unsafe_code)]`, no `unwrap`/`expect` on request paths | Memory safety, no panics as DoS |
| Config validated at startup; refuses to start; `Debug` redacts secrets | No half-configured production instance, no secrets in crash output |
| Frontend: no tokens in web storage, no `dangerouslySetInnerHTML`, no third-party CDNs/analytics | XSS surface and supply chain |

### Deployment

| Control | Purpose |
|---|---|
| The host's Apache2 is the only public listener (80/443 tcp); the compose stack has only the `app` service, published on **`127.0.0.1:<APP_HOST_PORT>` only** (port convention `1xxyy`) | App is not directly reachable from the internet; Apache runs on the host and sees every client's real IPv4/IPv6 address |
| App container: `read_only` root FS, `cap_drop: ALL`, `no-new-privileges`, memory/CPU/PID limits, rotated logs | Contain a compromise, prevent persistence and fork bombs |
| App: distroless image (no shell, no package manager), UID 65532, only `/data` writable | Minimal attack surface |
| Apache ([deploy/apache/vpn-control.conf](../deploy/apache/vpn-control.conf)): port 80 only redirects to https; TLS with certbot's certificate and `options-ssl-apache.conf`; `Protocols h2 http/1.1`; `ProxyPreserveHost On`, `X-Forwarded-Proto https`. Recommended globally: `ServerTokens Prod`, `ServerSignature Off` (`/etc/apache2/conf-available/security.conf`). The app sets all security headers (HSTS, CSP, …) itself; Apache passes them through | Minimal fingerprint, TLS with automatic renewal (certbot timer) |
| `.env` is the only secret store, mode 0600, git-ignored **and** docker-ignored (allow-list build context) | Secrets never land in git or image layers |
| Least-privilege IAM (deploy/iam/*.json): instance-scoped start/stop; EC2 EIP actions restricted to tag `vpn-orchestrator=managed` | A leaked AWS key cannot touch other resources (see residual risks for Lightsail) |
| Ingress: pinned sing-box with SHA-256 verification; runs as an unprivileged user with only `CAP_NET_BIND_SERVICE` and a systemd sandbox; config pulled over HTTPS without redirects and validated before use; token never on a command line | Supply chain and local privilege separation on the ingress |
| Ingress: sing-box user is blocked from instance metadata (169.254.169.254, fd00:ec2::254) | A proxy user cannot read user-data (INGRESS_TOKEN) or instance credentials |
| Ingress: ufw default-deny, only SSH + proxy ports; key-only SSH; unattended security upgrades | Host hardening |

### Keycloak (docs/keycloak.md)

Exact redirect URIs, PKCE required, no direct-access/implicit grants, brute-force detection, short
access-token lifetime, 2FA (OTP/WebAuthn) for every `vpn-admin` user, registration disabled.

## 4. Operational guidance

### Secret rotation

Generate fresh values without touching your current file, then copy over what you rotate:

```bash
(umask 077; docker compose run --rm --no-deps -T app gen-env > .env.new)
# copy the relevant lines from .env.new into .env, then:
shred -u .env.new 2>/dev/null || rm -f .env.new
docker compose up -d          # recreates the app with the new environment
```

Restarting the app also **logs out every browser session** (sessions are in memory).

| Secret | Procedure | Client impact |
|---|---|---|
| `SUB_TOKEN` | new value → restart. Old URL immediately returns 404. | Re-import the new subscription URL on every device |
| Proxy credentials (`VLESS_UUID`, `HY2_PASSWORD`, `SS_PASSWORD`, `REALITY_*`, `HY2_CERT_PEM_B64`+`HY2_KEY_PEM_B64`) | new values → restart → ingress picks up the new config within ~10 min (or immediately: `sudo systemctl start sing-box-config` on the ingress) | Clients must *update the subscription* (HY2 pin changes with the cert) |
| `INGRESS_TOKEN` | new value → restart → on the ingress re-run `bootstrap.sh` with the new token (or edit `/etc/sing-box-fetch.env`, root 0600). Until then the ingress keeps its last valid config. | none |
| `OIDC_CLIENT_SECRET` | Keycloak → Clients → vpn-control → Credentials → *Regenerate* → `.env` → restart | Users log in again |
| AWS access key | IAM → create a 2nd key → `.env` → restart → verify status works → deactivate, then delete the old key | none |
| `WG_INGRESS_PRIVATE_KEY` | new value → restart → update the peer on the VPS (`/api/wireguard` shows the new snippet) | none |

Recommended cadence: AWS key and OIDC client secret every 90 days; proxy credentials and tokens on
suspicion or when a device leaves your control.

### Incident: the subscription URL / `SUB_TOKEN` leaked (or a phone was lost)

The subscription contains **all client credentials**, so rotating the token alone is not enough.

1. Rotate `SUB_TOKEN` **and** the proxy credentials (VLESS UUID, HY2 password + cert/key,
   SS key, REALITY short id; REALITY keypair optional) — table above. Restart the app.
2. Force the ingress to pull the new config: `sudo systemctl start sing-box-config` on the ingress
   (or wait ≤ 10 min). The old credentials stop working when sing-box restarts.
3. **Rotate the IP** in the dashboard — the leaked links also revealed the ingress address.
4. Lost phone: Keycloak → Users → your user → *Sessions* → **Sign out** all sessions; remove/reset
   its OTP/passkey credential; change the password.
5. Re-import the new subscription on your remaining devices. Check the event log for actions you
   did not perform.

### Incident: `.env` leaked

Treat everything as compromised: rotate **all** secrets above (fastest: generate a complete new
`.env`, re-fill the placeholders), delete the old AWS key, regenerate the OIDC client secret,
re-run `bootstrap.sh` with the new `INGRESS_TOKEN`, rotate the IP, re-import the subscription.

### Backups

- `.env` is the only thing you cannot regenerate without client impact. Keep an **encrypted,
  offline** copy (password manager, age/gpg-encrypted file). Never store it in git, cloud sync in
  plaintext, or chat.
- `app_state` (event log, burned IPs) is optional; `/etc/letsencrypt` holds the certificates and
  certbot's account key — can be re-issued with `certbot certonly --apache` if lost (mind Let's
  Encrypt rate limits).

### Updates

- **Weekly / on advisories**: `git pull && docker compose build --pull && docker compose up -d`.
  This picks up new base images (security patches for distroless) and dependency updates.
- Run `cargo audit` (backend) and `npm audit --omit=dev` (frontend) before upgrading dependencies.
- VPS: unattended security upgrades (also covers Apache2 and certbot); Docker Engine updates.
  Certificates renew automatically via certbot's systemd timer (`sudo certbot renew --dry-run`).
- Ingress: unattended upgrades are enabled by `bootstrap.sh`; update sing-box by bumping the pinned
  version + checksums and re-running the script. A disposable ingress can also simply be rebuilt.
- For tamper-evident builds pin base images by digest (see the Dockerfile header).

### Monitoring

- `docker compose logs app` — watch for repeated `rate_limited`/failed-token events (scanning) and
  unexpected `rotate`/`stop` events.
- AWS: enable CloudTrail (management events are free) and a billing alarm; alert on IAM activity
  of the vpn-control user from unexpected IPs.
- Keycloak: enable login events for the realm and review failed logins.

## 5. Residual risks

- **Lightsail IAM granularity**: static IPs cannot be scoped (random UUID ARNs, no tags), so a
  leaked AWS key can detach/release *any* Lightsail static IP in the region. The backend only
  releases `vpn-orchestrator-*` IPs, but IAM does not enforce it. Mitigation: dedicated AWS
  account (or at least a region used for nothing else).
- **In-memory sessions**: a restart logs everyone out (by design; simple and leak-free).
- **Control-plane domain blocked by a restrictive network**: clients on that network may be
  unable to refresh the subscription directly. Update the subscription while connected through the
  proxy (Hiddify/v2rayNG fetch through the active proxy), or before travelling.
- **Protocol detection**: Shadowsocks-2022 can be flagged by entropy heuristics; Hysteria2 (QUIC)
  may be throttled; REALITY depends on the chosen `REALITY_SNI`. Rotation is the remedy — the
  ingress is meant to be disposable.
- **Credentials on client devices**: the subscription URL and proxy credentials live in the proxy
  app (and possibly its logs/clipboard). Use device encryption and a screen lock.
- **Apache runs on the host**, not in a container: an Apache RCE runs as `www-data` on the VPS,
  outside any container sandbox (the TLS private key is readable only by root). Keep Apache
  patched and the enabled modules minimal.
- **Apache-generated responses lack the app's security headers**: error pages Apache produces
  itself (e.g. 502 while the app is down or restarting) and the port-80 redirect carry no
  HSTS/CSP/etc. and include a `Server: Apache` header. Accepted: they contain no user content;
  HSTS is already pinned by earlier responses.
- **Docker host**: anyone with root or `docker` group membership on the VPS can read `.env`. Keep
  the host minimal, SSH key-only, and the docker group empty.
- **Supply chain**: crates, npm packages, base images (pinned by tag, not digest by default),
  the distribution's Apache2/certbot packages and sing-box releases are trusted. The build uses lockfiles (`--locked`, `npm ci`) and
  `npm ci --ignore-scripts`; sing-box is checksum-verified.
- **Keycloak dependency**: if `auth.kmode.dev` is down, nobody can log in (the subscription and
  ingress config endpoints keep working). A compromised Keycloak realm can mint admin tokens.
- **Ingress user-data** contains `INGRESS_TOKEN` and is readable by anyone with AWS console/API
  access to the instance and by root on the ingress (the sing-box user is blocked from IMDS).
  It only grants the server config, which the ingress holds anyway.
- **Rate limiting is per IP**: a distributed attacker gets more attempts; the 32+ character random
  path tokens and Keycloak brute-force protection make that irrelevant in practice.
