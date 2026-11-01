# vpn-control

A small, self-hosted control plane for a **disposable proxy ingress** on AWS
(Lightsail or EC2). The ingress runs [sing-box](https://sing-box.sagernet.org) with three
protocols — VLESS+REALITY, Hysteria2 and Shadowsocks-2022 — and can optionally send all traffic
out through WireGuard to your VPS.

From a web UI (or a Keycloak-authenticated API client) you can:

- see the ingress status and start / stop it
- **rotate its public IPv4 in seconds** (swap the Lightsail static IP / EC2 Elastic IP) when the
  current one gets blocked — no reboot, no client reconfiguration
- hand out one **subscription URL** for Hiddify, v2rayNG, NekoBox, … that always contains the
  current IP
- serve the sing-box server config the ingress pulls on boot
- review an audit log of every action

Backend: Rust (axum) REST API. Frontend: React + TypeScript (Vite). Login: OIDC against Keycloak at
`https://auth.kmode.dev`. Runs with `docker compose` behind the host's Apache2 reverse proxy (TLS via certbot / Let's Encrypt).
The full contract is in [docs/SPEC.md](docs/SPEC.md).

## Architecture

```text
                         ┌───────────────────────── your VPS (public) ─────────────────────────┐
 Browser (React SPA) ─┐  │                                                                      │
   cookie session     │  │  ┌────────────────┐  127.0.0.1:<APP_HOST_PORT>  ┌──────────────────┐ │
 Android app ─────────┼──┼─►│ Apache2 (host) │ ──────────────────────────► │ docker: app      │ │
   Bearer JWT         │  │  │ :80  :443 tcp  │   (e.g. 11001 → app:8080,   │ vpn-control      │ │
 Proxy client ────────┤  │  │ certbot / LE   │    localhost only)          │ (Rust, axum)     │ │
   GET /s/<SUB_TOKEN> │  │  └────────────────┘                             │ non-root, RO FS  │ │
 Ingress box ─────────┘  │                                                 │ volume app_state │ │
   GET /i/<INGRESS_TOKEN>/config.json                                      └───┬──────────┬───┘ │
                         └─────────────────────────────────────────────────────┼──────────┼─────┘
                                                                               │ HTTPS    │ HTTPS
                                                   AWS API (Lightsail / EC2) ◄─┘          └─► Keycloak
                                                   start/stop, swap static IP / EIP           auth.kmode.dev
                                                              │
                                                              ▼
  Phone / laptop ══ VLESS·REALITY / HY2 / SS ══► Ingress (sing-box, AWS) ──► Internet
                                                     ╚═ optional WireGuard ═► your VPS ──► Internet
```

* Browsers never see an OIDC token (backend-for-frontend pattern, server-side sessions).
* TLS terminates in the host's Apache2 (example vhosts: [deploy/apache/vpn-control.conf](deploy/apache/vpn-control.conf)).
  The compose stack has a single service, `app`, published **only on `127.0.0.1:<APP_HOST_PORT>`**
  — never on a public interface.
* All configuration and every secret live in one file: `.env`.

## Prerequisites

| What | Notes |
|---|---|
| A Linux VPS with a public IPv4 (IPv6 optional) | 1 vCPU / 1 GB RAM is plenty. Ports 80/tcp and 443/tcp reachable. |
| Apache2 2.4 and certbot (with the Apache plugin) on the host | Debian/Ubuntu: `apt install apache2 certbot python3-certbot-apache` |
| Docker Engine ≥ 25 with the Compose plugin ≥ 2.24 | `docker version`, `docker compose version` (the compose file uses `healthcheck.start_interval` and the long `env_file` syntax) |
| A DNS name for the control plane | e.g. `vpn.kmode.dev`, A (and optionally AAAA) record → VPS — see step 1 |
| Admin access to the Keycloak realm on `https://auth.kmode.dev` | see [docs/keycloak.md](docs/keycloak.md) |
| An AWS account | ideally a **dedicated** account (or at least a region you use for nothing else) |
| AWS CLI v2 with admin credentials (on your laptop or the VPS) | for the setup scripts in `deploy/aws/` (step 5); the control plane itself gets only a narrow key |
| A proxy client | Hiddify, v2rayNG, NekoBox, sing-box for Android/iOS, … |

## Setup

### 1. DNS

Create `A vpn.example.com → <VPS IPv4>` (and `AAAA → <VPS IPv6>` if the VPS has IPv6). Ports 80
and 443 must be reachable from the internet; certbot validates the domain on port 80 (step 6).

Apache runs directly on the host, so it sees every client's real IPv4 **and** IPv6 address and
appends it to `X-Forwarded-For` for the app.

After the first start (step 6), check that the app sees real client addresses: request
`https://<DOMAIN>/healthz` from another machine and look at the `client_ip` field in
`docker compose logs app`. It must show that machine's public IP, never `127.0.0.1` or a Docker
address such as `172.x.x.x`. If it does, the per-IP limits do not work — check that the request
went through the Apache vhost and that `TRUST_PROXY_HEADERS` is `true` (forced in compose).

### 2. VPS host firewall

Allow only SSH and the web ports:

```bash
sudo ufw default deny incoming
sudo ufw allow 22/tcp          # better: from your admin IP only
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

> Docker-published ports bypass ufw (Docker writes its own iptables rules). That is fine here
> because the app is published on `127.0.0.1` only — never change the `ports:` entry of the `app`
> service to a public interface.

### 3. Keycloak

Follow [docs/keycloak.md](docs/keycloak.md): create the confidential client
(`https://<DOMAIN>/auth/callback` as the only redirect URI), the realm role `vpn-admin`, assign it
to your user and enable 2FA. Note the **issuer URL**, **client id** and **client secret**.
For people who should only *use* the VPN, create a second role `vpn-user`: they sign in and see
just the subscription to join, with no controls. It is off until you set `OIDC_USER_ROLE=vpn-user`
in `.env`.

### 4. Generate `.env`

On the VPS, in the repository checkout:

```bash
umask 077
docker compose run --rm --no-deps -T app gen-env > .env   # pulls the image the first time
chmod 600 .env
$EDITOR .env
```

`gen-env` fills every secret with fresh random values (path tokens, VLESS UUID, REALITY keypair
and short id, Hysteria2 password and self-signed certificate, Shadowsocks key, WireGuard keypair).
Fill in the placeholders: `DOMAIN`, `PUBLIC_BASE_URL`, `OIDC_*`, and pin `VPN_CONTROL_IMAGE`
to a commit tag (see [Container image](#container-image)). `PROVIDER`, `AWS_*` and
`INGRESS_INSTANCE` are written by the AWS setup script in step 5. Every variable is documented in [.env.example](.env.example).

`APP_HOST_PORT` is the localhost port Apache forwards to (`gen-env` writes `11001` as an example).
Port convention: apps bind to `127.0.0.1` on ports **`1xxyy`**, where `xx` (01–99) is the id of the
application / compose stack and `yy` (01–99) numbers the ports of that stack that Apache forwards.
This stack forwards exactly one port (`yy = 01`); pick a free `xx` (e.g. `10` → `11001`) and use
the same port in the Apache vhost (step 6).

### 5. AWS: ingress + IAM user (automated with the AWS CLI)

[deploy/aws/setup-lightsail.sh](deploy/aws/setup-lightsail.sh) does the whole AWS side in one
idempotent run. It uses **your admin credentials** (an AWS CLI v2 profile or SSO session) — the
control plane itself only ever gets the narrow key the script creates for it.

```bash
# where you have admin AWS credentials and the .env from step 4
# (Linux, macOS, WSL or Git Bash; needs aws CLI v2)
deploy/aws/setup-lightsail.sh --profile admin --region ap-northeast-1   --budget-email you@example.com          # optional monthly cost alarm ($20 default)
```

What it does:

1. creates a Lightsail instance (Ubuntu 24.04, cheapest bundle with IPv4, IPv4-only networking)
   whose launch script runs [deploy/ingress/bootstrap.sh](deploy/ingress/bootstrap.sh) with
   `PUBLIC_BASE_URL` and `INGRESS_TOKEN` from `.env` (passed via a 0600 temp file, never on a
   command line)
2. sets the Lightsail firewall to exactly the proxy ports (TCP `VLESS_PORT`, UDP `HY2_PORT`,
   TCP+UDP `SS_PORT`) plus SSH from your current public IP (`--ssh-cidr`, or `--no-ssh`)
3. allocates and attaches a static IP named `vpn-orchestrator-*` (the control plane rotates it)
4. creates the IAM user `vpn-control` with the least-privilege policy
   [deploy/iam/lightsail.json](deploy/iam/lightsail.json) pinned to this instance and region,
   plus an access key
5. writes `PROVIDER=lightsail`, `AWS_REGION`, `INGRESS_INSTANCE`, `AWS_ACCESS_KEY_ID` and
   `AWS_SECRET_ACCESS_KEY` into `.env`

Re-running it changes nothing that is already correct (it refreshes the firewall — e.g. when
your own IP changed — and the IAM policy). `--help` lists all options.

If you ran it on another machine, copy the updated `.env` to the VPS (`scp`, keep it 0600). The
ingress configures itself within a few minutes and keeps retrying the config download every
10 minutes until the control plane (step 6) answers.

Two companion scripts:

| Script | Use |
|---|---|
| [deploy/aws/rebuild-lightsail.sh](deploy/aws/rebuild-lightsail.sh) `--region ap-southeast-1` | Rotating the IP is not enough (whole range blocked): builds a fresh ingress in another region, re-pins the IAM policy, updates `.env`, deletes the old instance and its static IPs. Same secrets, so clients only need a subscription update. Then `docker compose up -d --force-recreate app`. |
| [deploy/aws/teardown-lightsail.sh](deploy/aws/teardown-lightsail.sh) | Back home: deletes the instance, its static IPs, the IAM user (`--keep-iam` to keep it) and optionally the budget (`--budget`); clears the AWS key in `.env`. |

EC2 is supported by the backend (`PROVIDER=ec2`) but has no setup script — use the manual steps
below and [deploy/iam/ec2.json](deploy/iam/ec2.json).

#### Manual alternative: the ingress instance

**Lightsail** (simplest, cheapest):

1. Create an instance (Ubuntu 24.04 LTS or Debian 12) in a region close to your users,
   e.g. Frankfurt `eu-central-1`, Tokyo `ap-northeast-1` or Singapore `ap-southeast-1`.
2. *Launch script*: paste [deploy/ingress/bootstrap.sh](deploy/ingress/bootstrap.sh) after
   filling in `CONTROL_PLANE_URL` (= `PUBLIC_BASE_URL`) and `INGRESS_TOKEN` (from your `.env`,
   step 4). You can also create the instance first and run the script later via SSH. Never put
   the token on a command line: it would end up in your shell history and be visible in `ps` to
   every local user, including the `sing-box` user. Read it without echo and pass it through the
   environment instead:

   ```bash
   read -rs -p 'INGRESS_TOKEN: ' INGRESS_TOKEN; echo
   export INGRESS_TOKEN CONTROL_PLANE_URL=https://vpn.example.com
   sudo --preserve-env=INGRESS_TOKEN,CONTROL_PLANE_URL bash bootstrap.sh
   unset INGRESS_TOKEN
   ```

   (Alternatively edit the CONFIG block in a private copy — `install -m 600 bootstrap.sh
   ~/bootstrap.local.sh`, edit it, `sudo bash ~/bootstrap.local.sh`, then `shred -u` it.)
3. Attach a **static IP** to the instance (Networking tab). Rotation swaps it.
4. Networking → IPv4 firewall: delete the defaults except SSH, then allow **exactly**

   | Protocol | Port | Purpose |
   |---|---|---|
   | TCP | 22 | SSH (restrict to your IP) |
   | TCP | 443 | VLESS + REALITY |
   | UDP | 443 | Hysteria2 |
   | TCP + UDP | 8443 | Shadowsocks-2022 |

   (Adjust if you change `VLESS_PORT` / `HY2_PORT` / `SS_PORT`.) Remove the IPv6 rules or disable
   IPv6 networking — IPv6 addresses are never published in the subscription.
5. Find the instance's resource id for the IAM policy:
   `aws lightsail get-instance --instance-name vpn-ingress --query instance.arn`
   → `arn:aws:lightsail:<REGION>:<ACCOUNT_ID>:Instance/<INSTANCE_RESOURCE_ID>`.

**EC2** works the same way: launch Ubuntu 24.04/Debian 12 with the bootstrap script as *user data*,
a security group with the ports above, IMDSv2 required, **no instance role**, and an Elastic IP
tagged `vpn-orchestrator=managed` (or let the first rotation allocate one).

#### Manual alternative: IAM user for the control plane

Create a dedicated IAM user (programmatic access only, no console) and attach an inline policy:

- Lightsail: [deploy/iam/lightsail.json](deploy/iam/lightsail.json)
- EC2: [deploy/iam/ec2.json](deploy/iam/ec2.json)

Replace `<REGION>`, `<ACCOUNT_ID>`, `<INSTANCE_RESOURCE_ID>` / `<INSTANCE_ID>`. Create an access
key; it goes into `.env` (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).

Scoping notes:

- **Lightsail** static IPs are addressed by a random resource UUID, are not taggable, and
  `GetStaticIps` / `AllocateStaticIp` support no resource scoping at all. Static-IP actions are
  therefore limited to the region (`StaticIp/*`); the backend itself only ever releases IPs whose
  name starts with `vpn-orchestrator-`. Start/stop and attach are pinned to the one instance. The
  read calls are region-wide: although the Service Authorization Reference lists a resource type
  for `lightsail:GetInstance`, the API evaluates it against `arn:aws:lightsail:<region>:<account>:*`
  (observed: `not authorized to perform: lightsail:GetInstance on resource: …:*` with the
  instance-scoped statement), so an instance ARN never matches.
  ⇒ Do not keep other static IPs you care about in the same account/region.
- **EC2**: `Describe*` cannot be scoped. Start/stop is pinned to one instance; new Elastic IPs can
  only be created *with* the tag `vpn-orchestrator=managed`; only tagged EIPs can be associated
  (and only to the ingress instance) or released.

### 6. Start the app and configure Apache

Start the app:

```bash
docker compose pull
docker compose up -d
docker compose ps            # app must become "healthy"
docker compose logs -f app   # startup errors name the offending variable
curl -fsS http://127.0.0.1:11001/healthz   # use your APP_HOST_PORT
```

If a variable is missing or invalid the app refuses to start and logs the variable name (never its
value).

[deploy/apache/vpn-control.conf](deploy/apache/vpn-control.conf) contains just two `<VirtualHost>`
blocks: `*:80` redirects everything to https (certbot-style `RewriteRule`); `*:443` terminates TLS
with certbot's certificate and proxies to `http://127.0.0.1:<APP_HOST_PORT>/`. It is an example —
you can also merge its directives into your existing per-site setup.

```bash
# 1. modules
sudo a2enmod ssl proxy proxy_http headers rewrite http2 setenvif
# 2. certificate FIRST, before enabling the site (the 443 vhost needs it);
#    certbot's Apache plugin answers the challenge itself
sudo certbot certonly --apache -d <DOMAIN>
# 3. site file: copy, then replace vpn.example.com with your DOMAIN and 11001 with your APP_HOST_PORT
sudo cp deploy/apache/vpn-control.conf /etc/apache2/sites-available/vpn-control.conf
sudoedit /etc/apache2/sites-available/vpn-control.conf
# 4. enable
sudo a2ensite vpn-control && sudo apachectl configtest && sudo systemctl reload apache2
```

Renewal is automatic via certbot's systemd timer; the Apache plugin reloads Apache after each
renewal (`sudo certbot renew --dry-run` to test).

Recommended globally, in `/etc/apache2/conf-available/security.conf`: `ServerTokens Prod` and
`ServerSignature Off` (Apache adds its own `Server: Apache` header; this keeps it minimal).

### 7. First login

Open `https://<DOMAIN>/`, click **Sign in**, authenticate at Keycloak (with your second factor).
You should see the dashboard with the ingress status. "Your account lacks the required role" means
the `vpn-admin` role is missing from the access token — see docs/keycloak.md.

### 8. Import the subscription into a client

Dashboard → *Subscription* → **Show** → scan the QR code with the phone (or copy the URL).

- **Hiddify**: `+` → *Scan QR code* (or *Add from clipboard*). Pick a profile, connect.
- **v2rayNG**: menu → *Subscription group setting* → `+` → paste URL → save →
  *Update subscription*. (v2rayNG supports VLESS+REALITY and SS-2022; Hysteria2 needs a recent
  version.)

After every IP rotation the clients pick up the new address on their next subscription update
(`SUB_UPDATE_HOURS`, default 1 h) or immediately when you press "update" in the client.
**Treat the subscription URL like a password.**

## Operations

| Task | How |
|---|---|
| Rotate the ingress IP | Dashboard → **Rotate IP** (cooldown `ROTATE_COOLDOWN_S`). Then update the subscription in your clients. |
| Ingress range blocked / move region | `deploy/aws/rebuild-lightsail.sh --region <new>` (step 5), then `docker compose up -d --force-recreate app` and update the subscription in your clients. |
| Your SSH IP changed | re-run `deploy/aws/setup-lightsail.sh` (refreshes the firewall). |
| Logs | `docker compose logs -f app` (rotated: 3 × 10 MB); Apache: `/var/log/apache2/` (the vhost's access log replaces the URL of `/s/`, `/i/` and `/auth/callback` requests with a redacted line). Tokens and token paths are never logged. |
| Status | `docker compose ps`; the app's `/healthz` is used by the container healthcheck. |
| Backup | `.env` (encrypted, offline — e.g. password manager) is all you need to rebuild. Optional: the `app_state` volume (event log, burned IPs) and `/etc/letsencrypt` (certificates; can be re-issued with certbot if lost). |
| Upgrade | `git pull`, set `VPN_CONTROL_IMAGE` in `.env` to the new `sha-<commit>` tag, then `docker compose pull && docker compose up -d`. Roll back by setting the previous tag. Review the diff first (including `deploy/apache/vpn-control.conf` against your installed site file). Apache and certbot are updated by the host's package manager. |
| Rotate secrets | See [docs/security.md → Secret rotation](docs/security.md#secret-rotation). |
| Update sing-box on the ingress | bump `SING_BOX_VERSION` + checksums in `bootstrap.sh`, re-run it on the ingress. |
| Ingress stopped reporting | *Ingress health* shows the last report; on the ingress: `systemctl status sing-box-report.timer`, `journalctl -u sing-box-report -n 20`. A report needs the control plane reachable from the ingress. |
| Debug a connection problem | *Ingress health* → log level `info` for 30 min, reproduce, read *Ingress log* (filter e.g. `reality` or your client's IP), then *Back to warn now*. |
| Certificates | Renewed automatically by certbot's systemd timer (`systemctl list-timers | grep certbot`); Apache is reloaded after renewal. |
| Stop everything | `docker compose down` (volumes are kept; `down -v` deletes the state). Optionally `sudo a2dissite vpn-control && sudo systemctl reload apache2`. |

### Container image

The image is built by GitHub Actions ([.github/workflows/image.yml](.github/workflows/image.yml)) on
every push to `main` and every `v*` tag, and published to GitHub Container Registry:

| Tag | Meaning |
|---|---|
| `ghcr.io/kmodexc/aws-vpn-orchestrator:sha-<short commit>` | exactly that commit — **use this in production** |
| `…:latest` | newest build of `main` |
| `…:1.2.3`, `…:1.2` | release tag `v1.2.3` |

The server only pulls; it never compiles. (The Rust build needs more than 3 GB RAM — on a small
VPS that starves the host.) The image contains no secrets: everything comes from `.env` at runtime.

**Private repository / private image.** If the repository (and the package under *Packages →
aws-vpn-orchestrator → Package settings*) is private, the server has to log in to GHCR once with a
read-only token: GitHub → *Settings → Developer settings → Personal access tokens (classic)* → a
token with only the `read:packages` scope, then on the server

```bash
docker login ghcr.io -u <github-user>     # paste the token as password; stored in ~/.docker/config.json
docker compose pull
```

The attestation step below only runs while the repository is public (GitHub offers artifact
attestations for private repositories only on Enterprise Cloud).

Each pushed image carries a signed build-provenance attestation. To check that an image was built
by this repository's workflow before deploying it:

```bash
gh attestation verify oci://ghcr.io/kmodexc/aws-vpn-orchestrator:sha-<commit> --repo kmodexc/aws-vpn-orchestrator
```

Building locally still works (`docker compose build`, tagged with the same name). On a host with
little RAM, limit Cargo to one job and cap the builder, so a failing build cannot freeze the host:

```bash
docker buildx create --name lowmem --driver docker-container --driver-opt memory=3g --driver-opt memory-swap=3g
CARGO_BUILD_JOBS=1 BUILDX_BUILDER=lowmem docker compose build
```

### Protocol settings at runtime

The dashboard's **Protocol settings** card (API: `GET/PUT/DELETE /api/settings`) changes, without a
restart:

| Setting | Effect |
|---|---|
| REALITY camouflage target (`reality_sni`) | the TLS site VLESS-REALITY impersonates; pick a real TLS 1.3 site that is reachable, and not blocked, where you are |
| Hysteria2 on/off, server name, **Salamander** obfuscation | Salamander makes the UDP packets stop looking like QUIC (needs a client that supports it, e.g. Hiddify) |
| Shadowsocks on/off | Shadowsocks is easy to detect as fully encrypted traffic; where censorship is strong, keep it off |

`.env` (`REALITY_SNI`, `HY2_SNI`, `HY2_ENABLED`, `HY2_OBFS`, `SS_ENABLED`) provides the defaults;
a change in the UI overrides them until *Reset to .env*. The ingress picks a change up within
10 minutes (it pulls its config on a timer); clients pick it up on their next subscription
refresh. VLESS-REALITY is always on. Ports stay in `.env`, because changing one also needs the
Lightsail firewall and the ingress' ufw. Every change is recorded in the event log.

### Ingress health and logs

The ingress reports to the control plane once a minute (`sing-box-report.timer`, installed by
`bootstrap.sh`): active connections, traffic, sing-box version and uptime, plus the journal
lines of `sing-box.service` since its last report. The dashboard shows this in two cards:

- **Ingress health** — last report (a warning after 25 minutes without one), connections,
  traffic of the last 24 h, version/uptime, current log level. Here an admin can raise the
  sing-box log level (`info` or `debug`) for 1–60 minutes; it reverts to `warn` on its
  own. The ingress applies the change within about a minute (the report reply tells it to
  re-pull its config), as it does for the protocol settings. **Every config change restarts
  sing-box on the ingress** (it has no live reload): active connections drop for a few seconds,
  also at the automatic revert. Clients reconnect by themselves.
- **Ingress log** — live tail of the reported lines with a filter. At `warn` only problems
  appear. **At `info` and above every connection is logged with the client's address and its
  destination**, i.e. the browsing activity of everyone using the VPN — which is why the level
  is timed and why the control plane keeps these lines in memory only (last 2000 lines, gone on
  restart, discarded one hour after debug logging ends, never in `state.json` or the app's own
  logs).

Counters are read from sing-box's Clash-compatible API on the ingress, bound to `127.0.0.1` with
a secret derived from `INGRESS_TOKEN`; no new port is opened, and the served config rejects
proxied connections to private and loopback addresses, so VPN users cannot reach that API (or
the VPC) through the tunnel. Only the ingress talks to the control plane, never the other way
round.

**Ingress created before this existed?** Install the reporter by re-running the bootstrap script
on it once (idempotent; SSH is open from the IP you ran `setup-lightsail.sh` from):

```bash
scp -i LightsailDefaultKey-<region>.pem deploy/ingress/bootstrap.sh ubuntu@<ingress-ip>:
ssh -i LightsailDefaultKey-<region>.pem ubuntu@<ingress-ip>
read -rs -p 'INGRESS_TOKEN: ' INGRESS_TOKEN; echo          # from .env, never on a command line
export INGRESS_TOKEN CONTROL_PLANE_URL=https://<DOMAIN> SSH_ALLOW_FROM=<your-ip>/32
sudo --preserve-env=INGRESS_TOKEN,CONTROL_PLANE_URL,SSH_ALLOW_FROM bash bootstrap.sh
unset INGRESS_TOKEN
```

A minute later the health card shows the first report. New ingresses (`setup-lightsail.sh`,
`rebuild-lightsail.sh`) get the reporter automatically.

### What anonymous visitors see

Nothing of the app. Without a session, every page redirects to the Keycloak sign-in, every file
(`/assets/*`, `/favicon.svg`, …) is a plain 404, and every `/api/*` path answers the same 401,
whether it exists or not. The page title and icon are a neutral "Console". To keep the sign-in
itself neutral, see [docs/keycloak.md → Keep the sign-in neutral](docs/keycloak.md#keep-the-sign-in-neutral).

### Reproducible images

Base images are pinned by tag (`node:24-bookworm-slim`, `rust:1-bookworm`,
`gcr.io/distroless/cc-debian12:nonroot`). For tamper-evident builds pin them
by digest — see the header of the [Dockerfile](Dockerfile).

## Local development

The backend insists on an `https` `PUBLIC_BASE_URL` and sets `Secure`, `__Host-` cookies, so the
easiest local setup is a tiny HTTPS front door with a locally-trusted certificate:

```text
browser ──https://localhost:8443──► local TLS proxy ──► Vite :5173 ──(/api /auth /s /i /healthz)──► backend :8080
```

1. **Keycloak**: create a separate *dev* client (never reuse the production client) with redirect
   URI `https://localhost:8443/auth/callback` and post-logout URI `https://localhost:8443/`.
2. **Backend** with the fake provider (no AWS needed):

   ```bash
   cd backend
   (umask 077; cargo run -- gen-env > ../.env.dev)     # throw-away secrets, git-ignored
   set -a; . ../.env.dev; set +a
   export PROVIDER=fake LOG_FORMAT=pretty RUST_LOG=debug \
          BIND_ADDR=127.0.0.1:8080 STATE_DIR="$(mktemp -d)" STATIC_DIR=../frontend/dist \
          DOMAIN=localhost TRUST_PROXY_HEADERS=false \
          PUBLIC_BASE_URL=https://localhost:8443 \
          OIDC_ISSUER_URL=https://auth.kmode.dev/realms/<realm> \
          OIDC_CLIENT_ID=vpn-control-dev OIDC_CLIENT_SECRET=<dev client secret>
   cargo run -- serve
   ```

   `PROVIDER=fake` keeps everything in memory and hands out addresses from 203.0.113.0/24; it logs
   a loud warning — never use it in production. With the fake provider the `AWS_*` values may stay
   empty. `DOMAIN` must equal the host of `PUBLIC_BASE_URL` (`localhost`).
   `TRUST_PROXY_HEADERS=false` overrides the
   `true` that `gen-env` writes for the compose deployment — keep it false whenever the app is
   reachable directly.
3. **Frontend**:

   ```bash
   cd frontend
   npm ci
   npm run dev        # Vite on 127.0.0.1:5173, proxies /api /auth /s /i /healthz to :8080
   ```

4. **HTTPS front door**: any local TLS-terminating reverse proxy on `https://localhost:8443` that
   forwards to `127.0.0.1:5173` works — e.g. a local Apache vhost like the production one, with a
   certificate from [mkcert](https://github.com/FiloSottile/mkcert)
   (`mkcert -install && mkcert localhost`).

   Open `https://localhost:8443/`.

Tests and builds:

```bash
cd backend  && cargo test && cargo clippy --all-targets -- -D warnings
cd frontend && npm test && npm run build      # → frontend/dist
```

Never commit `.env` / `.env.*` — they are git-ignored and docker-ignored.

## Security

This application is built to be exposed on the public internet. Highlights:

- OIDC Authorization Code + PKCE (S256) as a confidential client; tokens stay server-side;
  `__Host-` cookies (HttpOnly, Secure, SameSite=Lax); CSRF token **and** Origin check
- role-based access (`vpn-admin`), Bearer JWT validation with strict algorithms/issuer/`azp`
- strict CSP and security headers, no CORS, no server fingerprint
- per-IP rate limiting and a failure limiter; generic 404 for wrong path tokens
- least-privilege IAM; container non-root, read-only, no capabilities; app port bound to localhost only
- secrets only in `.env` (mode 0600), never logged, never in an image

Threat model, controls, secret rotation and incident handling: **[docs/security.md](docs/security.md)**.
Report security issues privately to the maintainer, not via public issues.
