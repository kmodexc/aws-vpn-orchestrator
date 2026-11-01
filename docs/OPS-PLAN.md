# Final plan: debug the VPN from a phone, contain one compromised component, and rebuild any part

Line numbers refer to the working tree on 2026-11-01, including the uncommitted telemetry work. I re-checked these against the files: `bootstrap.sh:48,63,80,121,135,148,152,506,510,526,566`, `token_routes.rs:68-75`, `http/rate_limit.rs:27-32,199,212`, `settings.rs:89-90`, `api.rs:451,469`, `lib.sh:15,178,260-282,328-359`.

---

## 0. Do this first: diagnose today's incident without SSH (30 min)

Do these steps in this order, before any Stop/Start or rebuild. Docker keeps only 3 log files of 10 MB each (`docker-compose.yml:21-25`) and logrotate rotates the Apache logs, so the evidence is about to disappear.

1. **Save the evidence.** On the VPS:
   ```
   docker compose logs app > ~/incident-app.log
   cp /var/log/apache2/*access* ~/
   ```
2. **Check the token.**
   ```
   grep -c "wrong token" ~/incident-app.log
   ```
   This line is logged at `token_routes.rs:73`. If it appears, the token on the ingress does not match the VPS. `setup-lightsail.sh` takes `INGRESS_TOKEN` from the **laptop** `.env` (`lib.sh:178`), while the VPS `.env` may have been made separately with `gen-env`. A mismatch gives you exactly what you see:
   - every `/i/` request returns 404
   - the fetcher exits through `keep_old` with no previous config
   - `ConditionPathExists` (`bootstrap.sh:506`) then stops sing-box from starting, so ports 443 and 8443 refuse connections.
   
   "Connection refused" does **not** prove the bootstrap died before ufw: ufw sends a reset for an allowed port that nothing listens on.
3. **Find the ingress IP in the Apache access log.** The `/i/` paths are redacted, but the client address (`%h`) and status (`%>s`) are kept (`vpn-control.conf:44`).

   | What the log shows for the ingress IP | Cause |
   |---|---|
   | No requests | Never fetched (bootstrap died, or a DNS or TLS problem) |
   | 404 | Wrong token |
   | 429 | Rate limiter |
   | 200 | Fetch works, so the fault is in sing-box |

4. Only if the cause is still unclear: in the Lightsail console, add `lightsail-connect` to port 22, open browser SSH, then run:
   ```
   sudo tail -100 /var/log/vpn-control-bootstrap.log
   sudo journalctl -u sing-box-config -n 50
   ```
5. Fix it. If the token is wrong, put the correct token in the VPS `.env`, or rebuild with the token from the VPS. Otherwise, rebuild after PR 1 and PR 2. The live box also predates the reporter (README:411-412), so it has to be rebuilt once in any case.

---

## 1. What is wrong today

### The incident: possible causes, most likely first
1. **Token mismatch** between the laptop `.env` and the VPS `.env` (see §0).
2. **The bootstrap died early.**
   - `set -euo pipefail` (L48) plus `apt-get update` (L121) with no wait for the dpkg lock. On first boot, unattended-upgrades and cloud-init hold that lock.
   - `version | head -n1` (L152) can abort with SIGPIPE under pipefail.
3. **The rate limiter blocked the ingress** (see A2 in §1).

### Why you could not see it
- **Nothing on the ingress reports before L566.** The bootstrap log stays on the box (`lib.sh:180`). The report schema (`telemetry.rs:25-45`, `deny_unknown_fields`) has no field for a bootstrap stage.
- **The control plane measures nothing itself.** `/api/status` returns only the AWS state (`orchestrator.rs:106-118`).
- **Wrong-token hits are only an info log line.** They are not counted anywhere and not shown in the UI.
- **Some states look identical.** Telemetry is memory-only (`app.rs:76`), so "never reported", "control plane just restarted" and "still booting" look the same. The stale warning appears only after 25 minutes (`IngressCard.tsx:19`).
- **No alert is ever sent.**
- **Start/Stop cannot repair a failed first boot,** because cloud-init runs user-data only once. Rebuilding needs a laptop with admin AWS credentials and a manual copy of `.env`.

### Design gaps
- **The ingress trusts the control plane completely.** Any config that passes `sing-box check` is installed (`bootstrap.sh:221-235`).
- **The privacy limits are enforced only on the control plane** (`app.rs:92`).
- **Privacy bug in the uncommitted work.** `schedule_purge` is called only from `api.rs:451,469`. If the control plane restarts during a debug window, nothing ever purges the logs. `MAX_DEBUG_MINUTES` is 24 h and `trace` is allowed (`settings.rs:89-90`).
- **A poisoned `state.json` survives a redeploy.** `debug_log` and `ProtocolSettings` are not re-validated on load.
- **sing-box `warn` lines contain client IPs, and the reporter ships them verbatim** (L278). The journal is persistent. clash_api `/connections` is written to a disk-backed `/tmp` every minute.
- **The IMDS block covers only the sing-box UID** (L395-396). Any other non-root process can read user-data, which includes the token.
- **The failure limiter can lock out the ingress itself.** `/s/` and `/i/` share one bucket and one failure table per IP (`http/rate_limit.rs:27-32`), and `blocked()` is checked before the token.
   - Clients that refresh `/s/<old SUB_TOKEN>` *through the VPN* after a token rotation produce 404s, and all of them come from the ingress IP.
   - After 10 such failures the ingress is blocked for 10 minutes, so it cannot fetch the config that contains the new credentials.
- **Unattended-upgrades reboots at 04:30 UTC** (`bootstrap.sh:63`). That is 12:30 in China, in the middle of your day.
- **`INGRESS_TOKEN` is a static bearer token and is never rotated** (`rebuild-lightsail.sh:11`).
- **Recovery and supply chain:**
   - There is no script to recreate the VPS, and backups are manual.
   - The image tag `:latest` is mutable and compose falls back to a local build (`docker-compose.yml:35-37`).
   - `security.md:34-35` declares a compromise of the VPS or Keycloak out of scope.

---

## 2. Security model when one component is compromised

| Compromised | What the attacker gets today | What this plan changes |
|---|---|---|
| **App container** | All `.env` secrets; can push any config that passes `sing-box check` (reroute traffic, open proxy, permanent debug logging); redirect the subscription; stop the instance or release static IPs; poison `state.json` | **Ingress policy gate** (P6) and **ingress debug budget** (P7, default `LOG_MAX=warn`); re-validation on load; AWS key bound to `aws:SourceIp` in its own AWS account. The subscription redirect remains a residual risk. |
| **VPS host root** | All of the above, plus the TLS key, Apache logs and live `state.json` events | Ingress alerts to healthchecks.io whose URL the VPS never holds; CloudTrail and CloudWatch alarms; image pinned by digest; encrypted write-only backups; IPs in events truncated **when written**; `rotate-secrets.sh`. Do not co-host the WireGuard exit or Keycloak on this VPS. |
| **Ingress root** | Proxy secrets, live traffic, `INGRESS_TOKEN`, forged telemetry | TCP/TLS probe from the control plane, which the ingress cannot forge; UI labels data as "reported by ingress" or "measured"; rebuild with `--rotate-token`; volatile sing-box journal; source-IP check on `/i/*` (alert first, enforce later). |
| **Keycloak / IdP** | Full admin API, including debug surveillance | `OIDC_ADMIN_SUBS` allowlist, `aud` check, debug capped at 60 min with no `trace`, ingress budget plus an out-of-band alert, `ADMIN_READONLY` kill switch. |
| **GitHub / GHCR** | Code execution on the VPS at the next pull; admin AWS access at the next deploy script run | Digest-only compose; `update.sh` verifies the attestation; scripts refuse unsigned tags. The **signer key and release hashes live in the password manager**, not on GitHub, otherwise the check is circular. |
| **AWS app key** | Denial of service; follows rotated IPs (read calls) | `aws:SourceIp` covering VPS IPv4 **and** IPv6; dedicated member account; drift alert; **CloudTrail → CloudWatch Logs metric filter** for `vpn-control` calls from any IP other than the VPS, which covers read calls such as `GetInstance`/`GetStaticIp` that EventBridge does not see. |
| **DNS, registrar or CA** *(new)* | Can obtain a valid certificate, act as the control plane, collect `INGRESS_TOKEN`, push new users and keys inside the policy gate, redirect clients | Registrar lock and 2FA; CAA record with `accounturi`; DNSSEC if the registrar supports it; certificate and domain expiry monitoring. SPKI pinning on the ingress is optional (P10) and requires `certbot --reuse-key` plus a backup pin. |
| **AWS console identity** *(new)* | Every break-glass path | One named admin role; never log in as root; phishing-resistant MFA plus a second MFA device; root credentials kept offline to close or recover the account. |
| **Client phone or subscription leak** | Proxy use, the shared SS-2022 PSK, following IP rotations | SS-2022 off by default; runbook rotates `SUB_TOKEN` **and** the credentials. |
| **Leaked `HC_PING_URL` or ntfy token** | Fake "ok" pings, alert spam | The probe and drift paths still show the truth; rotate the URL. |

**Invariants:**
- The control plane gets no SSH, SSM, `GetInstanceAccessDetails`, `CreateInstances`, user-data or snapshot rights.
- The control plane has exactly **two** channels to the ingress, both bounded on the ingress:
   - the `config_stale` refetch, limited by the policy gate
   - the `X-Debug-Until` header, limited by the budget and `LOG_MAX`
- Every channel from the ingress to the control plane is typed, bounded, kept in memory only, and rendered as text.
- Rebuild rights stay with the operator's MFA-protected AWS identity.

---

## 3. The solution, in priority order

### P1. A bootstrap that cannot fail silently and retries itself

**User-data and stage 2** (this answers the size limit, B3, and the GitHub dependency at boot, B4). Measured today, the user-data is already 11,416 of 16,000 bytes, so the size check would fail around PR 7.

**What user-data contains:**
- a small wrapper
- `/etc/vpn-control/ingress.env` (mode 0600)
- **the SHA-256 of `stage2.tar.gz`**

**What stage 2 contains:** `bootstrap.sh`, the policy gate, the clamp, the unit files and the **pinned sing-box tarball**. It is published as a release asset and served from `/i/<token>/stage2.tar.gz`. The SHA-256 is pinned by the operator, so where the file comes from does not affect trust, and github.com is no longer needed at boot.

**`vpn-bootstrap.service`:**
- `Type=oneshot`
- `After=network-online.target cloud-final.service`
- `ConditionPathExists=!/var/lib/vpn-control/bootstrap.ok`
- `Restart=on-failure`, `RestartSec=90`, `StartLimitBurst=8` within `StartLimitIntervalSec=3600`
- `StandardOutput=append:/var/log/vpn-control-bootstrap.log`

The wrapper runs `systemctl enable` and then `systemctl start --no-block`. It never calls `cloud-init status --wait`. When the start limit is exhausted, only Stop/Start or `reset-failed` retries, and the banner says so.

**Changes in `bootstrap.sh`:**
- **Error reporting.** Set `set -Eeuo pipefail` and install **one** `trap on_exit EXIT`. It reads `$?` and `$STAGE`, cleans up `workdir`, and on a non-zero exit runs `phone_home failed`.
   - An ERR trap would miss `die()`, which calls `exit 1` (L80).
   - The `workdir` EXIT trap at L135/L148 would overwrite it.
- **Stages:** `validate | packages | singbox | units | first_fetch | firewall | ssh | done`.
- **Packages.** Run `dpkg -s` for each of ca-certificates, curl, tar, ufw, nftables and python3, and **skip apt entirely** when all are present (they are in the Lightsail Ubuntu 24.04 image). Otherwise use `-o DPkg::Lock::Timeout=600` with 3 tries and `dpkg --configure -a` before each retry. **Never stop `apt-daily-upgrade`**: interrupting dpkg in the middle breaks every later apt call.
- **L152:** append `|| true`.
- **Report timer:** enable it immediately after the unit files are written, not at L566.
- **Memory:** `pick_bundle` (`lib.sh:141`) requires at least 1 GB. No swapfile, because unencrypted swap would leak memory to disk.
- **Reboot window:** `AUTO_REBOOT_TIME` defaults to `19:00` UTC (03:00 in China) and is set in `ingress.env`. Report `reboot_required` (P2).
- **IMDS:** after the bootstrap, block IMDS for **every UID except 0**.
- **Phone-home content:** stage, exit code, and a tail built from an **allowlist** of lines matching `^(E:|W:|dpkg|apt|curl:|sing-box|systemd)`.

**Effort:** about 1.5 days.

### P2. Report schema v2, diagnostics ring, persisted last-seen, privacy fixes
- **New schema fields**, all optional:
   - `kind: report|bootstrap`
   - `bootstrap: {stage, status, exit_code}`
   - `units`, `listening` (from `ss -Hltnu`), and `fetch: {last_ok_at, result}` with result one of `ok|download_failed|http_4xx|check_failed|policy_reject|no_previous`
   - `effective_log_level`, `local_override`, `gate_version`, `bootstrap_sha`, `reboot_required`
   - `config_sha256` is optional when `kind=bootstrap`.
- **Version skew (B8).** The control plane accepts v1 and v2. If a v2 report gets a 400, the reporter resends it as v1. Deploy order: control plane first, then the ingress.
- **Diagnostics ring** of 300 lines from `journalctl -p warning` for `sing-box-config`, `sing-box-report` and `vpn-bootstrap`. It is not subject to the debug purge and never contains ufw lines.
- **Reporter:**
   - reads clash_api through a pipe, so nothing is written to `/tmp`
   - **redacts client IPs in `warn`/`error` lines to /24 or /48** unless a debug grant is active
- **Persisted record:** `ingress_last_seen` in `state.json`, written at most every 5 minutes. **Events are written with IPs already truncated.**
- **Fixes on load:**
   - in `AppState::new`, re-arm `schedule_purge` when `debug_log` is set
   - drop `debug_log` if its `until` is more than 3600 s away
   - re-validate `ProtocolSettings`
   - if a `state.json` write fails, fail the request instead of updating memory only

**Effort:** about 2 days.

### P3. Probe from the control plane and a single health verdict
**`probe.rs`** runs every 60 s (±15 s jitter), and once 30 s after any start or rotation:
- a TCP connect to `VLESS_PORT`/`SS_PORT`
- a TLS 1.3 ClientHello using the REALITY SNI

If **AWS is unreachable or access is denied, it keeps probing the last known IP** (B18), so the dashboard does not go blind when you deactivate the key as a containment step.

**Wrong-token counter on `/i/*`:** timestamp, count, and whether the source IP equals the ingress IP reported by AWS.

**`health.rs`:** a pure function returning `verdict → {level, reason enum, next_action enum}`, covered by a table test.

| Condition | Verdict | Next action |
|---|---|---|
| stopped | `stopped` | `start` |
| running < 10 min, bootstrap not ok | `booting(stage)` | — |
| bootstrap failed | `down` | `stop_start`; the same stage failing twice → `rebuild` |
| wrong-token hits from the ingress IP | `down/token_mismatch` | `rebuild_with_current_token` |
| TCP refused or timed out twice | `down` | `stop_start` → `rebuild` |
| TCP ok, TLS fails | `degraded/reality_target` (the `handshake.server` site may be down) | `change_sni` |
| AWS API denied or unreachable | `degraded/aws_denied` (shown separately, B17) | `check_aws_key` |
| no report for > 180 s while the control plane has been up > 180 s | `degraded/silent` | — |
| config hash mismatch for > 3 min, `local_override=none` | `degraded/refused_config` | — |
| probe ok but the ingress reports sing-box failed | `down/mismatch` | — |
| a stale A/B slot exists | `info/old_slot` | `delete_old_slot` |

- `next_action` is an enum; the frontend maps it to fixed text.
- `/api/me/health` returns only `{up, ip_changed_at}`.
- Fix `orchestrator.rs:86-99`: do the AWS call outside the cache mutex.

**Effort:** about 1.5 days.

### P4. Phone-first dashboard
- `HealthBanner` comes first and shows a colour, the reason, one button, and the age of the data.
- `IngressCard` sits directly under it. It shows the stage timeline and tail, the served and running hashes, the fetch result, unit states, listeners, the probe result and the wrong-token count. Every value is tagged "reported by ingress" or "measured by control plane".
- Delete `STALE_AFTER_S`.
- `LogsCard` opens automatically when the verdict is red, gets a Diagnostics tab, and asks for confirmation before Clear.
- Debug: default 15 min, maximum 60 min, no `trace`. Show the remaining ingress budget, or "remote debug disabled (LOG_MAX=warn)".
- "Copy diagnosis" copies an enums-only summary.
- `UserHome` gets an up/down indicator and an "IP changed" notice.

**Effort:** about 1.5 days.

### P5. Out-of-band alerts
- **Path A, from the VPS.** `notify.rs` posts to ntfy with a token. It alerts on:
   - a red verdict for more than 3 min, and on recovery
   - AWS drift
   - every admin mutation
   - the first login of a new admin `sub`
   - token mismatch

  Messages are built from enums only and contain no IPs.
- **Path B, from the ingress** (`HC_PING_URL` is never in the VPS `.env`):
   - a heartbeat every 5 min, sent only when sing-box is active and listening
   - `/fail` on bootstrap failure, policy reject, and every debug grant and expiry, **rate-limited to one ping per state change** (B6)
- **Path C, from AWS** via `deploy/aws/monitoring.sh --region R`, which `rebuild-lightsail.sh` calls on every region move:
   - an EventBridge rule on mutating Lightsail calls
   - **a CloudTrail trail to CloudWatch Logs, with a metric filter for `userName=vpn-control` from a source IP that is not the VPS, and for `AccessDenied`**
   - an alarm sending to SNS by email and SMS
   - Budgets on by default
   - a host cron that checks `/healthz` **and certificate expiry (alert at 14 days)** and pings a second healthchecks check
- **Delivery from China.** SNS starts in the SMS sandbox, so verify your number. Use a non-Google mail provider; Telegram, FCM and Gmail are blocked in China. Keep a roaming eSIM as a fallback. **Run a quarterly alert drill** (P11).

**Effort:** about 1 day.

### P6. Policy gate on the ingress
`/usr/local/sbin/sing-box-policy` runs as `python3 -I` and uses only the standard library. Its parameters come from `/etc/vpn-control/policy.json`, which is written from `ingress.env` and never fetched. It runs after `sing-box check` and before `mv`. The served bytes are installed unmodified.

It is an **exact allowlist**. A config is accepted only if all of these hold:

| Section | Rule |
|---|---|
| top-level keys | a subset of `log`, `dns`, `inbounds`, `outbounds`, `endpoints`, `route`, `experimental` |
| `log` | exactly `{level, timestamp}` |
| `dns` | exactly the local resolver |
| inbounds | allowlisted key set per type, on the pinned ports. No `masquerade`, `detour`, certificate or key paths, or `sniff_override_destination` |
| REALITY | `handshake.server == server_name`, a public DNS name, port 443 |
| outbounds | exactly `direct`, plus `block` if present |
| `endpoints` | empty, or exactly the pinned `wg-exit` |
| `route.rules` | exactly `[resolve, ip_is_private → reject]`; `final` is `direct` or the pinned `wg-exit` |
| `experimental` | exactly the loopback clash_api |
| `log.level` | `warn` or `error` unless a grant is valid (P7) |

**On rejection (B6):**
- keep the old config, **and clamp the running config's level to warn**
- store `rejected_sha`, and do not refetch the same served hash
- report `policy_reject`, and ping `/fail` once

**Version skew (B7):**
- Reports carry `gate_version`.
- A Rust test runs the repo's **and the previous release's** validator against every combination of settings the generator can emit.
- Document that bumping the gate requires a rebuild.

**Effort:** about 2 days.

### P7. Privacy enforced on the ingress
1. **Debug grant.** `token_routes.rs` sends `X-Debug-Until`. The fetcher accepts a level other than warn only if all of these hold:
   - the grant ends at most 3600 s from now
   - the rolling total stays at or below 2 h per 24 h
   - `LOG_MAX` allows it

   **`LOG_MAX` defaults to `warn`, so remote debug is off.** Enabling it means editing `ingress.env` and rebuilding. Even when enabled, this is a **daily allowance**, not a one-time cap: a persistent attacker gets 2 h of logs every day, and every grant alerts through path B.
2. **Expiry.** The reporter re-fetches when a grant expires, or clamps locally if the fetch fails. In addition, `sing-box.service` gets **`ExecStartPre=+/usr/local/sbin/sing-box-clamp`**. The `+` prefix is required because the unit runs as `User=sing-box` with `ProtectSystem=strict` (L510, L526).
3. **Volatile journal.** `LogNamespace=sing-box` with `journald@sing-box.conf` set to `Storage=volatile`, `RuntimeMaxUse=16M`, `ForwardToSyslog=no`.
   - **Every command in the runbook and README uses `journalctl --namespace=sing-box`.** Plain `-u sing-box` shows nothing and is misleading.
   - Claim this precisely: "no connection data reaches disk". Fetcher and reporter lines still reach the persistent system journal.
4. **Control plane:** maximum 60 min, no `trace` (PR 1).
5. **SS-2022** is off by default.

**Effort:** about 1.5 days.

### P8. Ingress replacement from a phone
- **Slots.** `.env` gets `INGRESS_INSTANCES=ap-northeast-1/vpn-ingress-a,ap-northeast-1/vpn-ingress-b`. The region is part of each entry, so **a region move needs no edit to `AWS_REGION`** (D2).
- **Active slot.** The app treats as active the slot that any `vpn-orchestrator-*` static IP is attached to (rotation renames static IPs, `lib.sh:275`).
- **IAM.** The policy pins instance **resource IDs** (`lib.sh:330-333`), so the rebuild always re-pins the policy with the operator's admin identity. There is no retarget API.

**`rebuild-lightsail.sh` must not need `.env` and must not write files (B9):**
- Split `ensure_iam` into:
   - `repin_policy`, used by rebuild
   - `issue_key`, used only by setup; it never writes `$HOME/.env` in CloudShell
- Region, slot and ports are passed as flags.
- Set `HISTFILE=/dev/null`.
- Read `ingress.env` as **one base64 line** with `read -rs` (B10). A multi-line paste would run as shell commands and land in the CloudShell history.

**Steps:**
1. **Check the signature.** `git verify-tag` against `allowed_signers`, which is **imported from the password manager**.
2. **Create the free slot.**
3. **Wait for it.** Up to 15 min for TCP and TLS to answer on its temporary IP.
4. **Move the static IP.** Explicit `DetachStaticIp` → `AttachStaticIp` (B12), then probe again on the static IP.
   - **`--new-ip`** gives the new box a fresh IP instead. It is the default when the verdict was "IP blocked".
5. **Stop the old slot.** Do not wait for deletion (CloudShell times out). **The next rebuild refuses to run while a stale slot exists**, and the dashboard shows `info/old_slot` (B13).

**Flags:** `--rotate-token` (rotate the token first), `--region R`, `--new-ip`.

**SSH:** replace the operator's /32 on port 22 with the `lightsail-connect` alias.

**Rejected alternatives:**
- delete-before-create: you can end up with zero ingresses
- a Lambda broker: downgrade and enrollment races
- a GitHub-OIDC rebuild role: effectively admin, and puts secrets in GitHub

**Effort:** about 2.5 days.

### P9. VPS recreate kit, digest-pinned image, backups
- **`provision.sh`** (idempotent) installs and configures:
   - docker
   - Apache with an `ErrorLogFormat` that does not include the request line, so tokens do not leak into the error log
   - certbot with **`--reuse-key`**, to allow SPKI pinning later
   - ufw and unattended-upgrades
   - `.env` with mode 0600
   - the healthchecks/cert cron and the backup timer
   - an nft policy for wg0
- **Compose:**
   - `${VPN_CONTROL_IMAGE:?}` must be a `@sha256:` digest
   - `pull_policy: never`
   - `build:` moves to `docker-compose.build.yml`
- **`update.sh <digest>`:** pull, `gh attestation verify`, save the old digest to `.env.prev`, `up -d`. `--rollback` goes back.
- **`backup.sh`:**
   - encrypts `.env`, `state.json` and the vhost with `age -r` to your public key
   - uploads them to S3 with a **PutObject-only** key that lives on the host, not in the container
   - the bucket is versioned with a 30-day Object Lock
- **`restore.sh`:**
   - reads the age identity **from the terminal with `-s`, keeps it in memory only and never writes it to disk** (B15)
   - pins **the digest you pass**, never one from the bundle
   - refuses to reuse secrets unless you pass `--trust-backup`
- **`rotate-secrets.sh`** (D3):
   - generates every secret locally with `openssl` and `sing-box generate`, not with the image's `gen-env`
   - writes `.env.new`
   - prints only `INGRESS_TOKEN` and the subscription QR
   - swaps the files and runs `up -d`

**Effort:** about 2.5 days, including a restore drill.

### P10. Narrow AWS access, admin pinning, limiter, small fixes
- **AWS key:**
   - `aws:SourceIp` for VPS **IPv4 and IPv6**, tested once with a deliberately wrong IP
   - a dedicated member account
   - an SCP that denies `GetInstanceAccessDetails`, snapshots and port changes **to everyone except the named admin role**
   - the key stored in a Docker secret file
   - `rotate-key.sh`
- **Admin identity:**
   - `OIDC_ADMIN_SUBS` allowlist
   - `validate_aud=true` (`jwt.rs:219`)
   - optional `acr`/`amr` check
   - `ADMIN_READONLY` kill switch from `.env` and from a read-only host file
   - `POST /api/sessions/revoke-all`
   - session timeouts: 15 min idle, 4 h absolute
- **Limiter (A2):**
   - **never record failures from the current ingress IP** (known from AWS)
   - give `/i/` **its own bucket**
   - requests with a valid session or a valid ingress token are exempt from the block, without clearing the counter
   - `TRUST_PROXY_HEADERS=false` combined with a loopback bind becomes a startup error
   - table test: a `/s/` storm with an old token from the ingress IP while `/i/` keeps working
- **Source-IP check on `/i/*`:** alert first; `INGRESS_IP_BIND=true` enforces it later.
- **Optional:** SPKI pin on the ingress with `curl --pinnedpubkey` (current key plus a backup key).
- **Delete:**
   - the EC2 provider
   - `trace`
   - the 25-minute threshold
   - the SSH /32 rule
   - the out-of-scope line in `security.md:34-35`
- **Documentation drift:**
   - `security.md:46,98,113,138`
   - README:369,379,416 (use `--namespace`)

**Effort:** about 2 days plus AWS console work.

### P11. Tested recovery
`bootstrap-smoke.yml` runs on an `ubuntu-24.04` VM with systemd, against a fake control plane that serves stage 2 and the config. It asserts:
1. a `bootstrap ok` report arrives and port 443 is listening
2. with an apt shim that fails twice: two `failed@packages` reports, then `ok`
3. with a wrong token: no config is installed, and the fake control plane records the wrong-token hits
4. a stage-2 hash mismatch → `failed@validate`
5. each poisoned config fixture is rejected with its enum, and debug is clamped on reject
6. a debug grant expires offline, and the clamp survives a reboot
7. user-data stays under 16,000 bytes
8. the generator output passes both the current and the previous gate

`image.yml` runs before any push: tests, clippy, `cargo audit`, `npm test` and `npm audit`. Images are published only from signed `v*` tags.

Add a **quarterly drill**: trigger alert paths A, B and C, run one rebuild, and run one restore.

**Effort:** about 2 days.

---

## 4. Traveling runbook

**Always first:** read the alert, or open the banner and press its button.

**Clients time out**
1. `down/token_mismatch`: rebuild with the token from the VPS `.env` (CloudShell, step 3 under "Ingress never came up").
2. `down: probe refused`, or `failed@<stage>`: Stop, then Start. The bootstrap retries by itself, and the verdict should reach `ok` in 5–8 min. The same failure twice → rebuild.
3. `degraded/reality_target`: change the SNI in Settings.
4. `degraded/refused_config`: if you just changed settings, use Reset to `.env`. If you did not, go to **Suspected compromise**.
5. Verdict `ok` and probe green, but your client fails: go to **IP blocked**.

**Ingress never came up**
1. Stage `packages` or `singbox`: wait, because it retries every 90 s. Or Stop/Start.
2. No report at all after 10 min:
   - check the token counter in the IngressCard
   - otherwise use the Lightsail app's **Connect** (browser SSH):
     ```
     sudo journalctl -u vpn-bootstrap -n 100
     sudo tail -50 /var/log/vpn-control-bootstrap.log
     ```
   - to retry: `sudo rm -f /var/lib/vpn-control/bootstrap.ok && sudo systemctl reset-failed vpn-bootstrap && sudo systemctl start vpn-bootstrap`
3. Out of time: CloudShell, then:
   ```
   git clone --branch vX.Y …
   git verify-tag vX.Y     # allowed_signers pasted from the password manager
   ./deploy/aws/rebuild-lightsail.sh
   ```
   Paste the base64 `ingress.env` when asked. It takes 12–18 min.

**Control plane down**
- Nothing is urgent: the ingress keeps its last good config and any debug window expires locally.
- Then, over SSH: `docker compose logs --tail 80 app`, and `update.sh --rollback` if a deploy broke it.
- If the host is dead: a new VPS, then `provision.sh` (check its hash against the **password manager**), `restore.sh`, `update.sh <digest>`, DNS, and re-pin `aws:SourceIp`. 30–45 min. The VPN stays up throughout.

**IP blocked**
1. **Rotate IP.** Clients pick it up when they refresh the subscription.
2. Blocked again within hours: change the SNI, or enable HY2 with obfs.
3. A whole range is blocked: `rebuild-lightsail.sh --region ap-southeast-1 --new-ip`. No `.env` edit is needed, because the region is in `INGRESS_INSTANCES`.
4. Every new IP is blocked immediately: check the CloudTrail alarm for read calls from an IP other than the VPS. Treat it as a leaked key or subscription.

**Phone lost** (new). From a borrowed device:
1. AWS console with your second MFA device → Stop the ingress, deactivate the app key if needed.
2. Keycloak → sign out all sessions.
3. Later: `rotate-secrets.sh`, plus a rebuild with `--rotate-token`.

**Suspected compromise**
1. **Contain from the AWS console, not the dashboard:**
   - VPS, app or IdP suspected: power off the VPS. The ingress gate keeps protecting the ingress.
   - Ingress suspected: Stop the instance.
   - AWS key suspected: deactivate it. The probe keeps running.
   - Keycloak suspected: disable the user and sign out all sessions.
2. **Ingress compromise:** run `rebuild --rotate-token`, then `rotate-secrets.sh` on the VPS, then re-import the subscription QR on your devices.
3. **VPS or image compromise:** `restore.sh` **without** `--trust-backup`, a digest you verified, `rotate-key.sh`, a new Keycloak client secret, and revoke and reissue the certificate. Then do step 2.
4. Write down the cause in `docs/RUNBOOK.md`.

---

## 5. Full recreate

- **Ingress:** run `rebuild-lightsail.sh [--region] [--rotate-token] [--new-ip]` from a signed tag. Its only input is `ingress.env` as a base64 line. It never writes files and never touches the VPS. CI exercises this path.
- **VPS:** `provision.sh` → `restore.sh` → `update.sh <digest>` → DNS → re-pin `aws:SourceIp` and the WireGuard endpoint.
- **Keycloak:** keep it off this VPS, back up the realm export separately, and use the AWS console as the fallback when it is down.

**Backups**

| Item | Where |
|---|---|
| `.env`, `state.json` (IPs already truncated), vhost | age-encrypted, write-only S3 bucket with Object Lock; `.env` also as a password-manager note |
| `ingress.env` as base64 | Password-manager note |
| `allowed_signers`, release hashes for `provision.sh` and stage 2 | Password manager |
| age identity, AWS admin with **2 MFA devices** and offline root, VPS login and SSH key, GitHub recovery codes, healthchecks and ntfy logins, printed recovery codes | Password manager, a hardware key carried separately from the phone, and paper |
| Keycloak realm export | Separate, off-box |
| Billing (new) | A backup payment method and auto-renew at AWS, the VPS provider and the registrar; billing mail on a non-Google provider |
| Not backed up | Certificates (reissue them), telemetry and logs, ingress disks |

---

## 6. Not built, and residual risks

**Not built:**
- control-plane SSH, SSM, snapshots or user-data rights
- a remote command channel
- a reboot button
- a rebuild driven by the control plane
- auto-promotion, auto-rotation or auto-retirement of an ingress
- a public ingress health endpoint
- a subscription watcher on GitHub
- a break-glass local login
- a log SaaS
- a warm standby in a second region (deferred: it would cost only disk and is worth adding later)

**Residual risks:**
1. A compromised control plane holds the REALITY and HY2 private keys, so it can redirect clients through `/s/`. The fix is keys generated on the ingress (phase 4).
2. If you enable remote debug, it is a **daily** 2-hour allowance. Every grant alerts. The default `LOG_MAX=warn` forbids it.
3. `INGRESS_TOKEN` is still a static bearer token. Mitigations: source-IP alert or binding, `--rotate-token`, and the IMDS block for every UID except 0.
4. A compromised ingress can fake its reports and its heartbeat. Only the TCP/TLS probe is independent. HY2 health is taken on trust.
5. A GFW block cannot be seen from Germany.
6. A compromised control plane chooses `handshake.server`, within the DNS-name rules.
7. A GitHub compromise combined with your signature on a bad tag is still total. Review the `deploy/` diff before tagging.
8. Client credentials are shared by all devices.
9. A DNS or CA compromise is only mitigated, not eliminated, unless you enable SPKI pinning.
10. During a Keycloak outage you can see only the probe alerts, healthchecks.io and CloudTrail.

**Critic findings rejected or changed:**
- **"Pin the Let's Encrypt SPKI" as a requirement:** made optional. It locks the ingress out if the key changes during renewal. `--reuse-key` plus a backup pin makes it workable, but it is not in the critical path.
- **DNSSEC:** recommended only where the registrar supports it.
- Everything else was accepted.

---

## 7. Implementation order

| # | PR | Size |
|---|---|---|
| 0 | **Incident:** save the logs, check the token and the Apache status codes (§0), fix the token or rebuild | 30 min |
| 1 | `fix(privacy)`: re-arm the purge on startup, re-validate state on load, fail on failed writes, max 60 min, drop `trace`. **Limiter fix:** exempt the ingress IP, separate `/i/` bucket | S |
| 2 | `bootstrap`: stage 2 with pinned hash and mirrored sing-box, retry unit, EXIT-trap phone-home, skip apt when possible, reboot at 19:00 UTC, IMDS block for all UIDs; schema v1+v2 with `kind=bootstrap` | M |
| 3 | `rebuild`: A/B slots with region in each entry, `repin_policy`/`issue_key` split, base64 input, explicit detach and attach, `--new-ip`, refuse while a stale slot exists, `lightsail-connect`, signed tags. **Drill: replace the broken ingress** | M |
| 4 | `health`: probe (continues when AWS is unknown), wrong-token counter, verdict, banner, mutex fix, `ingress_last_seen` | M |
| 5 | `report v2`: units, listeners, fetch result, diagnostics ring, IP redaction, nothing in `/tmp`, `gate_version`, `reboot_required` | M |
| 6 | `alerts`: ntfy, healthchecks with `/fail` once per state change, `monitoring.sh --region` (EventBridge plus CloudTrail metric filter), certificate-expiry cron | S–M |
| 7 | `policy gate`, clamp on reject, `rejected_sha`, test against the N and N-1 gates | M |
| 8 | `debug budget` with `LOG_MAX=warn` default, `ExecStartPre=+` clamp, volatile namespace, `--namespace` in the docs, SS off | M |
| 9 | `ci`: bootstrap smoke test, tests before push, signed releases | M |
| 10 | `vps`: provision, update, backup, restore (identity in memory only), `rotate-secrets.sh`, digest-only compose. **Restore drill** | M |
| 11 | `hardening`: SourceIp for both IP families, member account, SCP for the named role, admin subs, `aud`, kill switch, EC2 provider removed | M |
| 12 | `docs`: RUNBOOK including phone lost and billing, the threat model in `security.md`, README drift | S |
| 13 | Second drill: rebuild on the final bootstrap, run the compromise playbook end to end, run the alert drill | 1 h |
| later | Server keys generated on the ingress, one-time enrollment, per-device credentials, separate WireGuard exit, warm standby | L |

PRs 0–4 fix today's blind spot and make the VPN repairable from a phone (about 1 week). PRs 5–8 contain a single compromised component. PRs 9–13 make recreating each part tested and repeatable.