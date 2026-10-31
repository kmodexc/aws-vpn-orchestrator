#!/usr/bin/env bash
# =============================================================================================
# vpn-control — ingress bootstrap (sing-box server on AWS Lightsail / EC2)
# =============================================================================================
#
# Run as root on a fresh Ubuntu 24.04 LTS or Debian 12 instance, either
#   * pasted as the Lightsail "launch script" / EC2 "user data" (fill in the CONFIG block), or
#   * manually, with the token passed through the environment — NEVER as a command-line argument
#     (argv lands in shell history and is readable by every local user via ps / /proc/<pid>/cmdline,
#     including the unprivileged sing-box user this script isolates from the token):
#         read -rs -p 'INGRESS_TOKEN: ' INGRESS_TOKEN; echo
#         export INGRESS_TOKEN CONTROL_PLANE_URL=https://vpn.example.com
#         sudo --preserve-env=INGRESS_TOKEN,CONTROL_PLANE_URL bash bootstrap.sh
#         unset INGRESS_TOKEN
#     or edit the CONFIG block below in a private 0600 copy of this script and delete it afterwards.
# It is idempotent: running it again upgrades/repairs the installation and changes nothing that
# is already correct.
#
# What it does
#   1. installs a pinned sing-box release from GitHub, verified by SHA-256
#   2. creates an unprivileged `sing-box` system user; the service runs as that user with only
#      CAP_NET_BIND_SERVICE and a hardened systemd sandbox
#   3. pulls the server config from ${CONTROL_PLANE_URL}/i/${INGRESS_TOKEN}/config.json
#      (https only, TLS >= 1.2), validates it with `sing-box check`, installs it 0600 and restarts
#      sing-box only when it changed — on boot and every 10 minutes (systemd timer)
#   4. blocks the sing-box user from reaching the instance metadata service (169.254.169.254),
#      so a proxy client can never read user-data (which contains INGRESS_TOKEN) or credentials
#   5. host firewall (ufw): deny all inbound except SSH and the proxy ports
#   6. unattended security upgrades (with automatic reboot at a fixed time)
#   7. SSH: key-only, no root login
#
# Cloud firewall — ALSO open exactly these in the Lightsail "Networking" tab / EC2 security group
# (defaults; match VLESS_PORT / HY2_PORT / SS_PORT in .env):
#     TCP 22    SSH          (restrict to your own IP if you can)
#     TCP 443   VLESS+REALITY
#     UDP 443   Hysteria2
#     TCP 8443  Shadowsocks-2022
#     UDP 8443  Shadowsocks-2022 (UDP relay)
# Do NOT open anything else. The ingress needs outbound HTTPS to the control plane and GitHub.
#
# Updating sing-box: change SING_BOX_VERSION and BOTH checksums, re-run the script.
# Checksums: on https://github.com/SagerNet/sing-box/releases/tag/v<version> each asset shows its
# "sha256:" digest; or download the tarball yourself and run `sha256sum` on it. Never take the
# checksum from the same place as an unverified download at install time.
# =============================================================================================
set -euo pipefail
umask 077

# ------------------------------------- CONFIG -----------------------------------------------
# Values may also be passed as environment variables (they take precedence).
CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-https://vpn.example.com}"   # = PUBLIC_BASE_URL in .env
INGRESS_TOKEN="${INGRESS_TOKEN:-REPLACE_WITH_INGRESS_TOKEN_FROM_DOT_ENV}"

VLESS_PORT="${VLESS_PORT:-443}"   # TCP
HY2_PORT="${HY2_PORT:-443}"       # UDP
SS_PORT="${SS_PORT:-8443}"        # TCP + UDP
# Optional: restrict SSH to one source (IP or CIDR), e.g. "198.51.100.7". Empty = anywhere.
SSH_ALLOW_FROM="${SSH_ALLOW_FROM:-}"
# Unattended-upgrades reboots at this time (UTC) when a kernel/libc update requires it.
# Set to "" to never reboot automatically.
AUTO_REBOOT_TIME="${AUTO_REBOOT_TIME:-04:30}"

SING_BOX_VERSION="1.14.4"
SING_BOX_SHA256_AMD64="699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"
SING_BOX_SHA256_ARM64="436441f76ee2f7fe21b5b2d426d3cb261a480455a704865789ad533e4273ec26"
# ---------------------------------------------------------------------------------------------

readonly SB_USER="sing-box"
readonly SB_BIN="/usr/local/bin/sing-box"
readonly SB_ETC="/etc/sing-box"
readonly SB_CONFIG="${SB_ETC}/config.json"
readonly FETCH_ENV="/etc/sing-box-fetch.env"
readonly FETCH_BIN="/usr/local/sbin/sing-box-fetch-config"
readonly NFT_FILE="/etc/sing-box-egress.nft"

log() { printf '[bootstrap] %s\n' "$*" >&2; }
die() { printf '[bootstrap] ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------------------------
# 0. Preconditions and input validation
# ---------------------------------------------------------------------------------------------
[[ ${EUID} -eq 0 ]] || die "must run as root"
[[ -r /etc/os-release ]] || die "/etc/os-release missing"
# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
  ubuntu:24.04 | debian:12 | debian:13) ;;
  *) log "WARNING: untested OS '${ID:-?} ${VERSION_ID:-?}' (tested: Ubuntu 24.04, Debian 12)" ;;
esac

[[ ${CONTROL_PLANE_URL} =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] \
  || die "CONTROL_PLANE_URL must be https://<host>[:port] without path or trailing slash"
[[ ${CONTROL_PLANE_URL} != "https://vpn.example.com" ]] || die "set CONTROL_PLANE_URL"
[[ ${INGRESS_TOKEN} != REPLACE_WITH_* ]] || die "set INGRESS_TOKEN (copy it from .env)"
[[ ${INGRESS_TOKEN} =~ ^[A-Za-z0-9_-]{32,}$ ]] \
  || die "INGRESS_TOKEN must be >= 32 chars of [A-Za-z0-9_-] (copy it from .env)"
for p in "${VLESS_PORT}" "${HY2_PORT}" "${SS_PORT}"; do
  if ! [[ ${p} =~ ^[1-9][0-9]{0,4}$ ]] || ((p > 65535)); then die "invalid port '${p}'"; fi
done
[[ -z ${SSH_ALLOW_FROM} || ${SSH_ALLOW_FROM} =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]] \
  || die "SSH_ALLOW_FROM must be an IP or CIDR"
[[ -z ${AUTO_REBOOT_TIME} || ${AUTO_REBOOT_TIME} =~ ^[0-2][0-9]:[0-5][0-9]$ ]] \
  || die "AUTO_REBOOT_TIME must be HH:MM"

case "$(uname -m)" in
  x86_64) SB_ARCH="amd64"; SB_SHA256="${SING_BOX_SHA256_AMD64}" ;;
  aarch64 | arm64) SB_ARCH="arm64"; SB_SHA256="${SING_BOX_SHA256_ARM64}" ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
[[ ${SB_SHA256} =~ ^[0-9a-f]{64}$ ]] || die "sing-box SHA-256 for ${SB_ARCH} is not set"

export DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------------------------
# 1. Packages
# ---------------------------------------------------------------------------------------------
log "installing packages"
apt-get update -q
apt-get install -y -q --no-install-recommends \
  ca-certificates curl tar coreutils diffutils ufw nftables unattended-upgrades

# ---------------------------------------------------------------------------------------------
# 2. sing-box binary (pinned + checksum verified)
# ---------------------------------------------------------------------------------------------
installed_version=""
if [[ -x ${SB_BIN} ]]; then
  installed_version="$("${SB_BIN}" version 2>/dev/null | awk 'NR==1 {print $3}' || true)"
fi
if [[ ${installed_version} != "${SING_BOX_VERSION}" ]]; then
  log "installing sing-box ${SING_BOX_VERSION} (${SB_ARCH})"
  workdir="$(mktemp -d)"
  trap 'rm -rf -- "${workdir}"' EXIT
  name="sing-box-${SING_BOX_VERSION}-linux-${SB_ARCH}"
  url="https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/${name}.tar.gz"
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 15 --max-time 300 --retry 3 \
    --output "${workdir}/sb.tar.gz" "${url}"
  printf '%s  %s\n' "${SB_SHA256}" "${workdir}/sb.tar.gz" | sha256sum --check --strict --quiet \
    || die "sing-box checksum mismatch — refusing to install"
  tar -xzf "${workdir}/sb.tar.gz" -C "${workdir}" --no-same-owner "${name}/sing-box"
  install -o root -g root -m 0755 "${workdir}/${name}/sing-box" "${SB_BIN}.new"
  mv -f "${SB_BIN}.new" "${SB_BIN}"
  rm -rf -- "${workdir}"
  trap - EXIT
else
  log "sing-box ${SING_BOX_VERSION} already installed"
fi
"${SB_BIN}" version | head -n1 >&2

# ---------------------------------------------------------------------------------------------
# 3. User, directories, fetch credentials
# ---------------------------------------------------------------------------------------------
if ! id -u "${SB_USER}" >/dev/null 2>&1; then
  log "creating system user ${SB_USER}"
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin \
    --user-group "${SB_USER}"
fi
install -d -o root -g "${SB_USER}" -m 0750 "${SB_ETC}"

# Token lives in a root-only file, never on a command line (would be visible in `ps`).
tmp_env="$(mktemp "${FETCH_ENV}.XXXXXX")"
printf 'CONTROL_PLANE_URL=%s\nINGRESS_TOKEN=%s\n' "${CONTROL_PLANE_URL}" "${INGRESS_TOKEN}" >"${tmp_env}"
chown root:root "${tmp_env}"
chmod 0600 "${tmp_env}"
mv -f "${tmp_env}" "${FETCH_ENV}"

# ---------------------------------------------------------------------------------------------
# 4. Config fetcher (runs as root via systemd oneshot; installs config owned by sing-box, 0600)
# ---------------------------------------------------------------------------------------------
log "installing ${FETCH_BIN}"
cat >"${FETCH_BIN}.new" <<'FETCH'
#!/usr/bin/env bash
# Pull the sing-box server config from the control plane, validate, install, restart on change.
# Exit 0 when the running config is current or a previous valid config stays in place.
set -euo pipefail
umask 077
readonly SB_BIN=/usr/local/bin/sing-box
readonly SB_ETC=/etc/sing-box
readonly SB_CONFIG=/etc/sing-box/config.json
readonly FETCH_ENV=/etc/sing-box-fetch.env

log() { printf 'sing-box-fetch-config: %s\n' "$*" >&2; }

# Read the two values without `source` (no code execution from the file).
CONTROL_PLANE_URL="$(sed -n 's/^CONTROL_PLANE_URL=//p' "${FETCH_ENV}" | head -n1)"
INGRESS_TOKEN="$(sed -n 's/^INGRESS_TOKEN=//p' "${FETCH_ENV}" | head -n1)"
[[ ${CONTROL_PLANE_URL} =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || { log "bad CONTROL_PLANE_URL"; exit 1; }
[[ ${INGRESS_TOKEN} =~ ^[A-Za-z0-9_-]{32,}$ ]] || { log "bad INGRESS_TOKEN"; exit 1; }

tmp="$(mktemp "${SB_ETC}/.config.json.XXXXXX")"
trap 'rm -f -- "${tmp}"' EXIT

keep_old() {
  if [[ -s ${SB_CONFIG} ]]; then
    log "$1 — keeping the current config"
    exit 0
  fi
  log "$1 — and no previous config exists"
  exit 1
}

# URL (with token) is passed via stdin config, not argv, so it never shows up in `ps`.
# No redirects are followed (a redirect could leak the token to another host).
# curl's own messages are suppressed (they must never be able to echo the URL); only the exit
# code is reported.
rc=0
printf 'url = "%s/i/%s/config.json"\n' "${CONTROL_PLANE_URL}" "${INGRESS_TOKEN}" \
  | curl --config - --fail --silent \
      --proto '=https' --tlsv1.2 --max-redirs 0 \
      --connect-timeout 10 --max-time 60 --retry 3 --retry-delay 5 \
      --max-filesize 1048576 --output "${tmp}" 2>/dev/null || rc=$?
((rc == 0)) || keep_old "download failed (curl exit code ${rc})"
[[ -s ${tmp} ]] || keep_old "empty response"

# Validate as the unprivileged sing-box user, not as root.
chown sing-box:sing-box "${tmp}"
chmod 0600 "${tmp}"
if ! runuser -u sing-box -- "${SB_BIN}" check -c "${tmp}" >/dev/null 2>&1; then
  keep_old "downloaded config failed 'sing-box check'"
fi

if [[ -f ${SB_CONFIG} ]] && cmp -s "${tmp}" "${SB_CONFIG}"; then
  log "config unchanged"
  exit 0
fi

mv -f "${tmp}" "${SB_CONFIG}"
trap - EXIT
log "config updated — restarting sing-box"
# --no-block: this unit may run while sing-box.service is queued after it (boot ordering).
systemctl --no-block restart sing-box.service
FETCH
chown root:root "${FETCH_BIN}.new"
chmod 0700 "${FETCH_BIN}.new"
mv -f "${FETCH_BIN}.new" "${FETCH_BIN}"

# ---------------------------------------------------------------------------------------------
# 5. Egress guard: sing-box must not reach the instance metadata service
# ---------------------------------------------------------------------------------------------
log "installing egress guard (${NFT_FILE})"
cat >"${NFT_FILE}" <<'NFT'
#!/usr/sbin/nft -f
# Proxy clients must never reach the instance metadata service through sing-box
# (IMDS exposes user-data incl. INGRESS_TOKEN, and role credentials if a role is attached).
table inet sing_box_egress
delete table inet sing_box_egress
table inet sing_box_egress {
  chain output {
    type filter hook output priority filter; policy accept;
    meta skuid "sing-box" ip daddr { 169.254.169.254, 169.254.169.253, 169.254.170.2 } counter reject
    meta skuid "sing-box" ip6 daddr { fd00:ec2::254, fd00:ec2::253 } counter reject
  }
}
NFT
chmod 0644 "${NFT_FILE}"

cat >/etc/systemd/system/sing-box-egress.service <<UNIT
[Unit]
Description=Egress restrictions for the sing-box user (block instance metadata)
Before=sing-box.service
# After nftables/ufw: a "flush ruleset" from /etc/nftables.conf must not wipe this table.
After=network-pre.target nftables.service ufw.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f ${NFT_FILE}
ExecStop=/usr/sbin/nft delete table inet sing_box_egress

[Install]
WantedBy=multi-user.target
UNIT

# ---------------------------------------------------------------------------------------------
# 6. systemd units
# ---------------------------------------------------------------------------------------------
log "installing systemd units"
cat >/etc/systemd/system/sing-box-config.service <<UNIT
[Unit]
Description=Fetch sing-box config from the vpn-control plane
Wants=network-online.target
After=network-online.target
Before=sing-box.service

[Service]
Type=oneshot
ExecStart=${FETCH_BIN}
ProtectSystem=strict
ReadWritePaths=${SB_ETC}
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
NoNewPrivileges=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
UNIT

cat >/etc/systemd/system/sing-box-config.timer <<'UNIT'
[Unit]
Description=Periodically refresh the sing-box config

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min
RandomizedDelaySec=60
Persistent=false

[Install]
WantedBy=timers.target
UNIT

cat >/etc/systemd/system/sing-box.service <<UNIT
[Unit]
Description=sing-box proxy server (vpn-control ingress)
Documentation=https://sing-box.sagernet.org
Wants=network-online.target sing-box-config.service sing-box-egress.service
After=network-online.target sing-box-config.service sing-box-egress.service
Requires=sing-box-egress.service
ConditionPathExists=${SB_CONFIG}

[Service]
Type=simple
User=${SB_USER}
Group=${SB_USER}
ExecStartPre=${SB_BIN} check -c ${SB_CONFIG}
ExecStart=${SB_BIN} run -c ${SB_CONFIG} -D /var/lib/sing-box
Restart=on-failure
RestartSec=5s
StateDirectory=sing-box
StateDirectoryMode=0700
LimitNOFILE=1048576

# Privileges: only bind low ports. WireGuard runs in userspace (no CAP_NET_ADMIN needed).
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes

# Sandbox
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RemoveIPC=yes
UMask=0077
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now sing-box-egress.service
systemctl enable sing-box.service sing-box-config.timer
# First fetch now (synchronously), then start/restart sing-box.
systemctl start sing-box-config.service \
  || log "WARNING: initial config fetch failed (is the control plane up and INGRESS_TOKEN right?)"
if [[ -s ${SB_CONFIG} ]]; then
  systemctl restart sing-box.service
else
  log "WARNING: no config yet — sing-box starts automatically after the first successful fetch"
fi
systemctl start sing-box-config.timer

# ---------------------------------------------------------------------------------------------
# 7. Host firewall (ufw). SSH is allowed BEFORE enabling, so an SSH session is not cut off.
# ---------------------------------------------------------------------------------------------
log "configuring ufw"
ufw --force reset >/dev/null
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
if [[ -n ${SSH_ALLOW_FROM} ]]; then
  ufw allow proto tcp from "${SSH_ALLOW_FROM}" to any port 22 comment 'ssh' >/dev/null
else
  ufw limit 22/tcp comment 'ssh (rate limited)' >/dev/null
fi
# Ports deduplicated; each opened for tcp and udp (VLESS=tcp, HY2=udp, SS=tcp+udp).
declare -A seen=()
for p in "${VLESS_PORT}" "${HY2_PORT}" "${SS_PORT}"; do
  [[ -n ${seen[${p}]:-} ]] && continue
  seen[${p}]=1
  ufw allow "${p}/tcp" comment 'sing-box' >/dev/null
  ufw allow "${p}/udp" comment 'sing-box' >/dev/null
done
ufw logging off >/dev/null
ufw --force enable >/dev/null
ufw status verbose >&2

# ---------------------------------------------------------------------------------------------
# 8. Unattended security upgrades
# ---------------------------------------------------------------------------------------------
log "enabling unattended-upgrades"
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'APT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT
if [[ -n ${AUTO_REBOOT_TIME} ]]; then
  cat >/etc/apt/apt.conf.d/52vpn-ingress-reboot <<APT
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "${AUTO_REBOOT_TIME}";
APT
else
  rm -f /etc/apt/apt.conf.d/52vpn-ingress-reboot
fi
systemctl enable --now unattended-upgrades.service >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------------------------
# 9. SSH hardening (key-only; cloud images already ship authorised keys for the default user)
# ---------------------------------------------------------------------------------------------
if [[ -d /etc/ssh/sshd_config.d ]]; then
  log "hardening sshd"
  cat >/etc/ssh/sshd_config.d/10-vpn-ingress.conf <<'SSHD'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
X11Forwarding no
AllowAgentForwarding no
MaxAuthTries 3
SSHD
  chmod 0644 /etc/ssh/sshd_config.d/10-vpn-ingress.conf
  if sshd -t; then
    systemctl reload ssh.service 2>/dev/null || systemctl reload sshd.service 2>/dev/null || true
  else
    log "WARNING: sshd config test failed — removing hardening drop-in"
    rm -f /etc/ssh/sshd_config.d/10-vpn-ingress.conf
  fi
fi

log "done. sing-box: $(systemctl is-active sing-box.service || true)"
