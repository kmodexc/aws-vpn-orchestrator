# shellcheck shell=bash
# Shared helpers for the Lightsail CLI scripts in this directory. Sourced, never executed.
#
# Design rules
#   * These scripts run with YOUR admin credentials (AWS CLI profile / SSO), never with the
#     narrow control-plane key stored in .env. .env is parsed as data, never `source`d.
#   * Everything is idempotent: re-running converges to the desired state.
#   * Only static IPs named "vpn-orchestrator-*" are ever released (same rule as the backend).
#   * Portable: bash >= 3.2 (macOS), Linux, WSL. Needs aws CLI v2, gzip, base64, awk, sed.

readonly MANAGED_PREFIX="vpn-orchestrator-"
readonly MANAGED_TAG_KEY="vpn-orchestrator"
readonly POLICY_NAME="vpn-control-lightsail"
readonly DEFAULT_BLUEPRINT="ubuntu_24_04"
readonly USER_DATA_LIMIT=16000

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
AWS_ARGS=()
ASSUME_YES=0
export AWS_PAGER=""

log() { printf '[%s] %s\n' "${SCRIPT_NAME}" "$*" >&2; }
warn() { printf '[%s] WARNING: %s\n' "${SCRIPT_NAME}" "$*" >&2; }
die() {
  printf '[%s] ERROR: %s\n' "${SCRIPT_NAME}" "$*" >&2
  exit 1
}

aws_() { aws ${AWS_ARGS[@]+"${AWS_ARGS[@]}"} "$@"; }

require_tools() {
  local t
  command -v aws >/dev/null 2>&1 || die "aws CLI not found (https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)"
  aws --version 2>&1 | grep -q '^aws-cli/2' || die "aws CLI v2 required ($(aws --version 2>&1))"
  for t in gzip base64 awk sed tr mktemp; do
    command -v "${t}" >/dev/null 2>&1 || die "'${t}' not found"
  done
}

confirm() {
  local prompt=$1 expected=$2 answer
  [[ ${ASSUME_YES} -eq 1 ]] && return 0
  [[ -t 0 ]] || die "refusing to continue without a terminal; pass --yes to confirm non-interactively"
  read -r -p "${prompt} " answer
  [[ ${answer} == "${expected}" ]] || die "aborted"
}

# ------------------------------------------------------------------------------------------
# .env access (data only — never sourced)
# ------------------------------------------------------------------------------------------
require_env_file() {
  [[ -f ${ENV_FILE} ]] || die "${ENV_FILE} not found — generate it first: docker compose run --rm --no-deps -T app gen-env > .env"
}

# Last assignment wins (like docker compose). Strips CR and one pair of surrounding quotes.
env_get() {
  local v
  v="$(K="$1" awk 'index($0, ENVIRON["K"] "=") == 1 { v = substr($0, length(ENVIRON["K"]) + 2) } END { print v }' "${ENV_FILE}")"
  v="${v%$'\r'}"
  if [[ ${#v} -ge 2 && ( ${v:0:1} == '"' && ${v: -1} == '"' || ${v:0:1} == "'" && ${v: -1} == "'" ) ]]; then
    v="${v:1:${#v}-2}"
  fi
  printf '%s' "${v}"
}

# Replace the first assignment of KEY (dropping later duplicates) or append it. Mode stays 0600.
env_set() {
  local key=$1 value=$2 tmp
  [[ ${value} != *$'\n'* ]] || die "refusing to write a multi-line value for ${key}"
  tmp="$(mktemp "${ENV_FILE}.XXXXXX")"
  K="${key}" V="${value}" awk '
    index($0, ENVIRON["K"] "=") == 1 { if (!done) { print ENVIRON["K"] "=" ENVIRON["V"]; done = 1 } next }
    { print }
    END { if (!done) print ENVIRON["K"] "=" ENVIRON["V"] }
  ' "${ENV_FILE}" >"${tmp}" || { rm -f "${tmp}"; die "could not update ${ENV_FILE}"; }
  chmod 600 "${tmp}"
  mv -f "${tmp}" "${ENV_FILE}"
}

# Values the ingress needs, validated so they are safe to embed in the launch script.
load_ingress_settings() {
  CONTROL_PLANE_URL="$(env_get PUBLIC_BASE_URL)"
  INGRESS_TOKEN="$(env_get INGRESS_TOKEN)"
  VLESS_PORT="$(env_get VLESS_PORT)"; VLESS_PORT="${VLESS_PORT:-443}"
  HY2_PORT="$(env_get HY2_PORT)"; HY2_PORT="${HY2_PORT:-443}"
  SS_PORT="$(env_get SS_PORT)"; SS_PORT="${SS_PORT:-8443}"

  [[ ${CONTROL_PLANE_URL} =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] \
    || die "PUBLIC_BASE_URL in .env must be https://<host>[:port] (no path, no trailing slash)"
  [[ ${CONTROL_PLANE_URL} != "https://vpn.example.com" ]] || die "set PUBLIC_BASE_URL in .env first"
  [[ ${INGRESS_TOKEN} =~ ^[A-Za-z0-9_-]{32,}$ ]] || die "INGRESS_TOKEN in .env is missing or invalid (run gen-env)"
  local p
  for p in "${VLESS_PORT}" "${HY2_PORT}" "${SS_PORT}"; do
    if ! [[ ${p} =~ ^[1-9][0-9]{0,4}$ ]] || ((p > 65535)); then die "invalid port '${p}' in .env"; fi
  done
}

# ------------------------------------------------------------------------------------------
# AWS account / region
# ------------------------------------------------------------------------------------------
resolve_account() {
  local caller
  caller="$(aws_ sts get-caller-identity --query '[Account, Arn]' --output text)" \
    || die "no usable AWS credentials — log in with your ADMIN profile (e.g. --profile admin or 'aws sso login')"
  ACCOUNT_ID="${caller%%[[:space:]]*}"
  CALLER_ARN="${caller##*[[:space:]]}"
  [[ ${ACCOUNT_ID} =~ ^[0-9]{12}$ ]] || die "unexpected sts output: ${caller}"
  [[ ${CALLER_ARN} != *":user/${IAM_USER}" ]] \
    || die "you are using the control plane's own key (${CALLER_ARN}); use your admin profile instead"
  log "AWS account ${ACCOUNT_ID} as ${CALLER_ARN}"
}

validate_region() {
  [[ $1 =~ ^[a-z]{2}(-[a-z]+)+-[0-9]$ ]] || die "invalid region '$1'"
}

validate_instance_name() {
  [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$ ]] || die "invalid instance name '$1'"
}

# ------------------------------------------------------------------------------------------
# Lightsail instance
# ------------------------------------------------------------------------------------------
instance_exists() { # region name
  local err
  if err="$(aws_ lightsail get-instance --region "$1" --instance-name "$2" --query instance.name --output text 2>&1 >/dev/null)"; then
    return 0
  fi
  [[ ${err} == *NotFoundException* ]] && return 1
  die "get-instance failed: ${err}"
}

instance_field() { # region name jmespath
  aws_ lightsail get-instance --region "$1" --instance-name "$2" --query "instance.$3" --output text
}

pick_bundle() { # region
  local b
  # Cheapest active Linux bundle with >= 0.5 GB RAM that has a public IPv4 (no "ipv6-only" bundles).
  b="$(aws_ lightsail get-bundles --region "$1" --query \
    "sort_by(bundles[?isActive && contains(supportedPlatforms, 'LINUX_UNIX') && !contains(bundleId, 'ipv6') && ramSizeInGb >= \`0.5\`], &price)[0].bundleId" \
    --output text)"
  [[ -n ${b} && ${b} != None ]] || die "no suitable bundle found in $1 (pass --bundle)"
  printf '%s' "${b}"
}

check_blueprint() { # region blueprint
  local found
  found="$(aws_ lightsail get-blueprints --region "$1" --query \
    "blueprints[?blueprintId=='$2' && isActive].blueprintId | [0]" --output text)"
  [[ ${found} == "$2" ]] || die "blueprint '$2' not available in $1 (list: aws lightsail get-blueprints --region $1 --query 'blueprints[].blueprintId')"
}

pick_az() { # region
  local az
  az="$(aws_ lightsail get-regions --region "$1" --include-availability-zones --query \
    "regions[?name=='$1'] | [0].availabilityZones[?state=='available'] | [0].zoneName" --output text)"
  [[ -n ${az} && ${az} != None ]] || die "no available zone in $1 (is Lightsail offered there?)"
  printf '%s' "${az}"
}

# Launch script: a small wrapper carrying bootstrap.sh gzip+base64 (the raw script exceeds the
# 16 KB user-data limit). SSH_ALLOW_FROM stays empty on purpose: SSH is restricted by the
# Lightsail firewall, which these scripts can update any time; a host-level restriction could
# lock you out for good when your own IP changes.
render_user_data() {
  local payload
  payload="$(gzip -9n <"${REPO_ROOT}/deploy/ingress/bootstrap.sh" | base64 | tr -d '\r\n')"
  # POSIX sh only, no bash-isms: Lightsail PREPENDS its own "#!/bin/sh" block (SSH CA setup) to
  # the launch script and runs the whole thing with dash, so our shebang is ignored and e.g.
  # `set -o pipefail` aborts the script before anything is installed. EC2 honours the shebang;
  # plain sh works there too. The real bootstrap runs under bash explicitly.
  cat <<EOF
#!/bin/sh
# vpn-control ingress bootstrap — generated by deploy/aws/*-lightsail.sh
set -eu
umask 077
install -d -m 700 /root/vpn-control
printf '%s' '${payload}' | base64 -d | gunzip >/root/vpn-control/bootstrap.sh
chmod 700 /root/vpn-control/bootstrap.sh
# Values go in through the environment of this one command (not argv, never visible in ps).
if CONTROL_PLANE_URL='${CONTROL_PLANE_URL}' INGRESS_TOKEN='${INGRESS_TOKEN}' \\
   VLESS_PORT='${VLESS_PORT}' HY2_PORT='${HY2_PORT}' SS_PORT='${SS_PORT}' SSH_ALLOW_FROM='' \\
   bash /root/vpn-control/bootstrap.sh >>/var/log/vpn-control-bootstrap.log 2>&1; then
  echo "vpn-control: bootstrap finished, see /var/log/vpn-control-bootstrap.log"
else
  echo "vpn-control: bootstrap FAILED, see /var/log/vpn-control-bootstrap.log" >&2
  exit 1
fi
EOF
}

wait_for_state() { # region name wanted-state
  local i state
  for ((i = 0; i < 90; i++)); do
    state="$(aws_ lightsail get-instance-state --region "$1" --instance-name "$2" --query state.name --output text 2>/dev/null || true)"
    [[ ${state} == "$3" ]] && return 0
    sleep 5
  done
  die "instance $2 did not reach state '$3' (last: '${state:-unknown}')"
}

ensure_instance() { # region name bundle blueprint az
  local region=$1 name=$2 bundle=$3 blueprint=$4 az=$5 user_data
  if instance_exists "${region}" "${name}"; then
    log "instance ${name} already exists in ${region} — keeping it (the launch script is not re-run)"
    return 0
  fi
  [[ -n ${bundle} ]] || bundle="$(pick_bundle "${region}")"
  [[ -n ${az} ]] || az="$(pick_az "${region}")"
  check_blueprint "${region}" "${blueprint}"
  user_data="$(render_user_data)"
  ((${#user_data} <= USER_DATA_LIMIT)) || die "launch script is ${#user_data} bytes (limit ${USER_DATA_LIMIT})"

  # The launch script contains INGRESS_TOKEN: pass it via a private temp file, not argv (ps).
  local ud_file rc=0
  ud_file="$(mktemp)"
  chmod 600 "${ud_file}"
  printf '%s\n' "${user_data}" >"${ud_file}"
  local ud_ref="${ud_file}"
  # Git Bash / MSYS on Windows: aws.exe needs a Windows path.
  if command -v cygpath >/dev/null 2>&1; then ud_ref="$(cygpath -m "${ud_file}")"; fi
  log "creating instance ${name} in ${az} (${blueprint}, ${bundle}, IPv4 only)"
  aws_ lightsail create-instances --region "${region}" \
    --instance-names "${name}" \
    --availability-zone "${az}" \
    --blueprint-id "${blueprint}" \
    --bundle-id "${bundle}" \
    --ip-address-type ipv4 \
    --user-data "file://${ud_ref}" \
    --tags "key=${MANAGED_TAG_KEY},value=managed" \
    --query 'operations[0].status' --output text >/dev/null || rc=$?
  rm -f "${ud_file}"
  ((rc == 0)) || die "create-instances failed"
}

# Firewall: exactly the proxy ports (+ SSH from one CIDR, unless disabled). Replaces all rules.
apply_ports() { # region name ssh-cidr("" = no SSH)
  local region=$1 name=$2 ssh=$3 infos=() seen=" " spec
  add_port() {
    local s="$1/$2"
    [[ ${seen} == *" ${s} "* ]] && return 0
    seen+="${s} "
    infos+=("fromPort=$1,toPort=$1,protocol=$2,cidrs=0.0.0.0/0")
  }
  add_port "${VLESS_PORT}" tcp
  add_port "${HY2_PORT}" udp
  add_port "${SS_PORT}" tcp
  add_port "${SS_PORT}" udp
  if [[ -n ${ssh} ]]; then
    infos+=("fromPort=22,toPort=22,protocol=tcp,cidrs=${ssh}")
  fi
  for spec in "${infos[@]}"; do log "firewall: ${spec}"; done
  aws_ lightsail put-instance-public-ports --region "${region}" --instance-name "${name}" \
    --port-infos "${infos[@]}" --query 'operation.status' --output text >/dev/null
}

detect_ssh_cidr() {
  local ip
  ip="$(curl -fsS --max-time 10 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]')" || true
  [[ ${ip} =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "could not detect your public IPv4; pass --ssh-cidr <ip>/32 or --no-ssh"
  printf '%s/32' "${ip}"
}

validate_cidr() {
  [[ $1 =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$ ]] || die "invalid IPv4 CIDR '$1'"
}

attached_static_ip() { # region name -> static IP name or ""
  local n
  n="$(aws_ lightsail get-static-ips --region "$1" --query \
    "staticIps[?isAttached && attachedTo=='$2'].name | [0]" --output text)"
  [[ ${n} == None ]] && n=""
  printf '%s' "${n}"
}

ensure_static_ip() { # region name
  local region=$1 name=$2 ip_name
  ip_name="$(attached_static_ip "${region}" "${name}")"
  if [[ -n ${ip_name} ]]; then
    log "static IP ${ip_name} already attached"
    return 0
  fi
  ip_name="${MANAGED_PREFIX}$(date +%s)000"
  log "allocating static IP ${ip_name}"
  aws_ lightsail allocate-static-ip --region "${region}" --static-ip-name "${ip_name}" --output text >/dev/null
  aws_ lightsail attach-static-ip --region "${region}" --static-ip-name "${ip_name}" \
    --instance-name "${name}" --output text >/dev/null \
    || {
      aws_ lightsail release-static-ip --region "${region}" --static-ip-name "${ip_name}" --output text >/dev/null || true
      die "attaching ${ip_name} failed (released it again)"
    }
}

# Everything needed for a working ingress: instance, running, firewall, static IP.
provision_ingress() { # region name bundle blueprint az ssh-cidr
  ensure_instance "$1" "$2" "$3" "$4" "$5"
  log "waiting for ${2} to run"
  wait_for_state "$1" "$2" running
  apply_ports "$1" "$2" "$6"
  ensure_static_ip "$1" "$2"
  INGRESS_IP="$(instance_field "$1" "$2" publicIpAddress)"
  log "ingress ${2} is running at ${INGRESS_IP}"
}

# Detach + release every managed static IP of an instance, delete it, then sweep unattached
# managed IPs in that region (an unattached static IP costs money).
destroy_ingress() { # region name
  local region=$1 name=$2 ip_name n
  if instance_exists "${region}" "${name}"; then
    ip_name="$(attached_static_ip "${region}" "${name}")"
    if [[ -n ${ip_name} ]]; then
      log "detaching static IP ${ip_name}"
      aws_ lightsail detach-static-ip --region "${region}" --static-ip-name "${ip_name}" --output text >/dev/null
    fi
    log "deleting instance ${name} in ${region}"
    aws_ lightsail delete-instance --region "${region}" --instance-name "${name}" \
      --force-delete-add-ons --output text >/dev/null
  else
    log "instance ${name} in ${region} does not exist — nothing to delete"
  fi
  for n in $(aws_ lightsail get-static-ips --region "${region}" --query \
    "staticIps[?!isAttached && starts_with(name, '${MANAGED_PREFIX}')].name" --output text); do
    log "releasing unattached static IP ${n}"
    aws_ lightsail release-static-ip --region "${region}" --static-ip-name "${n}" --output text >/dev/null
  done
}

# ------------------------------------------------------------------------------------------
# IAM user for the control plane (narrow policy, pinned to one instance + region)
# ------------------------------------------------------------------------------------------
render_policy() { # region resource-id
  sed -e "s/<REGION>/$1/g" -e "s/<ACCOUNT_ID>/${ACCOUNT_ID}/g" -e "s/<INSTANCE_RESOURCE_ID>/$2/g" \
    "${REPO_ROOT}/deploy/iam/lightsail.json"
}

ensure_iam() { # region name
  local region=$1 name=$2 arn resource_id policy err keys current count id secret
  arn="$(instance_field "${region}" "${name}" arn)"
  resource_id="${arn##*/}"
  [[ ${resource_id} =~ ^[A-Za-z0-9-]+$ ]] || die "unexpected instance ARN ${arn}"
  policy="$(render_policy "${region}" "${resource_id}")"
  [[ ${policy} != *"<"*">"* ]] || die "unreplaced placeholder in deploy/iam/lightsail.json"

  if ! err="$(aws_ iam get-user --user-name "${IAM_USER}" --output text 2>&1 >/dev/null)"; then
    [[ ${err} == *NoSuchEntity* ]] || die "get-user failed: ${err}"
    log "creating IAM user ${IAM_USER} (no console access)"
    aws_ iam create-user --user-name "${IAM_USER}" \
      --tags "Key=${MANAGED_TAG_KEY},Value=managed" --output text >/dev/null
  fi
  log "setting inline policy ${POLICY_NAME} (instance ${name}, region ${region})"
  aws_ iam put-user-policy --user-name "${IAM_USER}" --policy-name "${POLICY_NAME}" \
    --policy-document "${policy}"

  keys="$(aws_ iam list-access-keys --user-name "${IAM_USER}" --query 'AccessKeyMetadata[].AccessKeyId' --output text)"
  current="$(env_get AWS_ACCESS_KEY_ID)"
  if [[ -n ${current} && " ${keys} " == *" ${current} "* ]]; then
    log "keeping existing access key ${current} from .env"
    return 0
  fi
  count="$(printf '%s\n' ${keys} | grep -c . || true)"
  ((count < 2)) || die "${IAM_USER} already has 2 access keys and none matches .env; delete one: aws iam delete-access-key --user-name ${IAM_USER} --access-key-id <id>"
  log "creating a new access key for ${IAM_USER} and writing it to .env"
  read -r id secret < <(aws_ iam create-access-key --user-name "${IAM_USER}" \
    --query 'AccessKey.[AccessKeyId, SecretAccessKey]' --output text)
  [[ ${id} =~ ^[A-Z0-9]{16,128}$ && -n ${secret} ]] || die "create-access-key returned unexpected output"
  env_set AWS_ACCESS_KEY_ID "${id}"
  env_set AWS_SECRET_ACCESS_KEY "${secret}"
}

delete_iam_user() {
  local err k
  if ! err="$(aws_ iam get-user --user-name "${IAM_USER}" --output text 2>&1 >/dev/null)"; then
    [[ ${err} == *NoSuchEntity* ]] && { log "IAM user ${IAM_USER} does not exist"; return 0; }
    die "get-user failed: ${err}"
  fi
  for k in $(aws_ iam list-access-keys --user-name "${IAM_USER}" --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
    log "deleting access key ${k}"
    aws_ iam delete-access-key --user-name "${IAM_USER}" --access-key-id "${k}"
  done
  aws_ iam delete-user-policy --user-name "${IAM_USER}" --policy-name "${POLICY_NAME}" 2>/dev/null || true
  log "deleting IAM user ${IAM_USER}"
  aws_ iam delete-user --user-name "${IAM_USER}"
}

# ------------------------------------------------------------------------------------------
# Optional monthly cost alarm (AWS Budgets is global; its API lives in us-east-1)
# ------------------------------------------------------------------------------------------
readonly BUDGET_NAME="vpn-orchestrator-monthly"

ensure_budget() { # email usd
  [[ $1 =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "invalid e-mail '$1'"
  [[ $2 =~ ^[1-9][0-9]{0,5}$ ]] || die "invalid budget amount '$2'"
  if aws_ budgets describe-budget --region us-east-1 --account-id "${ACCOUNT_ID}" \
    --budget-name "${BUDGET_NAME}" --output text >/dev/null 2>&1; then
    log "budget ${BUDGET_NAME} already exists"
    return 0
  fi
  log "creating budget ${BUDGET_NAME}: e-mail $1 at 80% and 100% of \$$2/month"
  aws_ budgets create-budget --region us-east-1 --account-id "${ACCOUNT_ID}" \
    --budget "{\"BudgetName\":\"${BUDGET_NAME}\",\"BudgetLimit\":{\"Amount\":\"$2\",\"Unit\":\"USD\"},\"TimeUnit\":\"MONTHLY\",\"BudgetType\":\"COST\"}" \
    --notifications-with-subscribers "[
      {\"Notification\":{\"NotificationType\":\"ACTUAL\",\"ComparisonOperator\":\"GREATER_THAN\",\"Threshold\":80,\"ThresholdType\":\"PERCENTAGE\"},\"Subscribers\":[{\"SubscriptionType\":\"EMAIL\",\"Address\":\"$1\"}]},
      {\"Notification\":{\"NotificationType\":\"FORECASTED\",\"ComparisonOperator\":\"GREATER_THAN\",\"Threshold\":100,\"ThresholdType\":\"PERCENTAGE\"},\"Subscribers\":[{\"SubscriptionType\":\"EMAIL\",\"Address\":\"$1\"}]}
    ]"
}

delete_budget() {
  aws_ budgets delete-budget --region us-east-1 --account-id "${ACCOUNT_ID}" \
    --budget-name "${BUDGET_NAME}" 2>/dev/null && log "deleted budget ${BUDGET_NAME}" || log "no budget ${BUDGET_NAME}"
}

next_steps() {
  cat >&2 <<EOF

Next steps
  1. If you ran this on another machine, copy .env to the VPS (keep it 0600):
       scp .env <vps>:<repo>/.env
  2. Restart the app on the VPS so it loads the new AWS settings:
       docker compose up -d --force-recreate app
  3. The ingress configures itself (~3-5 min after boot) and pulls its sing-box config from
     ${CONTROL_PLANE_URL}/i/<INGRESS_TOKEN>/config.json — retried every 10 min until the
     control plane answers. Watch the dashboard; clients pick up the IP from the subscription.
  Debug on the ingress (SSH with the Lightsail default key of the region):
       sudo tail -f /var/log/vpn-control-bootstrap.log; systemctl status sing-box
EOF
}

# Common CLI options. Sets: REGION NAME BUNDLE BLUEPRINT AZ SSH_CIDR NO_SSH IAM_USER
# BUDGET_EMAIL BUDGET_USD and the shared globals. Unknown options go to EXTRA_ARGS.
parse_common_args() {
  REGION="" NAME="" BUNDLE="" BLUEPRINT="${DEFAULT_BLUEPRINT}" AZ="" SSH_CIDR="" NO_SSH=0
  IAM_USER="vpn-control" BUDGET_EMAIL="" BUDGET_USD=20
  EXTRA_ARGS=()
  while (($#)); do
    case $1 in
      --env) ENV_FILE=${2:?}; shift ;;
      --profile) AWS_ARGS+=(--profile "${2:?}"); shift ;;
      --region) REGION=${2:?}; shift ;;
      --name) NAME=${2:?}; shift ;;
      --bundle) BUNDLE=${2:?}; shift ;;
      --blueprint) BLUEPRINT=${2:?}; shift ;;
      --az) AZ=${2:?}; shift ;;
      --ssh-cidr) SSH_CIDR=${2:?}; shift ;;
      --no-ssh) NO_SSH=1 ;;
      --iam-user) IAM_USER=${2:?}; shift ;;
      --budget-email) BUDGET_EMAIL=${2:?}; shift ;;
      --budget-usd) BUDGET_USD=${2:?}; shift ;;
      -y | --yes) ASSUME_YES=1 ;;
      -h | --help) usage; exit 0 ;;
      *) EXTRA_ARGS+=("$1") ;;
    esac
    shift
  done
  [[ ${IAM_USER} =~ ^[A-Za-z0-9+=,.@_-]{1,64}$ ]] || die "invalid --iam-user"
  if [[ -n ${SSH_CIDR} ]]; then validate_cidr "${SSH_CIDR}"; fi
}

resolve_ssh_cidr() {
  if [[ ${NO_SSH} -eq 1 ]]; then
    SSH_CIDR=""
  elif [[ -z ${SSH_CIDR} ]]; then
    SSH_CIDR="$(detect_ssh_cidr)"
  fi
  log "SSH: ${SSH_CIDR:-closed}"
}
