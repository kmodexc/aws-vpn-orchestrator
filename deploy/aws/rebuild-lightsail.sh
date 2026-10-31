#!/usr/bin/env bash
# =============================================================================================
# vpn-control — rebuild the Lightsail ingress (typically in another region)
# =============================================================================================
# For when rotating the IP is not enough (e.g. a whole AWS range is blocked). Using YOUR admin
# AWS credentials it:
#   1. creates a fresh ingress (instance, firewall, static IP) in --region
#   2. re-pins the control plane's IAM policy to the new instance + region (same access key)
#   3. switches AWS_REGION / INGRESS_INSTANCE in .env
#   4. deletes the old instance and releases its vpn-orchestrator-* static IPs (unless --keep-old)
# Secrets do not change: clients keep the same subscription URL and pick up the new IP.
#
# Usage
#   deploy/aws/rebuild-lightsail.sh --region ap-southeast-1 [--profile admin] [options]
#
# Options
#   --region REGION       target region (required)
#   --name NAME           new instance name (default: vpn-ingress-<region>-<date>)
#   --keep-old            do not delete the old instance (it keeps costing money)
#   -y, --yes             do not ask before deleting the old instance
#   --env, --profile, --bundle, --blueprint, --az, --ssh-cidr, --no-ssh, --iam-user
#                         as in setup-lightsail.sh
#   -h, --help
# =============================================================================================
set -euo pipefail
umask 077
SCRIPT_NAME="rebuild-lightsail"
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { awk 'NR > 4 && /^# =+$/ { exit } NR > 4 { sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"; }

parse_common_args "$@"
KEEP_OLD=0
for arg in ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}; do
  case ${arg} in
    --keep-old) KEEP_OLD=1 ;;
    *) die "unknown option: ${arg} (see --help)" ;;
  esac
done

require_tools
require_env_file
load_ingress_settings

[[ $(env_get PROVIDER) == lightsail ]] || die "PROVIDER in .env is not 'lightsail' — run setup-lightsail.sh first"
OLD_REGION="$(env_get AWS_REGION)"
OLD_NAME="$(env_get INGRESS_INSTANCE)"
validate_region "${OLD_REGION}"
validate_instance_name "${OLD_NAME}"

[[ -n ${REGION} ]] || die "--region is required"
validate_region "${REGION}"
[[ -n ${NAME} ]] || NAME="vpn-ingress-${REGION}-$(date +%Y%m%d%H%M)"
validate_instance_name "${NAME}"
[[ ${REGION}/${NAME} != "${OLD_REGION}/${OLD_NAME}" ]] || die "new and old ingress are identical; pick another --name or --region"

resolve_account
resolve_ssh_cidr

log "rebuilding: ${OLD_NAME} (${OLD_REGION}) -> ${NAME} (${REGION})"
provision_ingress "${REGION}" "${NAME}" "${BUNDLE}" "${BLUEPRINT}" "${AZ}" "${SSH_CIDR}"
ensure_iam "${REGION}" "${NAME}"
env_set AWS_REGION "${REGION}"
env_set INGRESS_INSTANCE "${NAME}"
log "updated ${ENV_FILE}: AWS_REGION=${REGION}, INGRESS_INSTANCE=${NAME}"

if [[ ${KEEP_OLD} -eq 1 ]]; then
  warn "keeping old instance ${OLD_NAME} in ${OLD_REGION} (it still costs money; the control plane no longer manages it)"
else
  confirm "Delete old instance '${OLD_NAME}' in ${OLD_REGION}? Type its name to confirm:" "${OLD_NAME}"
  destroy_ingress "${OLD_REGION}" "${OLD_NAME}"
fi

log "done — new ingress ${NAME} (${REGION}) at ${INGRESS_IP}"
next_steps
