#!/usr/bin/env bash
# =============================================================================================
# vpn-control — one-shot AWS setup of the Lightsail ingress (idempotent)
# =============================================================================================
# Creates (or converges) everything the control plane needs, using YOUR admin AWS credentials:
#   1. Lightsail instance (Ubuntu 24.04, cheapest IPv4 bundle, IPv4-only networking) whose launch
#      script runs deploy/ingress/bootstrap.sh with PUBLIC_BASE_URL + INGRESS_TOKEN from .env
#   2. Lightsail firewall: exactly VLESS/HY2/SS ports (+ SSH from your current IP)
#   3. a static IP named vpn-orchestrator-* (the control plane rotates it later)
#   4. IAM user "vpn-control" with the least-privilege inline policy from deploy/iam/lightsail.json
#      (pinned to this instance + region) and an access key
#   5. writes PROVIDER, AWS_REGION, INGRESS_INSTANCE, AWS_ACCESS_KEY_ID/SECRET into .env
#   6. optional: an AWS Budgets e-mail alarm
# Re-running changes nothing that is already correct (refreshes firewall + IAM policy).
#
# Usage
#   deploy/aws/setup-lightsail.sh [--profile admin] [--region ap-northeast-1] [options]
#
# Options
#   --env FILE            .env to read/update (default: <repo>/.env)
#   --profile NAME        AWS CLI profile with admin rights (default: your default credentials)
#   --region REGION       default: AWS_REGION from .env, else ap-northeast-1 (Tokyo)
#   --name NAME           instance name (default: INGRESS_INSTANCE from .env, else vpn-ingress)
#   --add-target ID       add a switchable target; preserve primary settings and existing policies
#   --bundle ID           Lightsail bundle (default: cheapest active Linux bundle with IPv4)
#   --blueprint ID        default: ubuntu_24_04
#   --az ZONE             availability zone (default: first available)
#   --ssh-cidr CIDR       allow SSH only from this IPv4 CIDR (default: your current IP /32)
#   --no-ssh              close port 22 entirely
#   --iam-user NAME       IAM user for the control plane (default: vpn-control)
#   --budget-email ADDR   create a monthly cost alarm sent to ADDR
#   --budget-usd N        budget amount in USD (default: 20)
#   -h, --help
# =============================================================================================
set -euo pipefail
umask 077
SCRIPT_NAME="setup-lightsail"
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { awk 'NR > 4 && /^# =+$/ { exit } NR > 4 { sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"; }

parse_common_args "$@"
((${#EXTRA_ARGS[@]} == 0)) || die "unknown option: ${EXTRA_ARGS[0]} (see --help)"

require_tools
require_env_file
load_ingress_settings

if [[ -z ${REGION} ]]; then
  REGION="$(env_get AWS_REGION)"
  REGION="${REGION:-ap-northeast-1}"
fi
if [[ -z ${NAME} ]]; then
  NAME="$(env_get INGRESS_INSTANCE)"
  [[ -n ${NAME} && ${NAME} != i-* ]] || NAME="vpn-ingress"
fi
validate_region "${REGION}"
validate_instance_name "${NAME}"
if [[ -n ${ADD_TARGET} ]]; then
  prepare_added_target "${ADD_TARGET}" "${REGION}" "${NAME}"
fi

resolve_account
resolve_ssh_cidr

log "ingress: ${NAME} in ${REGION}; control plane: ${CONTROL_PLANE_URL}"
provision_ingress "${REGION}" "${NAME}" "${BUNDLE}" "${BLUEPRINT}" "${AZ}" "${SSH_CIDR}"
ensure_iam "${REGION}" "${NAME}" "${ADD_TARGET:+${POLICY_NAME}-${ADD_TARGET}}"

if [[ -n ${ADD_TARGET} ]]; then
  env_set INGRESS_TARGETS "${UPDATED_TARGETS}"
  log "registered target ${ADD_TARGET}; primary settings preserved"
else
  env_set PROVIDER lightsail
  env_set AWS_REGION "${REGION}"
  env_set INGRESS_INSTANCE "${NAME}"
  log "updated ${ENV_FILE}: PROVIDER, AWS_REGION, INGRESS_INSTANCE, AWS_ACCESS_KEY_ID/SECRET"
fi

if [[ -n ${BUDGET_EMAIL} ]]; then
  ensure_budget "${BUDGET_EMAIL}" "${BUDGET_USD}"
fi

log "done — ingress ${NAME} (${REGION}) at ${INGRESS_IP}"
next_steps
