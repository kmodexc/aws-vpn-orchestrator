#!/usr/bin/env bash
# =============================================================================================
# vpn-control — remove the Lightsail ingress and its AWS resources
# =============================================================================================
# Using YOUR admin AWS credentials it deletes:
#   1. the ingress instance from .env (AWS_REGION / INGRESS_INSTANCE)
#   2. its static IP and any unattached vpn-orchestrator-* static IPs in that region
#   3. the control plane's IAM user (access keys + inline policy) unless --keep-iam
#   4. the cost alarm, if --budget is given
# and clears AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in .env. Nothing else is touched.
#
# Usage
#   deploy/aws/teardown-lightsail.sh [--profile admin] [options]
#
# Options
#   --region REGION / --name NAME   override the ingress taken from .env
#   --keep-iam            keep the IAM user and its key
#   --budget              also delete the vpn-orchestrator-monthly budget
#   -y, --yes             do not ask for confirmation
#   --env, --profile, --iam-user    as in setup-lightsail.sh
#   -h, --help
# =============================================================================================
set -euo pipefail
umask 077
SCRIPT_NAME="teardown-lightsail"
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() { awk 'NR > 4 && /^# =+$/ { exit } NR > 4 { sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"; }

parse_common_args "$@"
KEEP_IAM=0 DELETE_BUDGET=0
for arg in ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}; do
  case ${arg} in
    --keep-iam) KEEP_IAM=1 ;;
    --budget) DELETE_BUDGET=1 ;;
    *) die "unknown option: ${arg} (see --help)" ;;
  esac
done

require_tools
require_env_file
[[ -n ${REGION} ]] || REGION="$(env_get AWS_REGION)"
[[ -n ${NAME} ]] || NAME="$(env_get INGRESS_INSTANCE)"
validate_region "${REGION}"
validate_instance_name "${NAME}"

resolve_account

log "this deletes ingress ${NAME} in ${REGION}$([[ ${KEEP_IAM} -eq 1 ]] || printf ' and IAM user %s' "${IAM_USER}")"
confirm "Type the instance name to confirm:" "${NAME}"

destroy_ingress "${REGION}" "${NAME}"
if [[ ${KEEP_IAM} -eq 0 ]]; then
  delete_iam_user
  env_set AWS_ACCESS_KEY_ID ""
  env_set AWS_SECRET_ACCESS_KEY ""
  log "cleared AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in ${ENV_FILE}"
fi
if [[ ${DELETE_BUDGET} -eq 1 ]]; then
  delete_budget
fi

log "done. The control plane can no longer manage an ingress; stop it with 'docker compose down' or run setup-lightsail.sh again."
