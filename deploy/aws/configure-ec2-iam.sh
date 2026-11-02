#!/usr/bin/env bash
# Attach the provisioning policy to the existing dedicated app user. Does not create servers,
# enable lifecycle mode, change keys, or delete existing policies.
set -euo pipefail
umask 077
SCRIPT_NAME=configure-ec2-iam
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
usage() { printf '%s\n' 'Usage: configure-ec2-iam.sh [--profile default] [--iam-user vpn-control]'; }
parse_common_args "$@"
((${#EXTRA_ARGS[@]} == 0)) || die "unknown option"
require_tools
resolve_account
aws_ iam get-user --user-name "${IAM_USER}" --output text >/dev/null
policy_name=vpn-control-ec2-provisioning-v1
policy_arn="arn:aws:iam::${ACCOUNT_ID}:policy/${policy_name}"
policy="$(sed "s/<ACCOUNT_ID>/${ACCOUNT_ID}/g" "${REPO_ROOT}/deploy/iam/ec2-provisioning.json")"
if ! err="$(aws_ iam get-policy --policy-arn "${policy_arn}" --output text 2>&1 >/dev/null)"; then
  [[ ${err} == *NoSuchEntity* ]] || die "get-policy failed: ${err}"
  aws_ iam create-policy --policy-name "${policy_name}" --policy-document "${policy}" --output text >/dev/null
fi
aws_ iam attach-user-policy --user-name "${IAM_USER}" --policy-arn "${policy_arn}"
log "attached on-demand provisioning permissions to ${IAM_USER}; no servers changed"
