#!/usr/bin/env bash
# Local regression checks; all AWS operations are mocked.
set -euo pipefail
umask 077
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEST_TMP="$(mktemp -d)"
trap 'rm -rf "${TEST_TMP}"' EXIT
export TEST_REAL_LIB="${TEST_ROOT}/deploy/aws/lib.sh"
SCRIPT_NAME=setup-lightsail
. "${TEST_REAL_LIB}"
ENV_FILE="${TEST_TMP}/app.env"
cat >"${ENV_FILE}" <<'EOF'
PROVIDER=lightsail
AWS_REGION=ap-northeast-1
INGRESS_INSTANCE=vpn-ingress
AWS_ACCESS_KEY_ID=EXISTING_KEY
AWS_SECRET_ACCESS_KEY=unchanged-secret
EOF
prepare_added_target singapore ap-southeast-1 vpn-ingress-singapore
expected='default|lightsail|ap-northeast-1|vpn-ingress;singapore|lightsail|ap-southeast-1|vpn-ingress-singapore'
[[ ${UPDATED_TARGETS} == "${expected}" ]]
env_set INGRESS_TARGETS "${UPDATED_TARGETS}"
prepare_added_target singapore ap-southeast-1 vpn-ingress-singapore
[[ ${UPDATED_TARGETS} == "${expected}" ]]
if (prepare_added_target singapore ap-east-1 other) 2>/dev/null; then exit 1; fi
if (prepare_added_target other ap-southeast-1 vpn-ingress-singapore) 2>/dev/null; then exit 1; fi
if (prepare_added_target 'bad.id' ap-east-1 other) 2>/dev/null; then exit 1; fi

# Exercise actual IAM handling with two tab-separated keys. Creating a key is forbidden.
ACCOUNT_ID=123456789012
IAM_USER=vpn-control
ADD_TARGET=singapore
instance_field() { printf 'arn:aws:lightsail:%s:123456789012:Instance/test-id\n' "$1"; }
aws_() {
  case "$1 $2" in
    'iam get-user') return 0 ;;
    'iam get-policy') [[ -f ${TEST_TMP}/policy-call ]] && return 0; echo NoSuchEntity >&2; return 1 ;;
    'iam create-policy') [[ ! -f ${TEST_TMP}/policy-call ]]; printf '%s\n' "$@" >"${TEST_TMP}/policy-call" ;;
    'iam attach-user-policy') printf '%s\n' "$@" >"${TEST_TMP}/attach-call" ;;
    'iam list-access-keys') printf 'OTHER_KEY\tEXISTING_KEY\n' ;;
    *) echo "Unexpected AWS mutation: $*" >&2; return 1 ;;
  esac
}
ensure_iam ap-southeast-1 vpn-ingress-singapore vpn-control-lightsail-singapore
rg -q '^vpn-control-lightsail-singapore-test-id-v1$' "${TEST_TMP}/policy-call"
rg -q 'policy/vpn-control-lightsail-singapore-test-id-v1$' "${TEST_TMP}/attach-call"
ensure_iam ap-southeast-1 vpn-ingress-singapore vpn-control-lightsail-singapore
[[ $(env_get AWS_ACCESS_KEY_ID) == EXISTING_KEY ]]
[[ $(env_get AWS_SECRET_ACCESS_KEY) == unchanged-secret ]]

# Run the setup entrypoint with provisioning and IAM mocked, but real env/target handling.
cp "${TEST_ROOT}/deploy/aws/setup-lightsail.sh" "${TEST_TMP}/setup-lightsail.sh"
cat >"${TEST_TMP}/lib.sh" <<'EOF'
. "${TEST_REAL_LIB}"
require_tools() { :; }
load_ingress_settings() { CONTROL_PLANE_URL=https://example.test; }
resolve_account() { :; }
resolve_ssh_cidr() { SSH_CIDR=''; }
provision_ingress() { INGRESS_IP=192.0.2.1; }
ensure_iam() { [[ $3 == "vpn-control-lightsail-${ADD_TARGET}" ]]; }
next_steps() { :; }
EOF
bash "${TEST_TMP}/setup-lightsail.sh" --env "${ENV_FILE}" --region ap-east-1 \
  --name vpn-ingress-hongkong --add-target hongkong
[[ $(env_get AWS_REGION) == ap-northeast-1 ]]
[[ $(env_get INGRESS_INSTANCE) == vpn-ingress ]]
[[ $(env_get AWS_ACCESS_KEY_ID) == EXISTING_KEY ]]
[[ $(env_get AWS_SECRET_ACCESS_KEY) == unchanged-secret ]]
[[ $(env_get INGRESS_TARGETS) == "${expected};hongkong|lightsail|ap-east-1|vpn-ingress-hongkong" ]]
bash "${TEST_TMP}/setup-lightsail.sh" --env "${ENV_FILE}" --region ap-east-1 \
  --name vpn-ingress-hongkong --add-target hongkong
[[ $(env_get INGRESS_TARGETS) == "${expected};hongkong|lightsail|ap-east-1|vpn-ingress-hongkong" ]]
echo 'add-target regression checks passed'
