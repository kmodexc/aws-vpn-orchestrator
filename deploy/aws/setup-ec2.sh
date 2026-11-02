#!/usr/bin/env bash
# =============================================================================================
# vpn-control — prepare EC2 on-demand infrastructure (idempotent)
# =============================================================================================
#
# This administrator-side script prepares durable EC2 infrastructure and configures .env. It
# deliberately does not launch an EC2 ingress: the Rust lifecycle manager launches, bootstraps,
# tags, switches and cleans up disposable instances so their inventory stays in state.json.
#
# It creates/reuses a dedicated public VPC, subnet, internet gateway, route table and security
# group per region, discovers a Canonical Ubuntu 24.04 AMI, attaches the EC2 provisioning policy,
# and writes EC2_REGION_CONFIG for the application.
#
# Usage: deploy/aws/setup-ec2.sh [options]
#   --env FILE             .env to read/update (default: <repo>/.env)
#   --profile NAME         AWS CLI administrator profile
#   --regions CSV          regions (default: INGRESS_REGIONS or the supported regions)
#   --instance-type TYPE   t3.nano, t3.micro, t4g.nano or t4g.micro (default: t3.nano)
#   --root-volume-gib N    encrypted gp3 root volume size, 8..64 (default: 8)
#   --iam-user NAME        control-plane IAM user (default: vpn-control)
#   -y, --yes              do not ask for confirmation
#   -h, --help             show this help
#
# Network resources are tagged vpn-control-network=managed and are never deleted by this script.
# =============================================================================================
set -euo pipefail
umask 077

SCRIPT_NAME="setup-ec2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${SCRIPT_DIR}/lib.sh"

readonly NETWORK_TAG_KEY="vpn-control-network"
readonly NETWORK_TAG_VALUE="managed"
readonly REGION_TAG_KEY="vpn-control-region"
readonly CANONICAL_OWNER="099720109477"
readonly DEFAULT_REGIONS="ap-northeast-1,ap-southeast-1,ap-east-1"

ENV_FILE="${REPO_ROOT}/.env"
AWS_ARGS=()
ASSUME_YES=0
IAM_USER="vpn-control"
REGIONS_RAW=""
INSTANCE_TYPE="t3.nano"
ROOT_VOLUME_GIB=8

usage() {
  awk 'NR > 4 && /^# =+$/ { exit } NR > 4 { sub(/^# ?/, ""); print }' "${BASH_SOURCE[0]}"
}

die_usage() { die "$1 (see --help)"; }

while (($#)); do
  case "$1" in
    --env) (($# >= 2)) || die_usage "--env requires a file"; ENV_FILE=$2; shift 2 ;;
    --profile) (($# >= 2)) || die_usage "--profile requires a name"; AWS_ARGS+=(--profile "$2"); shift 2 ;;
    --regions) (($# >= 2)) || die_usage "--regions requires a CSV list"; REGIONS_RAW=$2; shift 2 ;;
    --instance-type) (($# >= 2)) || die_usage "--instance-type requires a value"; INSTANCE_TYPE=$2; shift 2 ;;
    --root-volume-gib) (($# >= 2)) || die_usage "--root-volume-gib requires a value"; ROOT_VOLUME_GIB=$2; shift 2 ;;
    --iam-user) (($# >= 2)) || die_usage "--iam-user requires a name"; IAM_USER=$2; shift 2 ;;
    -y | --yes) ASSUME_YES=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die_usage "unknown option: $1" ;;
  esac
done

require_tools
require_env_file

[[ ${IAM_USER} =~ ^[A-Za-z0-9+=,.@_-]{1,64}$ ]] || die "invalid --iam-user"
case "${INSTANCE_TYPE}" in
  t3.nano | t3.micro | t4g.nano | t4g.micro) ;;
  *) die "unsupported instance type '${INSTANCE_TYPE}'" ;;
esac
[[ ${ROOT_VOLUME_GIB} =~ ^[0-9]+$ ]] && ((ROOT_VOLUME_GIB >= 8 && ROOT_VOLUME_GIB <= 64)) \
  || die "--root-volume-gib must be an integer from 8 to 64"
if [[ -z ${REGIONS_RAW} ]]; then
  REGIONS_RAW="$(env_get INGRESS_REGIONS)"
  REGIONS_RAW="${REGIONS_RAW:-${DEFAULT_REGIONS}}"
fi

case "${INSTANCE_TYPE}" in
  t3.*) AMI_ARCH="amd64" ;;
  t4g.*) AMI_ARCH="arm64" ;;
esac

declare -a REGIONS=()
IFS=',' read -r -a raw_regions <<< "${REGIONS_RAW}"
for raw_region in "${raw_regions[@]}"; do
  region="${raw_region//[[:space:]]/}"
  [[ -n ${region} ]] || continue
  validate_region "${region}"
  case "${region}" in
    ap-northeast-1 | ap-southeast-1 | ap-east-1) ;;
    *) die "${region} is not supported by the EC2 provisioning policy" ;;
  esac
  for existing in "${REGIONS[@]}"; do
    [[ ${existing} != "${region}" ]] || die "duplicate region '${region}'"
  done
  REGIONS+=("${region}")
done
((${#REGIONS[@]} > 0)) || die "at least one region is required"

tag_spec() {
  local resource=$1 region=$2 name=$3
  printf 'ResourceType=%s,Tags=[{Key=Name,Value=%s},{Key=%s,Value=%s},{Key=%s,Value=%s}]' \
    "${resource}" "${name}" "${NETWORK_TAG_KEY}" "${NETWORK_TAG_VALUE}" \
    "${REGION_TAG_KEY}" "${region}"
}

one_id() {
  local ids=$1 label=$2 id count=0
  for id in ${ids}; do
    [[ ${id} != None ]] || continue
    printf '%s\n' "${id}"
    count=$((count + 1))
  done
  ((count == 1)) || die "expected exactly one tagged ${label}, found ${count}"
}

find_tagged() {
  local resource=$1 region=$2 query
  case "${resource}" in
    vpc) query='Vpcs[].VpcId' ;;
    subnet) query='Subnets[].SubnetId' ;;
    security-group) query='SecurityGroups[].GroupId' ;;
    internet-gateway) query='InternetGateways[].InternetGatewayId' ;;
    route-table) query='RouteTables[].RouteTableId' ;;
    *) die "internal error: unknown resource ${resource}" ;;
  esac
  aws_ "ec2" "describe-${resource}s" \
    --filters "Name=tag:${NETWORK_TAG_KEY},Values=${NETWORK_TAG_VALUE}" \
              "Name=tag:${REGION_TAG_KEY},Values=${region}" \
    --query "${query}" --output text
}

env_unset() {
  local key=$1 tmp
  tmp="$(mktemp "${ENV_FILE}.XXXXXX")"
  awk -v K="${key}" 'index($0, K "=") != 1 { print }' "${ENV_FILE}" >"${tmp}" \
    || { rm -f "${tmp}"; die "could not update ${ENV_FILE}"; }
  chmod 600 "${tmp}"
  mv -f "${tmp}" "${ENV_FILE}"
}

choose_vpc_cidr() {
  local octet cidr used
  for octet in 250 251 252 253 254; do
    cidr="10.${octet}.0.0/16"
    used="$(aws_ ec2 describe-vpcs --region "${CURRENT_REGION}" \
      --filters "Name=cidr-block,Values=${cidr}" --query 'length(Vpcs)' --output text)"
    [[ ${used} == 0 ]] && { printf '%s\n' "${cidr}"; return; }
  done
  die "no unused 10.x.0.0/16 CIDR is available in ${CURRENT_REGION}"
}

ensure_vpc() {
  local ids cidr
  ids="$(find_tagged vpc "${CURRENT_REGION}")"
  if [[ -n ${ids} && ${ids} != None ]]; then
    VPC_ID="$(one_id "${ids}" VPC)"
    return
  fi
  cidr="$(choose_vpc_cidr)"
  log "creating VPC ${cidr} in ${CURRENT_REGION}"
  VPC_ID="$(aws_ ec2 create-vpc --region "${CURRENT_REGION}" --cidr-block "${cidr}" \
    --tag-specifications "$(tag_spec vpc "${CURRENT_REGION}" "vpn-control-${CURRENT_REGION}")" \
    --query Vpc.VpcId --output text)"
  aws_ ec2 wait vpc-available --region "${CURRENT_REGION}" --vpc-ids "${VPC_ID}"
  aws_ ec2 modify-vpc-attribute --region "${CURRENT_REGION}" --vpc-id "${VPC_ID}" \
    --enable-dns-support '{"Value":true}'
  aws_ ec2 modify-vpc-attribute --region "${CURRENT_REGION}" --vpc-id "${VPC_ID}" \
    --enable-dns-hostnames '{"Value":true}'
}

ensure_internet_gateway() {
  local ids attached
  ids="$(find_tagged internet-gateway "${CURRENT_REGION}")"
  if [[ -n ${ids} && ${ids} != None ]]; then
    IGW_ID="$(one_id "${ids}" internet gateway)"
  else
    log "creating internet gateway in ${CURRENT_REGION}"
    IGW_ID="$(aws_ ec2 create-internet-gateway --region "${CURRENT_REGION}" \
      --tag-specifications "$(tag_spec internet-gateway "${CURRENT_REGION}" "vpn-control-${CURRENT_REGION}-igw")" \
      --query InternetGateway.InternetGatewayId --output text)"
  fi
  attached="$(aws_ ec2 describe-internet-gateways --region "${CURRENT_REGION}" \
    --internet-gateway-ids "${IGW_ID}" \
    --query 'InternetGateways[0].Attachments[?VpcId==`'"${VPC_ID}"'`].State | [0]' \
    --output text)"
  if [[ ${attached} != available && ${attached} != attached ]]; then
    aws_ ec2 attach-internet-gateway --region "${CURRENT_REGION}" \
      --internet-gateway-id "${IGW_ID}" --vpc-id "${VPC_ID}"
  fi
}

ensure_subnet() {
  local ids az prefix cidr
  ids="$(find_tagged subnet "${CURRENT_REGION}")"
  if [[ -n ${ids} && ${ids} != None ]]; then
    SUBNET_ID="$(one_id "${ids}" subnet)"
  else
    az="$(aws_ ec2 describe-availability-zones --region "${CURRENT_REGION}" \
      --filters Name=state,Values=available --query 'AvailabilityZones[0].ZoneName' --output text)"
    [[ -n ${az} && ${az} != None ]] || die "no available availability zone in ${CURRENT_REGION}"
    prefix="$(aws_ ec2 describe-vpcs --region "${CURRENT_REGION}" --vpc-ids "${VPC_ID}" \
      --query 'Vpcs[0].CidrBlock' --output text | awk -F. '{print $1"."$2}')"
    cidr="${prefix}.1.0/24"
    log "creating public subnet ${cidr} in ${az}"
    SUBNET_ID="$(aws_ ec2 create-subnet --region "${CURRENT_REGION}" --vpc-id "${VPC_ID}" \
      --cidr-block "${cidr}" --availability-zone "${az}" \
      --tag-specifications "$(tag_spec subnet "${CURRENT_REGION}" "vpn-control-${CURRENT_REGION}-subnet")" \
      --query Subnet.SubnetId --output text)"
    aws_ ec2 wait subnet-available --region "${CURRENT_REGION}" --subnet-ids "${SUBNET_ID}"
  fi
  aws_ ec2 modify-subnet-attribute --region "${CURRENT_REGION}" \
    --subnet-id "${SUBNET_ID}" --map-public-ip-on-launch
}

ensure_route_table() {
  local ids route_gateway existing_assoc
  ids="$(find_tagged route-table "${CURRENT_REGION}")"
  if [[ -n ${ids} && ${ids} != None ]]; then
    ROUTE_TABLE_ID="$(one_id "${ids}" route table)"
  else
    log "creating public route table in ${CURRENT_REGION}"
    ROUTE_TABLE_ID="$(aws_ ec2 create-route-table --region "${CURRENT_REGION}" \
      --vpc-id "${VPC_ID}" \
      --tag-specifications "$(tag_spec route-table "${CURRENT_REGION}" "vpn-control-${CURRENT_REGION}-public")" \
      --query RouteTable.RouteTableId --output text)"
  fi
  route_gateway="$(aws_ ec2 describe-route-tables --region "${CURRENT_REGION}" \
    --route-table-ids "${ROUTE_TABLE_ID}" \
    --query 'RouteTables[0].Routes[?DestinationCidrBlock==`0.0.0.0/0`].GatewayId | [0]' \
    --output text)"
  if [[ ${route_gateway} == None || -z ${route_gateway} ]]; then
    aws_ ec2 create-route --region "${CURRENT_REGION}" --route-table-id "${ROUTE_TABLE_ID}" \
      --destination-cidr-block 0.0.0.0/0 --gateway-id "${IGW_ID}"
  elif [[ ${route_gateway} != "${IGW_ID}" ]]; then
    aws_ ec2 replace-route --region "${CURRENT_REGION}" --route-table-id "${ROUTE_TABLE_ID}" \
      --destination-cidr-block 0.0.0.0/0 --gateway-id "${IGW_ID}"
  fi
  existing_assoc="$(aws_ ec2 describe-route-tables --region "${CURRENT_REGION}" \
    --route-table-ids "${ROUTE_TABLE_ID}" \
    --query 'RouteTables[0].Associations[?SubnetId==`'"${SUBNET_ID}"'`].RouteTableAssociationId | [0]' \
    --output text)"
  if [[ ${existing_assoc} == None || -z ${existing_assoc} ]]; then
    aws_ ec2 associate-route-table --region "${CURRENT_REGION}" \
      --route-table-id "${ROUTE_TABLE_ID}" --subnet-id "${SUBNET_ID}" >/dev/null
  fi
}

authorize_rule() {
  local protocol=$1 port=$2 cidr=$3 err
  if ! err="$(aws_ ec2 authorize-security-group-ingress --region "${CURRENT_REGION}" \
    --group-id "${SG_ID}" --protocol "${protocol}" --port "${port}" --cidr "${cidr}" 2>&1)"; then
    [[ ${err} == *InvalidPermission.Duplicate* ]] || die "security group rule failed: ${err}"
  fi
}

ensure_security_group() {
  local ids
  ids="$(find_tagged security-group "${CURRENT_REGION}")"
  if [[ -n ${ids} && ${ids} != None ]]; then
    SG_ID="$(one_id "${ids}" security group)"
  else
    log "creating security group in ${CURRENT_REGION}"
    SG_ID="$(aws_ ec2 create-security-group --region "${CURRENT_REGION}" \
      --group-name "vpn-control-${CURRENT_REGION}" \
      --description "vpn-control EC2 on-demand ingress (${CURRENT_REGION})" \
      --vpc-id "${VPC_ID}" \
      --tag-specifications "$(tag_spec security-group "${CURRENT_REGION}" "vpn-control-${CURRENT_REGION}-sg")" \
      --query GroupId --output text)"
  fi
  authorize_rule tcp "${VLESS_PORT}" 0.0.0.0/0
  authorize_rule udp "${HY2_PORT}" 0.0.0.0/0
  authorize_rule tcp "${SS_PORT}" 0.0.0.0/0
  authorize_rule udp "${SS_PORT}" 0.0.0.0/0
}

find_ami() {
  local image
  image="$(aws_ ec2 describe-images --region "${CURRENT_REGION}" --owners "${CANONICAL_OWNER}" \
    --filters \
      "Name=name,Values=ubuntu/images/*/ubuntu-noble-24.04-${AMI_ARCH}-server-*" \
      Name=state,Values=available Name=root-device-type,Values=ebs \
    --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)"
  [[ -n ${image} && ${image} != None ]] || die "no Canonical Ubuntu 24.04 ${AMI_ARCH} AMI found in ${CURRENT_REGION}"
  printf '%s\n' "${image}"
}

require_env_file
load_ingress_settings
resolve_account

if [[ $(env_get INGRESS_ON_DEMAND) == true && $(env_get PROVIDER) == lightsail ]]; then
  warn "reconcile persisted Lightsail lifecycle state before restarting the app with EC2"
fi

log "regions: ${REGIONS[*]}"
log "instance type: ${INSTANCE_TYPE}; root volume: ${ROOT_VOLUME_GIB} GiB; SSH: disabled"
confirm "Create/reuse EC2 networking and update ${ENV_FILE}? Type EC2 to continue:" EC2

VLESS_PORT="$(env_get VLESS_PORT)"; VLESS_PORT="${VLESS_PORT:-443}"
HY2_PORT="$(env_get HY2_PORT)"; HY2_PORT="${HY2_PORT:-443}"
SS_PORT="$(env_get SS_PORT)"; SS_PORT="${SS_PORT:-8443}"

CONFIG_JSON="{"
for CURRENT_REGION in "${REGIONS[@]}"; do
  log "preparing ${CURRENT_REGION}"
  ensure_vpc
  ensure_internet_gateway
  ensure_subnet
  ensure_route_table
  ensure_security_group
  AMI_ID="$(find_ami)"
  log "${CURRENT_REGION}: AMI ${AMI_ID}, subnet ${SUBNET_ID}, security group ${SG_ID}"
  [[ ${CONFIG_JSON} == "{" ]] || CONFIG_JSON+=","
  CONFIG_JSON+="\"${CURRENT_REGION}\":{\"ami_id\":\"${AMI_ID}\",\"subnet_id\":\"${SUBNET_ID}\",\"security_group_ids\":[\"${SG_ID}\"]}"
done
CONFIG_JSON+="}"

iam_args=(--iam-user "${IAM_USER}")
if ((${#AWS_ARGS[@]})); then iam_args+=("${AWS_ARGS[@]}"); fi
bash "${SCRIPT_DIR}/configure-ec2-iam.sh" "${iam_args[@]}"

env_set PROVIDER ec2
env_set AWS_REGION "${REGIONS[0]}"
env_set INGRESS_ON_DEMAND true
env_set INGRESS_ADOPT_EXISTING false
env_set INGRESS_REGIONS "$(printf '%s' "${REGIONS_RAW}" | tr -d '[:space:]')"
env_set EC2_INSTANCE_TYPE "${INSTANCE_TYPE}"
env_set EC2_ROOT_VOLUME_GIB "${ROOT_VOLUME_GIB}"
env_set EC2_REGION_CONFIG "${CONFIG_JSON}"
env_unset INGRESS_INSTANCE
env_unset INGRESS_TARGETS

log "updated ${ENV_FILE} for EC2 on-demand mode"
log "next: deploy the new image, then choose a region in the dashboard to launch the first ingress"
