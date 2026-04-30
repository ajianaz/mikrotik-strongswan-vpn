#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# setup.sh — Generate VPN configs from .env + templates
# =============================================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✅ $1${NC}"; }
fail() { echo -e "  ${RED}❌ $1${NC}"; }

# ── Find repo root ──
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [[ ! -f "${REPO_ROOT}/docker-compose.yml" ]]; do
  REPO_ROOT="$(dirname "${REPO_ROOT}")"
  if [[ "${REPO_ROOT}" == "/" ]]; then
    echo -e "${RED}Error: docker-compose.yml not found.${NC}" >&2
    exit 1
  fi
done

echo ""
echo "========================================"
echo "  VPN Config Generator"
echo "========================================"
echo ""

# ── Check .env ──
if [[ ! -f "${REPO_ROOT}/.env" ]]; then
  fail ".env not found. Run: cp .env.example .env && nano .env"
  exit 1
fi

# ── Source .env ──
set -a
# shellcheck source=/dev/null
source "${REPO_ROOT}/.env"
set +a

# ── Validate required vars ──
REQUIRED_VARS=(SERVER_PUBLIC_IP VPN_PSK CLIENT_LAN_SUBNET CLIENT_FQDN VPN_POOL_SUBNET)
missing=()
for var in "${REQUIRED_VARS[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    missing+=("${var}")
  fi
done

if [[ ${#missing[@]} -gt 0 ]]; then
  fail "Missing required variables: ${missing[*]}"
  exit 1
fi

pass "All required variables present"
echo "  SERVER_PUBLIC_IP = ${SERVER_PUBLIC_IP}"
echo "  CLIENT_LAN_SUBNET = ${CLIENT_LAN_SUBNET}"
echo "  VPN_POOL_SUBNET = ${VPN_POOL_SUBNET}"
echo "  CLIENT_FQDN = ${CLIENT_FQDN}"
echo "  VPN_PSK = $(echo "${VPN_PSK}" | head -c 8)...$(echo "${VPN_PSK}" | tail -c 5)"
echo ""

# ── Generate server config ──
TEMPLATE_SERVER="${REPO_ROOT}/server/swanctl/vpn.conf.example"
OUTPUT_SERVER="${REPO_ROOT}/server/swanctl/vpn.conf"

if [[ ! -f "${TEMPLATE_SERVER}" ]]; then
  fail "Template not found: ${TEMPLATE_SERVER}"
  exit 1
fi

sed \
  -e "s|{{SERVER_PUBLIC_IP}}|${SERVER_PUBLIC_IP}|g" \
  -e "s|{{VPN_PSK}}|${VPN_PSK}|g" \
  -e "s|{{VPN_POOL_SUBNET}}|${VPN_POOL_SUBNET}|g" \
  "${TEMPLATE_SERVER}" > "${OUTPUT_SERVER}"

chmod 600 "${OUTPUT_SERVER}"
pass "Generated: server/swanctl/vpn.conf (chmod 600)"

# ── Generate MikroTik client config ──
TEMPLATE_CLIENT="${REPO_ROOT}/client/mikrotik.rsc.example"
OUTPUT_CLIENT="${REPO_ROOT}/client/mikrotik.rsc"

if [[ ! -f "${TEMPLATE_CLIENT}" ]]; then
  fail "Template not found: ${TEMPLATE_CLIENT}"
  exit 1
fi

sed \
  -e "s|{{SERVER_PUBLIC_IP}}|${SERVER_PUBLIC_IP}|g" \
  -e "s|{{VPN_PSK}}|${VPN_PSK}|g" \
  -e "s|{{CLIENT_LAN_SUBNET}}|${CLIENT_LAN_SUBNET}|g" \
  -e "s|{{CLIENT_FQDN}}|${CLIENT_FQDN}|g" \
  -e "s|{{VPN_POOL_SUBNET}}|${VPN_POOL_SUBNET}|g" \
  "${TEMPLATE_CLIENT}" > "${OUTPUT_CLIENT}"

chmod 600 "${OUTPUT_CLIENT}"
pass "Generated: client/mikrotik.rsc (chmod 600)"

echo ""
echo -e "  ${GREEN}Setup complete. Run: bash scripts/deploy.sh${NC}"
echo ""
