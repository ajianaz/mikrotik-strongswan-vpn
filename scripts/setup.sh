#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# setup.sh — Generate VPN configs from .env + templates
# =============================================================================
#
# Output:
#   config/swanctl.conf    — include loader (static, always exists)
#   config/conf.d/vpn.conf — connection config (generated from template)
#   config/secret          — PSK secrets (generated, chmod 640)
#   client/mikrotik.rsc    — MikroTik import script (generated)
#
# These files are bind-mounted into vpn-server and vpn-manager containers.
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

CONFIG_DIR="${REPO_ROOT}/config"
CONF_DIR="${CONFIG_DIR}/conf.d"

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

# ── Sanitize inputs before sed (prevent injection) ──
sanitize() {
  local var_name="$1" var_value="$2" pattern="$3" description="$4"
  if ! echo "${var_value}" | grep -qE "${pattern}"; then
    fail "${var_name} contains invalid characters (${description})"
    exit 1
  fi
}

sanitize "SERVER_PUBLIC_IP" "${SERVER_PUBLIC_IP}" '^[0-9.]+$' "IP only"
sanitize "VPN_POOL_SUBNET" "${VPN_POOL_SUBNET}" '^[0-9./]+$' "CIDR only"
sanitize "CLIENT_LAN_SUBNET" "${CLIENT_LAN_SUBNET}" '^[0-9./]+$' "CIDR only"
sanitize "CLIENT_FQDN" "${CLIENT_FQDN}" '^[a-zA-Z0-9._-]+$' "FQDN chars only"
# PSK: allow base64 chars + common special chars, block shell metacharacters
sanitize "VPN_PSK" "${VPN_PSK}" '^[A-Za-z0-9+/=@._-]+$' "base64-safe chars only"

pass "Input sanitization passed"
echo ""

# ── Ensure config directories exist ──
mkdir -p "${CONF_DIR}"
mkdir -p "${CONFIG_DIR}/pki"
pass "Created config directories"

# ── Generate swanctl.conf (include loader) — only if not already present ──
if [[ ! -f "${CONFIG_DIR}/swanctl.conf" ]]; then
  cat > "${CONFIG_DIR}/swanctl.conf" << 'SWANCTL'
swanctl {
  load = {
    confd_dir = /etc/swanctl/conf.d
    secrets_file = /etc/swanctl/secret
  }
}
SWANCTL
  pass "Generated: config/swanctl.conf"
else
  pass "config/swanctl.conf already exists (skipped)"
fi

# ── Generate server connection config ──
TEMPLATE_SERVER="${REPO_ROOT}/server/swanctl/vpn.conf.example"
OUTPUT_SERVER="${CONF_DIR}/vpn.conf"

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
pass "Generated: config/conf.d/vpn.conf (chmod 600)"

# ── Generate secrets file (separate from connection config) ──
# strongSwan expects secrets in a dedicated file
SECRET_FILE="${CONFIG_DIR}/secret"
cat > "${SECRET_FILE}" << SECRET
# strongSwan secrets — PSK for IKEv2 roadwarrior
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)
ike-psk {
    id-1 = ${SERVER_PUBLIC_IP}
    id-2 = %any
    secret = "${VPN_PSK}"
}
SECRET
chmod 640 "${SECRET_FILE}"
pass "Generated: config/secret (chmod 640)"

# ── Generate MikroTik client config ──
TEMPLATE_CLIENT="${REPO_ROOT}/client/mikrotik.rsc.example"
OUTPUT_CLIENT="${REPO_ROOT}/client/mikrotik.rsc"

if [[ -f "${TEMPLATE_CLIENT}" ]]; then
  sed \
    -e "s|{{SERVER_PUBLIC_IP}}|${SERVER_PUBLIC_IP}|g" \
    -e "s|{{VPN_PSK}}|${VPN_PSK}|g" \
    -e "s|{{CLIENT_LAN_SUBNET}}|${CLIENT_LAN_SUBNET}|g" \
    -e "s|{{CLIENT_FQDN}}|${CLIENT_FQDN}|g" \
    -e "s|{{VPN_POOL_SUBNET}}|${VPN_POOL_SUBNET}|g" \
    "${TEMPLATE_CLIENT}" > "${OUTPUT_CLIENT}"

  chmod 600 "${OUTPUT_CLIENT}"
  pass "Generated: client/mikrotik.rsc (chmod 600)"
else
  fail "Template not found: ${TEMPLATE_CLIENT}"
fi

echo ""
echo -e "  ${GREEN}Setup complete.${NC}"
echo "  Config files ready at: ${CONFIG_DIR}/"
echo ""
echo "  Next step: bash scripts/deploy.sh"
echo ""
