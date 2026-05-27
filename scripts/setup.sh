#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# setup.sh — Generate VPN configs from .env + templates
# =============================================================================
#
# Output:
#   config/swanctl.conf              — include loader (static, always exists)
#   config/conf.d/roadwarrior-eap.conf — EAP connection config (generated from template)
#
# With named volumes (vpn-configs), configs are copied into the Docker volume
# via deploy.sh after first compose up. vpn-manager API writes runtime configs
# directly into the shared volume at /etc/swanctl/conf.d/.
#
# Auth credentials (EAP users, L2TP secrets) are managed via the API:
#   POST /api/v1/tunnels
#
# =============================================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✅ $1${NC}"; }
fail() { echo -e "  ${RED}❌ $1${NC}"; }
warn() { echo -e "  ${YELLOW}⚠️  $1${NC}"; }

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

# ── Set defaults ──
AUTH_TYPE="${AUTH_TYPE:-eap}"

# ── Validate required vars ──
REQUIRED_VARS=(SERVER_PUBLIC_IP VPN_POOL_SUBNET)
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
echo "  VPN_POOL_SUBNET = ${VPN_POOL_SUBNET}"
echo "  AUTH_TYPE = ${AUTH_TYPE}"
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

# ── Generate EAP connection config (if AUTH_TYPE contains "eap") ──
if [[ "${AUTH_TYPE}" == *"eap"* ]]; then
  TEMPLATE_EAP="${REPO_ROOT}/server/swanctl/roadwarrior-eap.conf.example"
  OUTPUT_EAP="${CONF_DIR}/roadwarrior-eap.conf"

  if [[ -f "${TEMPLATE_EAP}" ]]; then
    sed \
      -e "s|{{SERVER_PUBLIC_IP}}|${SERVER_PUBLIC_IP}|g" \
      -e "s|{{VPN_POOL_SUBNET}}|${VPN_POOL_SUBNET}|g" \
      "${TEMPLATE_EAP}" > "${OUTPUT_EAP}"

    chmod 600 "${OUTPUT_EAP}"
    pass "Generated: config/conf.d/roadwarrior-eap.conf (EAP mode)"
    echo "  EAP mode: tunnel credentials managed via API (POST /api/v1/tunnels)"
  else
    fail "Template not found: ${TEMPLATE_EAP}"
    exit 1
  fi
fi

# ── Generate L2TP config (if AUTH_TYPE contains "l2tp") ──
if [[ "${AUTH_TYPE}" == *"l2tp"* ]]; then
  # xl2tpd config is baked into the Docker image; no file generation needed
  pass "L2TP mode: xl2tpd config managed by Docker image"
fi

# ── Sync configs to Docker volume ──
# Named volumes need explicit copy — bootstrap via temporary container
echo ""
echo "  Syncing configs to Docker volume (vpn-configs)..."

if docker volume inspect vpn-configs >/dev/null 2>&1; then
  docker run --rm \
    -v "vpn-configs:/etc/swanctl" \
    -v "${CONFIG_DIR}:/host-config:ro" \
    alpine sh -c "
      cp -a /host-config/. /etc/swanctl/ 2>/dev/null || true
      chmod 600 /etc/swanctl/conf.d/*.conf 2>/dev/null || true
    "
  pass "Configs synced to vpn-configs volume"
else
  warn "vpn-configs volume not created yet — configs will be synced on first deploy"
fi

echo ""
echo -e "  ${GREEN}Setup complete.${NC}"
echo "  Local configs: ${CONFIG_DIR}/"
echo "  Volume sync: vpn-configs → /etc/swanctl (inside containers)"
echo ""
echo "  Next step: bash scripts/deploy.sh"
echo ""
