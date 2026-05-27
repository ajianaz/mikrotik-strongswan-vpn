#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# deploy.sh — Deploy strongSwan VPN server via Docker Compose
# =============================================================================
#
# Prerequisites:
#   1. cp .env.example .env && nano .env    (fill all required fields)
#   2. bash scripts/validate.sh            (verify .env)
#   3. bash scripts/setup.sh               (generate configs + sync to volume)
#   4. bash scripts/deploy.sh              (THIS — start services)
#
# Config flow:
#   setup.sh generates → ./config/ → syncs to vpn-configs Docker volume
#   vpn-manager API writes runtime configs → /etc/swanctl/conf.d/ (in volume)
#   vpn-server reads from /etc/swanctl (shared volume)
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

echo ""
echo "========================================"
echo "  VPN Deployment"
echo "========================================"
echo ""

# ── Pre-flight checks ──
if [[ ! -f "${REPO_ROOT}/.env" ]]; then
  fail ".env not found. Run: cp .env.example .env && bash scripts/validate.sh && bash scripts/setup.sh"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  fail "Docker daemon not running"
  exit 1
fi

# ── Pre-deploy summary ──
echo "  Config files:"
echo "    config/swanctl.conf  = $(test -f "${CONFIG_DIR}/swanctl.conf" && echo "OK" || echo "MISSING")"
echo "    config/conf.d/roadwarrior-eap.conf = $(test -f "${CONFIG_DIR}/conf.d/roadwarrior-eap.conf" && echo "OK" || echo "MISSING")"
echo ""

# ── Source .env for LISTEN port detection ──
set -a
# shellcheck source=/dev/null
source "${REPO_ROOT}/.env"
set +a

# ── Deploy ──
echo "  Starting Docker Compose..."
cd "${REPO_ROOT}"
docker compose up -d

echo ""
echo "  Waiting for charon daemon to initialize..."
MAX_WAIT=30
elapsed=0
while (( elapsed < MAX_WAIT )); do
  if docker exec vpn-server swanctl --stats >/dev/null 2>&1; then
    pass "charon daemon ready (${elapsed}s)"
    break
  fi
  sleep 2
  (( elapsed += 2 )) || true
done

if (( elapsed >= MAX_WAIT )); then
  warn "charon daemon not ready after ${MAX_WAIT}s — checking logs"
fi

# ── Verify containers ──
echo ""
for container in vpn-server vpn-manager; do
  if docker ps --filter name="${container}" --format '{{.Names}}' | grep -q "${container}"; then
    pass "Container ${container} is running"
  else
    fail "Container ${container} not running"
    echo ""
    echo "  Container logs:"
    docker logs "${container}" --tail 20 2>&1 || true
    exit 1
  fi
done

# ── Show swanctl status ──
echo ""
echo "  --- Loaded connections ---"
docker exec vpn-server swanctl --list-conns 2>&1 || warn "Could not list connections"

echo ""
echo "  --- Active Security Associations ---"
sas_output="$(docker exec vpn-server swanctl --list-sas 2>&1 || true)"
if echo "${sas_output}" | grep -q "none"; then
  warn "No active SAs — waiting for client connection"
else
  echo "${sas_output}"
fi

# ── vpn-manager API health check ──
echo ""
echo "  --- vpn-manager API ---"
LISTEN="${LISTEN:-:8080}"
API_PORT="${LISTEN#:}"
api_check="$(docker exec vpn-manager wget -qO- "http://localhost:${API_PORT}/healthz" 2>&1 || true)"
if echo "${api_check}" | grep -q "ok\|healthy\|200"; then
  pass "vpn-manager API is healthy"
else
  warn "vpn-manager API not responding yet (may need DB_URL configured)"
fi

echo ""
echo -e "  ${GREEN}Deployment complete.${NC}"
echo ""
echo "  Next steps:"
echo "    1. Add tunnels via API: POST /api/v1/tunnels"
echo "    2. Import generated RSC script on MikroTik"
echo "    3. Run: bash scripts/verify.sh to check tunnel status"
echo ""
