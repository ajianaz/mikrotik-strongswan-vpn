#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# deploy.sh — Deploy strongSwan VPN server via Docker Compose
# =============================================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
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
echo "  VPN Deployment"
echo "========================================"
echo ""

# ── Pre-flight checks ──
if [[ ! -f "${REPO_ROOT}/.env" ]]; then
  fail ".env not found. Run: cp .env.example .env && bash scripts/validate.sh && bash scripts/setup.sh"
  exit 1
fi

if [[ ! -f "${REPO_ROOT}/server/swanctl/vpn.conf" ]]; then
  fail "server/swanctl/vpn.conf not found. Run: bash scripts/setup.sh first"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  fail "Docker daemon not running"
  exit 1
fi

# ── Deploy ──
echo "  Starting Docker Compose..."
cd "${REPO_ROOT}"
docker compose up -d --build

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
  warn "charon daemon not ready after ${MAX_WAIT}s — checking anyway"
fi

# ── Verify ──
echo ""
if docker ps --filter name=vpn-server --format '{{.Names}}' | grep -q 'vpn-server'; then
  pass "Container vpn-server is running"
else
  fail "Container vpn-server not running"
  echo ""
  echo "  Container logs:"
  docker logs vpn-server --tail 20 2>&1 || true
  exit 1
fi

echo ""
echo "  Active Security Associations:"
docker exec vpn-server swanctl --list-sas 2>&1 || echo "  (no active SAs yet — waiting for client connection)"

echo ""
echo -e "  ${GREEN}Deployment complete.${NC}"
echo "  Import client/mikrotik.rsc on MikroTik to establish tunnel."
echo ""
