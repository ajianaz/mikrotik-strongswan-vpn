#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# verify.sh — Verify VPN tunnel status
# =============================================================================

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✅ $1${NC}"; }
fail() { echo -e "  ${RED}❌ $1${NC}"; }
warn() { echo -e "  ${YELLOW}⚠️  $1${NC}"; }

echo ""
echo "========================================"
echo "  VPN Tunnel Verification"
echo "========================================"
echo ""

# ── Container status ──
if docker ps --filter name=vpn-server --format '{{.Names}}' | grep -q 'vpn-server'; then
  pass "Container vpn-server is running"
  docker ps --filter name=vpn-server --format "  Table: {{.Names}} | Status: {{.Status}} | Ports: {{.Ports}}"
else
  fail "Container vpn-server is NOT running"
  echo ""
  echo "  Fix: bash scripts/deploy.sh"
  exit 1
fi

echo ""

# ── Security Associations ──
echo "  --- Active Security Associations ---"
sas_output="$(docker exec vpn-server swanctl --list-sas 2>&1 || true)"
if echo "${sas_output}" | grep -q "none"; then
  warn "No active SAs — tunnel not established yet"
  echo "  Check: MikroTik client connected? PSK matches?"
else
  echo "${sas_output}"
  pass "Active SAs found"
fi

echo ""
echo "  --- Recent Logs (last 20 lines) ---"
docker logs vpn-server --tail 20 2>&1 || warn "Could not read logs"

echo ""
echo "========================================"
echo "  Verification complete"
echo "========================================"
echo ""
