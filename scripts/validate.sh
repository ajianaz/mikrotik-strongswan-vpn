#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# validate.sh — Credential & Environment Validation
# =============================================================================
# Validates .env file before VPN deployment.
# Exit 0 = all required checks pass, Exit 1 = failures found.
# =============================================================================

# ── Colors ──
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
    echo -e "${RED}Error: docker-compose.yml not found. Run from repo directory.${NC}" >&2
    exit 1
  fi
done

# ── Counters ──
pass_count=0
warn_count=0
fail_count=0

echo ""
echo "========================================"
echo "  VPN Credential Validation"
echo "  Repo: ${REPO_ROOT}"
echo "========================================"
echo ""

# ── Check 1: .env exists ──
if [[ -f "${REPO_ROOT}/.env" ]]; then
  pass ".env file found"
  ((pass_count++))
else
  fail ".env file not found at ${REPO_ROOT}"
  ((fail_count++))
  echo ""
  echo "  Fix: cp .env.example .env && nano .env"
  echo ""
  echo "Results: ${pass_count} passed, ${warn_count} warnings, ${fail_count} failures"
  exit 1
fi

# ── Source .env ──
set -a
# shellcheck source=/dev/null
source "${REPO_ROOT}/.env"
set +a

# ── Check 2: SERVER_PUBLIC_IP ──
IP_REGEX='^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$'
if [[ -n "${SERVER_PUBLIC_IP:-}" ]] && echo "${SERVER_PUBLIC_IP}" | grep -qE "${IP_REGEX}"; then
  pass "SERVER_PUBLIC_IP = ${SERVER_PUBLIC_IP}"
  ((pass_count++))
else
  fail "SERVER_PUBLIC_IP invalid or missing (current: '${SERVER_PUBLIC_IP:-<unset>}')"
  ((fail_count++))
fi

# ── Check 3: VPN_PSK (length + entropy) ──
if [[ -n "${VPN_PSK:-}" ]]; then
  psk_len="${#VPN_PSK}"
  psk_entropy="$(python3 -c "
import math
from collections import Counter
psk = '${VPN_PSK}'
counts = Counter(psk)
length = len(psk)
entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
print(f'{entropy:.4f}')
")"
  if (( psk_len >= 24 )) && (( $(echo "${psk_entropy} >= 3.0" | bc -l) )); then
    pass "VPN_PSK length=${psk_len}, entropy=${psk_entropy}"
    ((pass_count++))
  else
    reasons=()
    (( psk_len < 24 )) && reasons+=("length ${psk_len} < 24")
    (( $(echo "${psk_entropy} < 3.0" | bc -l) )) && reasons+=("entropy ${psk_entropy} < 3.0")
    warn "VPN_PSK weak: ${reasons[*]} — run: bash scripts/generate-psk.sh"
    ((warn_count++))
  fi
else
  fail "VPN_PSK is not set"
  ((fail_count++))
fi

# ── Check 4: CLIENT_LAN_SUBNET ──
CIDR_REGEX='^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}/(1[6-9]|2[0-8])$'
if [[ -n "${CLIENT_LAN_SUBNET:-}" ]] && echo "${CLIENT_LAN_SUBNET}" | grep -qE "${CIDR_REGEX}"; then
  pass "CLIENT_LAN_SUBNET = ${CLIENT_LAN_SUBNET}"
  ((pass_count++))
else
  fail "CLIENT_LAN_SUBNET invalid (must be CIDR /16-/28, current: '${CLIENT_LAN_SUBNET:-<unset>}')"
  ((fail_count++))
fi

# ── Check 5: CLIENT_FQDN (optional) ──
FQDN_REGEX='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
if [[ -z "${CLIENT_FQDN:-}" ]]; then
  warn "CLIENT_FQDN is empty (optional, but recommended for multi-site)"
  ((warn_count++))
elif echo "${CLIENT_FQDN}" | grep -qE "${FQDN_REGEX}"; then
  pass "CLIENT_FQDN = ${CLIENT_FQDN}"
  ((pass_count++))
else
  fail "CLIENT_FQDN invalid RFC 1123 (current: '${CLIENT_FQDN}')"
  ((fail_count++))
fi

# ── Check 6: VPN_POOL_SUBNET (valid + no overlap) ──
POOL_CIDR_REGEX='^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}/([0-9]|[12][0-9]|3[0-2])$'
if [[ -n "${VPN_POOL_SUBNET:-}" ]] && echo "${VPN_POOL_SUBNET}" | grep -qE "${POOL_CIDR_REGEX}"; then
  overlap="$(python3 -c "
import ipaddress
try:
    a = ipaddress.ip_network('${VPN_POOL_SUBNET}', strict=False)
    b = ipaddress.ip_network('${CLIENT_LAN_SUBNET:-0.0.0.0/0}', strict=False)
    print('overlap' if a.overlaps(b) else 'ok')
except Exception:
    print('error')
")"
  if [[ "${overlap}" == "ok" ]]; then
    pass "VPN_POOL_SUBNET = ${VPN_POOL_SUBNET} (no overlap)"
    ((pass_count++))
  else
    fail "VPN_POOL_SUBNET overlaps CLIENT_LAN_SUBNET (${VPN_POOL_SUBNET} vs ${CLIENT_LAN_SUBNET:-?})"
    ((fail_count++))
  fi
else
  fail "VPN_POOL_SUBNET invalid (current: '${VPN_POOL_SUBNET:-<unset>}')"
  ((fail_count++))
fi

# ── Check 7: Docker daemon ──
if docker info >/dev/null 2>&1; then
  pass "Docker daemon is running"
  ((pass_count++))
else
  fail "Docker daemon is not running or not accessible"
  ((fail_count++))
fi

# ── Check 8: UDP 500 & 4500 available ──
port_issues=()
if ss -uln 2>/dev/null | grep -q ':500 ' || ss -uln 2>/dev/null | grep -q ':500$'; then
  port_issues+=("UDP 500")
fi
if ss -uln 2>/dev/null | grep -q ':4500 ' || ss -uln 2>/dev/null | grep -q ':4500$'; then
  port_issues+=("UDP 4500")
fi
if [[ ${#port_issues[@]} -eq 0 ]]; then
  pass "Ports UDP 500 & UDP 4500 are available"
  ((pass_count++))
else
  fail "Ports already in use: ${port_issues[*]}"
  ((fail_count++))
fi

# ── Summary ──
echo ""
echo "========================================"
echo "  Results: ${pass_count} passed, ${warn_count} warnings, ${fail_count} failures"
echo "========================================"
echo ""

if (( fail_count > 0 )); then
  echo -e "  ${RED}Validation FAILED — fix errors above before running setup.sh${NC}"
  exit 1
else
  echo -e "  ${GREEN}Validation PASSED — ready for setup.sh${NC}"
  if (( warn_count > 0 )); then
    echo -e "  ${YELLOW}Review warnings above.${NC}"
  fi
  exit 0
fi
