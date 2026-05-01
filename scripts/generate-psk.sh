#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# generate-psk.sh — Generate a strong Pre-Shared Key
# =============================================================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "========================================"
echo "  PSK Generator"
echo "========================================"
echo ""

# Generate 32-byte base64 PSK
PSK="$(openssl rand -base64 32)"

# Calculate entropy (safe: PSK passed via env, not interpolated)
entropy="$(VPN_PSK_VAL="${PSK}" python3 -c "
import math, os
from collections import Counter
psk = os.environ['VPN_PSK_VAL']
counts = Counter(psk)
length = len(psk)
entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
print(f'{entropy:.4f}')
")"

echo -e "  ${GREEN}Generated PSK:${NC}"
echo ""
echo "  ${PSK}"
echo ""
echo "  Length: ${#PSK} characters"
echo "  Entropy: ${entropy} bits/char"
echo ""

# Auto-append to .env if it exists in repo root
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [[ ! -f "${REPO_ROOT}/docker-compose.yml" ]]; do
  REPO_ROOT="$(dirname "${REPO_ROOT}")"
  if [[ "${REPO_ROOT}" == "/" ]]; then break; fi
done

if [[ -f "${REPO_ROOT}/.env" ]]; then
  # Check if VPN_PSK already exists in .env
  if grep -q '^VPN_PSK=' "${REPO_ROOT}/.env"; then
    echo -e "  ${YELLOW}VPN_PSK already exists in .env — update manually:${NC}"
    echo -e "  ${YELLOW}  nano ${REPO_ROOT}/.env${NC}"
  else
    echo "VPN_PSK=${PSK}" >> "${REPO_ROOT}/.env"
    chmod 600 "${REPO_ROOT}/.env"
    echo -e "  ${GREEN}Appended VPN_PSK to ${REPO_ROOT}/.env (chmod 600)${NC}"
  fi
else
  echo -e "  ${YELLOW}No .env found. Create one:${NC}"
  echo "  cp .env.example .env"
  echo "  echo 'VPN_PSK=${PSK}' >> .env"
fi
echo ""
