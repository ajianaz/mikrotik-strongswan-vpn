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

# Calculate entropy
entropy="$(python3 -c "
import math
from collections import Counter
psk = '${PSK}'
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
echo -e "  ${YELLOW}Add this to your .env file:${NC}"
echo ""
echo "  VPN_PSK=${PSK}"
echo ""
echo -e "  ${YELLOW}Or run: echo 'VPN_PSK=${PSK}' >> .env${NC}"
echo ""
