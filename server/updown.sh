#!/usr/bin/env bash
# updown.sh — strongSwan tunnel up/down hook
# Called by charon with: PLUTO_VERB=up-host-v2 or down-host-v2
# Environment: PLUTO_PEER_ID (EAP username), PLUTO_VIRTUAL_IP, PLUTO_PEER_ADDRESS

set -euo pipefail

API_URL="http://localhost:6060/api/v1"
LOG_TAG="updown"

log_msg() {
    echo "[${LOG_TAG}] $(date -u '+%Y-%m-%dT%H:%M:%SZ') $*" >&2
}

case "${PLUTO_VERB:-}" in
    up-host-v2|up-client-v2)
        PEER_ID="${PLUTO_PEER_ID:-}"
        VIRTUAL_IP="${PLUTO_VIRTUAL_IP:-}"
        if [[ -z "$PEER_ID" ]]; then
            log_msg "UP: no PEER_ID, skipping route"
            exit 0
        fi
        log_msg "UP: peer=${PEER_ID} vip=${VIRTUAL_IP}"
        
        # Query API for tunnel info
        TUNNEL_JSON=$(curl -sf "${API_URL}/tunnels?username=${PEER_ID}" 2>/dev/null || echo "")
        if [[ -z "$TUNNEL_JSON" ]]; then
            log_msg "UP: could not query API for ${PEER_ID}"
            exit 0
        fi
        
        LOCAL_SUBNET=$(echo "$TUNNEL_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data'][0]['local_subnet'])" 2>/dev/null || echo "")
        if [[ -z "$LOCAL_SUBNET" ]]; then
            log_msg "UP: no local_subnet found for ${PEER_ID}"
            exit 0
        fi
        
        log_msg "UP: adding route ${LOCAL_SUBNET} via ${VIRTUAL_IP}"
        ip route add "${LOCAL_SUBNET}" via "${VIRTUAL_IP}" 2>/dev/null || true
        ;;
    down-host-v2|down-client-v2)
        PEER_ID="${PLUTO_PEER_ID:-}"
        VIRTUAL_IP="${PLUTO_VIRTUAL_IP:-}"
        if [[ -z "$PEER_ID" || -z "$VIRTUAL_IP" ]]; then
            exit 0
        fi
        
        # Remove all routes via this virtual IP
        ip route | grep "via ${VIRTUAL_IP}" | while read -r line; do
            log_msg "DOWN: removing route: ${line}"
            ip route del $(echo "$line" | awk '{print $1, $3}') 2>/dev/null || true
        done
        ;;
    *)
        # Other verbs: route-host-v2, etc. — ignore
        ;;
esac

exit 0
