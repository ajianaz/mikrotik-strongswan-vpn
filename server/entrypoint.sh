#!/bin/bash
# =============================================================================
# entrypoint.sh — Bootstrap swanctl config + start charon + xl2tpd
# =============================================================================
# Runs inside vpn-server container on every start.
# 1. Bootstraps conf.d/ and secret if they don't exist (first run / empty bind mount)
# 2. Processes xl2tpd.conf env var substitution
# 3. Starts xl2tpd in background, then charon in foreground
# =============================================================================

set -e

SWANCTL_DIR="/etc/swanctl"
CONF_DIR="${SWANCTL_DIR}/conf.d"
SECRET_FILE="${SWANCTL_DIR}/secret"

# ── Bootstrap config directory structure ──
mkdir -p "${CONF_DIR}"

if [[ ! -f "${SECRET_FILE}" ]]; then
  touch "${SECRET_FILE}"
  chmod 640 "${SECRET_FILE}"
fi

# Copy L2TP transport mode config if available
if [[ -f /etc/swanctl/conf.d/l2tp-transport.conf ]]; then
  echo "[entrypoint] L2TP transport config found in conf.d/"
else
  for src in /opt/config/l2tp-transport.conf /config/l2tp-transport.conf; do
    if [[ -f "$src" ]]; then
      cp "$src" "${CONF_DIR}/l2tp-transport.conf"
      echo "[entrypoint] Copied L2TP transport config from ${src}"
      break
    fi
  done
fi

# Append L2TP PSK to secret file if not already present
for src in /etc/swanctl/conf.d/l2tp-secret.conf "${CONF_DIR}/l2tp-secret.conf"; do
  if [[ -f "$src" ]]; then
    if ! grep -q "%any %any" "${SECRET_FILE}" 2>/dev/null; then
      cat "$src" >> "${SECRET_FILE}"
      echo "[entrypoint] Appended L2TP PSK to ${SECRET_FILE}"
    fi
    break
  fi
done

# ── Bootstrap xl2tpd / pppd ──
mkdir -p /var/run/xl2tpd

if [[ ! -f /etc/ppp/options.xl2tpd ]]; then
  cat > /etc/ppp/options.xl2tpd << 'EOF'
name = l2tp-vpn
ms-dns = 10.10.10.1
nodefaultroute
lock
nobsdcomp
nopcomp
noaccomp
mtu 1400
mru 1400
EOF
fi

if [[ ! -f /etc/ppp/chap-secrets ]]; then
  touch /etc/ppp/chap-secrets
  chmod 640 /etc/ppp/chap-secrets
fi

# ── Process xl2tpd.conf template with env vars ──
if [[ -f /etc/xl2tpd/xl2tpd.conf ]]; then
  envsubst '${VPN_POOL_RANGE} ${VPN_POOL_LOCAL_IP}' < /etc/xl2tpd/xl2tpd.conf > /tmp/xl2tpd.conf.tmp
  mv /tmp/xl2tpd.conf.tmp /etc/xl2tpd/xl2tpd.conf
fi

# ── Start xl2tpd in background ──
echo "[entrypoint] Starting xl2tpd..." >&2
xl2tpd -D &

# ── Start charon (foreground) ──
exec /usr/local/bin/charon "$@"
