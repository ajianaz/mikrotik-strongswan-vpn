#!/bin/bash
# =============================================================================
# entrypoint.sh — Bootstrap swanctl config + start charon
# =============================================================================
# Runs inside vpn-server container on every start.
# 1. Bootstraps conf.d/ and secret if they don't exist (first run / empty bind mount)
# 2. Starts charon with debug flags for ARM troubleshooting
# =============================================================================

set -e

SWANCTL_DIR="/etc/swanctl"
CONF_DIR="${SWANCTL_DIR}/conf.d"
SECRET_FILE="${SWANCTL_DIR}/secret"

# ── Bootstrap config directory structure ──
mkdir -p "${CONF_DIR}"

# Create empty secret file if missing (setup.sh will populate it)
if [[ ! -f "${SECRET_FILE}" ]]; then
  touch "${SECRET_FILE}"
  chmod 640 "${SECRET_FILE}"
  echo "[entrypoint] Created empty ${SECRET_FILE}"
fi

# Warn if swanctl.conf is missing (charon won't auto-load configs)
if [[ ! -f "${SWANCTL_DIR}/swanctl.conf" ]]; then
  echo "[entrypoint] WARNING: ${SWANCTL_DIR}/swanctl.conf missing — charon may not load configs"
fi

echo "[entrypoint] swanctl config directory ready:"
ls -la "${SWANCTL_DIR}/" 2>&1 || true
echo ""

# ── Diagnostics (helpful for ARM segfault debugging) ──
echo "[entrypoint] === charon starting at $(date) ===" >&2
echo "[entrypoint] === Plugins in /usr/lib/ipsec/plugins/ ===" >&2
ls /usr/lib/ipsec/plugins/ 2>/dev/null | sort >&2 || echo "(no plugins dir)" >&2
echo "[entrypoint] === strongswan.conf ===" >&2
cat /etc/strongswan.conf >&2
echo "[entrypoint] === Executing charon ===" >&2

# ── Start charon ──
# ARM Ubuntu 24.04: charon binary is at /usr/lib/ipsec/charon, symlinked to
# /usr/local/bin/charon during build. Debug flags help diagnose init failures.
exec /usr/local/bin/charon --debug-lib 4 --debug-net 4 --debug-knl 4 "$@"
