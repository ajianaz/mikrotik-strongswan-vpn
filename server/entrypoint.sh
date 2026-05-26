#!/bin/sh
# Wrapper to run charon — prints diagnostics before/after exec.
echo "=== charon starting at $(date) ===" >&2
echo "=== Plugins in /usr/lib/ipsec/plugins/ ===" >&2
ls /usr/lib/ipsec/plugins/ 2>/dev/null | sort
echo "=== Config ===" >&2
cat /etc/strongswan.conf >&2
echo "=== Executing charon ===" >&2
exec /usr/local/bin/charon --debug-lib 4 --debug-net 4 --debug-knl 4
