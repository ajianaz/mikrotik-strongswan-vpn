#!/bin/sh
# Wrapper to run charon with signal handling for debugging.
# Traps SIGSEGV, SIGABRT, SIGBUS and reports before container restart.

trap 'echo "=== SIGNAL $(kill -l $?) ===" >&2' SEGV ABRT BUS

echo "=== Starting charon at $(date) ===" >&2
echo "=== LD_LIBRARY_PATH=$LD_LIBRARY_PATH ===" >&2
echo "=== strongswan.conf contents ===" >&2
cat /etc/strongswan.conf >&2
echo "=== /etc/strongswan.d/ contents ===" >&2
ls -la /etc/strongswan.d/ 2>/dev/null || echo "(directory does not exist)" >&2
echo "=== Plugin .so files ===" >&2
ls /usr/lib/ipsec/plugins/ 2>/dev/null | head -20
echo "=== /usr/lib/ipsec/ contents ===" >&2
ls /usr/lib/ipsec/*.so 2>/dev/null | head -10
echo "=== Starting charon ===" >&2

exec /usr/local/bin/charon
