#!/bin/sh
# Dummy updown script — charon calls this on SA up/down events.
# Override per-tunnel scripts via swanctl conf.d/{name}.conf -> updown = /path/to/script
# This default script does nothing (no iptables, no routing).
# IKEv2 with PSK + static routes doesn't require updown hooks.
exit 0
