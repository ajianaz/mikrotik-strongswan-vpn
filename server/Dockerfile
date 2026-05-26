# Custom strongSwan image — ARM (aarch64) & AMD64 compatible
# Replaces: strongx509/strongswan:ubuntu24 (amd64 only)
#
# Build:  docker build -t vpn-server ./server
# Run:    Used by docker-compose (network_mode: host)

FROM ubuntu:24.04

# Prevent interactive prompts during apt
ENV DEBIAN_FRONTEND=noninteractive

# Install strongSwan + swanctl + utilities
# - strongswan: core IKEv2 daemon (charon)
# - strongswan-swanctl: modern swanctl CLI (replaces ipsec)
# - strongswan-pki: optional, for future certificate support
# - libcharon-plugins: CORE crypto plugins (SHA1, AES, NONCE, HMAC, etc.)
#   CRITICAL: without this, charon fails with "unmet dependency: HASH_SHA1"
# - libcharon-extra-plugins: ECP384 DH group + additional crypto
# - iproute2: ip / ss utilities for debugging
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        strongswan \
        strongswan-swanctl \
        strongswan-pki \
        libcharon-plugins \
        libcharon-extra-plugins \
        iproute2 \
        iptables \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Find charon binary and create symlink to /usr/local/bin.
# Ubuntu 24.04 layout differs by architecture:
#   AMD64: /usr/sbin/charon (wrapper) + /usr/lib/ipsec/charon (binary)
#   ARM64: /usr/lib/ipsec/charon (binary only, no /usr/sbin wrapper)
RUN CHARON_BIN="" \
    && for p in /usr/lib/ipsec/charon /usr/libexec/ipsec/charon /usr/lib64/ipsec/charon; do \
        if [ -f "$p" ]; then CHARON_BIN="$p"; break; fi; \
    done \
    && if [ -z "$CHARON_BIN" ] && [ -f /usr/sbin/charon ]; then \
        CHARON_BIN=/usr/sbin/charon; \
    fi \
    && if [ -z "$CHARON_BIN" ]; then echo "ERROR: charon binary not found" && exit 1; fi \
    && ln -sf "$CHARON_BIN" /usr/local/bin/charon \
    && echo "charon binary: $CHARON_BIN" \
    && for bin in swanctl pki; do \
        for p in /usr/lib/ipsec/$bin /usr/libexec/ipsec/$bin /usr/lib64/ipsec/$bin /usr/sbin/$bin; do \
            if [ -f "$p" ]; then ln -sf "$p" /usr/local/bin/$bin && echo "Linked: $p"; break; fi; \
        done; \
    done

# swanctl config directory
RUN mkdir -p /etc/swanctl/conf.d /etc/swanctl/pki \
    && touch /etc/swanctl/secret \
    && chmod 640 /etc/swanctl/secret

# Copy charon daemon config (read-only)
COPY strongswan.conf /etc/strongswan.conf

# Expose IKEv2 ports (documented — actual binding via network_mode: host)
# UDP 500  = IKE (key exchange)
# UDP 4500 = NAT-T (ESP-in-UDP)
EXPOSE 500/udp 4500/udp

# Healthcheck: check if charon process is alive
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=5s \
    CMD pgrep -x charon >/dev/null

# Start charon — ELF binary stays in foreground by default.
ENTRYPOINT ["/usr/local/bin/charon"]
