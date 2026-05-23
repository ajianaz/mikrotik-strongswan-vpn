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
# - libcharon-extra-plugins: ECP384 DH group + additional crypto
# - iproute2: ip / ss utilities for debugging
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        strongswan \
        strongswan-swanctl \
        strongswan-pki \
        libcharon-extra-plugins \
        iproute2 \
        iptables \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

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

# Healthcheck: verify charon loaded connections
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=10s \
    CMD swanctl --stats 2>/dev/null | grep -q 'loaded' || exit 1

# Start charon (swanctl backend, not the legacy ipsec starter)
ENTRYPOINT ["charon-systemd"]
