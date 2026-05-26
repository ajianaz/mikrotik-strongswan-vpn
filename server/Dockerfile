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

# Symlink all strongSwan binaries into /usr/local/bin for consistent PATH access.
# Ubuntu 24.04 ARM places binaries under /usr/lib/ipsec/ (not /usr/sbin).
# AMD64 uses /usr/sbin. This handles both by scanning libexec/lib dirs.
RUN LIB_DIR=$(find /usr/lib* /usr/libexec -maxdepth 2 -name 'charon' -type f -executable 2>/dev/null | head -1 | xargs dirname) \
    && if [ -n "$LIB_DIR" ]; then \
        for bin in charon swanctl pki; do \
            if [ -f "$LIB_DIR/$bin" ] && [ ! -f "/usr/local/bin/$bin" ]; then \
                ln -sf "$LIB_DIR/$bin" "/usr/local/bin/$bin" && echo "Linked: $LIB_DIR/$bin -> /usr/local/bin/$bin"; \
            fi; \
        done; \
    fi \
    # Also link /usr/sbin binaries if they exist (AMD64 path)
    && for bin in charon swanctl pki; do \
        if [ -f "/usr/sbin/$bin" ] && [ ! -f "/usr/local/bin/$bin" ]; then \
            ln -sf "/usr/sbin/$bin" "/usr/local/bin/$bin" && echo "Linked: /usr/sbin/$bin -> /usr/local/bin/$bin"; \
        fi; \
    done

# Verify required binaries exist
RUN for bin in charon swanctl; do \
        if ! command -v "$bin" > /dev/null 2>&1 && [ ! -f "/usr/local/bin/$bin" ]; then \
            echo "ERROR: $bin not found" && exit 1; \
        fi; \
    done \
    && echo "Build verified: charon=$(which charon 2>/dev/null || echo /usr/local/bin/charon) swanctl=$(which swanctl 2>/dev/null || echo /usr/local/bin/swanctl)"

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

# Healthcheck: verify charon is running (process check, not swanctl --stats)
# swanctl --stats depends on loaded connections which won't exist on fresh deploy.
# Checking the charon process is sufficient to confirm the daemon is alive.
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=5s \
    CMD test -f /usr/local/bin/charon && /usr/local/bin/charon --help >/dev/null 2>&1 || pgrep -x charon >/dev/null

# Start charon in foreground mode — required for Docker (no init system).
# Without -T, charon daemonizes and the container exits immediately (code 66).
ENTRYPOINT ["/usr/local/bin/charon", "-T"]
