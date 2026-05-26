# Custom strongSwan image — ARM (aarch64) focused
# Replaces: strongx509/strongswan:ubuntu24 (amd64 only)
#
# Build:  docker build -t vpn-server ./server
# Run:    Used by docker-compose (network_mode: host)

FROM ubuntu:24.04

# Prevent interactive prompts during apt
ENV DEBIAN_FRONTEND=noninteractive

# Install strongSwan — explicit packages (not metapackage).
#
# Ubuntu 24.04 splits strongSwan into many packages:
#   strongswan              = metapackage (docs only on ARM!)
#   libstrongswan          = CORE: libstrongswan.so + crypto plugins (SHA1, AES, NONCE, RNG, etc.)
#   strongswan-charon       = /usr/lib/ipsec/charon binary + default config
#   strongswan-libcharon    = libcharon.so + IKE plugins (socket-default, updown, etc.)
#   strongswan-swanctl      = /usr/sbin/swanctl + vici plugin
#   strongswan-pki          = pki tool for cert management
#   libcharon-extra-plugins = additional plugins (EAP, RADIUS, ECP384, etc.)
#
# We install explicit binary packages, NOT the metapackage.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libstrongswan \
        strongswan-charon \
        strongswan-libcharon \
        strongswan-swanctl \
        strongswan-pki \
        libcharon-extra-plugins \
        iproute2 \
        iptables \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Register /usr/lib/ipsec in the dynamic linker path.
# Without this, charon can't dlopen() libstrongswan.so and plugin .so files,
# causing: "unmet dependency: HASH_SHA1" → "initialization failed".
RUN echo "/usr/lib/ipsec" > /etc/ld.so.conf.d/libstrongswan.conf \
    && ldconfig

# Find charon binary and create symlink to /usr/local/bin.
# Ubuntu 24.04 ARM64: /usr/lib/ipsec/charon (no /usr/sbin wrapper)
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

# DEBUG: Check charon linking details
RUN apt-get update && apt-get install -y --no-install-recommends binutils python3-minimal \
    && echo "=== RPATH/RUNPATH ===" \
    && readelf -d /usr/local/bin/charon | grep -E "(RPATH|RUNPATH)" || echo "NO RPATH/RUNPATH" \
    && echo "=== NEEDED libs ===" \
    && readelf -d /usr/local/bin/charon | grep NEEDED \
    && echo "=== ldd ===" \
    && ldd /usr/local/bin/charon 2>&1 || true \
    && echo "=== ldconfig strongswan ===" \
    && ldconfig -p | grep strongswan \
    && echo "=== dlopen test ===" \
    && python3 -c "
import ctypes, ctypes.util
lib = ctypes.util.find_library('strongswan')
print(f'find_library: {lib}')
try:
    ctypes.CDLL('/usr/lib/ipsec/libstrongswan.so')
    print('OK: dlopen libstrongswan.so')
except Exception as e:
    print(f'FAIL: {e}')
" 2>&1 \
    && apt-get purge -y binutils python3-minimal && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

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
