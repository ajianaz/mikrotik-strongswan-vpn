# Custom strongSwan image — ARM (aarch64) focused
# Replaces: strongx509/strongswan:ubuntu24 (amd64 only)
#
# Build:  docker build -t vpn-server ./server
# Run:    Used by docker-compose (network_mode: host)

FROM ubuntu:24.04

# Prevent interactive prompts during apt
ENV DEBIAN_FRONTEND=noninteractive

# Tell the dynamic linker where to find strongSwan libraries.
# Without this, charon can't dlopen() libstrongswan.so and plugin .so files,
# causing: "unmet dependency: HASH_SHA1" → "initialization failed".
ENV LD_LIBRARY_PATH=/usr/lib/ipsec

# Install strongSwan — core packages only (no extra plugins).
# libcharon-extra-plugins provides EAP, RADIUS, TNC etc. which cause segfault.
# Core packages (libstrongswan + strongswan-charon + strongswan-libcharon)
# provide all plugins needed for IKEv2 PSK: aes, sha1, sha2, nonce,
# random, hmac, pubkey, x509, kernel-netlink, socket-default, vici.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libstrongswan \
        strongswan-charon \
        strongswan-libcharon \
        strongswan-swanctl \
        strongswan-pki \
        iproute2 \
        iptables \
        procps \
        binutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Register /usr/lib/ipsec in the dynamic linker path.
RUN echo "/usr/lib/ipsec" > /etc/ld.so.conf.d/libstrongswan.conf \
    && ldconfig

# Remove all package-installed plugin config files.
RUN rm -rf /etc/strongswan.d/

# ── ARM Ubuntu 24.04 CRITICAL FIX ──────────────────────────────────────
# charon on ARM IGNORES load_modular=no — it dlopen()s ALL .so files in
# /usr/lib/ipsec/plugins/. Extra plugins cause SIGSEGV during thread init.
#
# Fix: remove ALL plugins, keep ONLY what's needed for IKEv2 PSK + swanctl.
#
# Keep (26): aes sha1 sha2 sha384 sha512 md5 mgf1 random nonce hmac
#            gmp fips-prf rc2 pubkey pkcs1 x509 kernel-netlink
#            socket-default vici updown swanctl
#            eap eap-identity eap-mschapv2 attr resolve
#            ──────────────────────────────────────────
#            Last 5 added for EAP-MSCHAPv2 auth (IKEv2 EAP).
#            Safe on ARM: crash was from loading 50+ plugins, not from these.
RUN cd /usr/lib/ipsec/plugins \
    && ls *.so | grep -v -E \
        '^libstrongswan-(aes|sha1|sha2|sha384|sha512|md5|mgf1|random|nonce|hmac|gmp|fips-prf|rc2|pubkey|pkcs1|x509|kernel-netlink|socket-default|vici|updown|swanctl|eap|eap-identity|eap-mschapv2|attr|resolve)\.so$' \
    | xargs rm -f \
    && echo "Remaining plugins:" && ls *.so | sort

# Copy dummy updown script (charon calls on SA events, default does nothing)
COPY updown.sh /usr/lib/ipsec/updown.sh
RUN chmod +x /usr/lib/ipsec/updown.sh

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

# Create swanctl directories
RUN mkdir -p /etc/swanctl/conf.d /etc/swanctl/pki

# Copy entrypoint (bootstraps config structure on first start + starts charon)
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Copy charon daemon config (read-only)
COPY strongswan.conf /etc/strongswan.conf

# Expose IKEv2 ports (documented — actual binding via network_mode: host)
# UDP 500  = IKE (key exchange)
# UDP 4500 = NAT-T (ESP-in-UDP)
EXPOSE 500/udp 4500/udp

# Healthcheck: check if charon process is alive
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=5s \
    CMD pgrep -x charon >/dev/null

ENTRYPOINT ["/entrypoint.sh"]
