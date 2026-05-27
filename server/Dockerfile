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
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Register /usr/lib/ipsec in the dynamic linker path.
RUN echo "/usr/lib/ipsec" > /etc/ld.so.conf.d/libstrongswan.conf \
    && ldconfig

# Remove all package-installed plugin config files.
RUN rm -rf /etc/strongswan.d/

# ── ARM Ubuntu 24.04 CRITICAL FIX ──────────────────────────────────────
# charon on ARM IGNORES load_modular=no — it dlopen()s ALL .so files in
# /usr/lib/ipsec/plugins/. Extra plugins (EAP, TNC, xauth) cause SIGSEGV.
# Fix: keep only the minimal set needed for IKEv2 PSK + swanctl + updown.
#
# Required: aes sha1 sha2 md5 random nonce hmac mgf1 gmp pubkey pkcs1
#           x509 kernel-netlink socket-default updown vici swanctl stroke
# Keep:    fips-prf rc2 sha384 sha512 attr constraints revocation resolve
#          bypass-lan forecast farp counters (harmless, core deps)
# Remove:  ALL eap-* tnc-* xauth-* radius-* dhcp-* led-* lookip-*
#          addrblock unity error-notify certexpire dnskey sshkey
#          pkcs7 pkcs12 pgp pem pkcs8 xcbc kdf drbg (unused, reduce surface)
RUN cd /usr/lib/ipsec/plugins \
    && rm -f \
        libstrongswan-eap-identity.so \
        libstrongswan-eap-md5.so \
        libstrongswan-eap-aka.so \
        libstrongswan-eap-gtc.so \
        libstrongswan-eap-dynamic.so \
        libstrongswan-eap-radius.so \
        libstrongswan-eap-tls.so \
        libstrongswan-eap-ttls.so \
        libstrongswan-eap-peap.so \
        libstrongswan-eap-tnc.so \
        libstrongswan-xauth-eap.so \
        libstrongswan-xauth-pam.so \
        libstrongswan-tnc-tnccs.so \
        libstrongswan-ha.so \
        libstrongswan-dhcp.so \
        libstrongswan-led.so \
        libstrongswan-lookip.so \
        libstrongswan-error-notify.so \
        libstrongswan-certexpire.so \
        libstrongswan-addrblock.so \
        libstrongswan-unity.so \
        libstrongswan-dnskey.so \
        libstrongswan-sshkey.so \
        libstrongswan-pem.so \
        libstrongswan-pkcs7.so \
        libstrongswan-pkcs12.so \
        libstrongswan-pgp.so \
        libstrongswan-pkcs8.so \
        libstrongswan-xcbc.so \
        libstrongswan-kdf.so \
        libstrongswan-drbg.so \
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
