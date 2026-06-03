# Changelog

All notable changes to this project will be documented in this file.

## [0.1.1] - 2026-06-03

### Security Hardening (QA Audit #54-#55)

- **H4**: Add `tunnelIDRe` regex validation (`tun-[a-f0-9]{8}`) before any file path construction — prevents path traversal via malformed tunnel IDs
- **M3**: Add `syscall.Flock(LOCK_EX)` on all secret file read-write-remove operations — eliminates TOCTOU race condition in concurrent secret file access
- **L1**: Remove dead `LOCAL_IP_DEFAULT` constant — `VPN_LOCAL_IP` env var is now the sole source
- **L2**: Remove dead PSK-era template code (`RenderSwanctlConfig`, `RenderPSK`, `swanctl.conf.tmpl`, `psk.tmpl`) — only RouterOS `.rsc` templates remain
- **M5**: Improve docker-socket-proxy documentation in `docker-compose.yml` with link to Tecnativa/docker-socket-proxy

### Documentation

- Rewrite README.md: cleaner structure, accurate feature table, production-ready quick start, scaling info
- Add template safety note in `strongswan.go` package doc (Go `text/template` vs `envsubst`)
- Document file-level locking mechanism in `strongswan.go`

### Tests

- Add `TestValidateTunnelID` — 10 cases including path traversal, uppercase, boundary lengths
- Fix existing test tunnel IDs to comply with new 8-hex-char validation regex
- All 125 tests passing with `-race` flag

## [0.1.0] - 2026-05-28

### Features

- Multi-tenant VPN tunnel management via REST API
- IKEv2 EAP-MSCHAPv2 authentication (primary, RouterOS 6.45+)
- L2TP/IPsec authentication (fallback, all RouterOS versions)
- Per-tunnel IP allocation from configurable pool
- AES-256-GCM password encryption at rest
- MikroTik RouterOS `.rsc` script generation (Go `text/template`)
- Bearer token API authentication
- Per-IP rate limiting (10 req/s)
- Brute-force lockout (configurable attempts + duration)
- Docker Compose: strongSwan + vpn-manager + PostgreSQL
- CI/CD: GitHub Actions → GHCR → SSH deploy to Oracle VPS
- Dynamic LAN routing via `updown.sh`
