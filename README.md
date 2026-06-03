# MikroTik ↔ strongSwan VPN — Multi-Tenant Dual-Protocol

Site-to-site VPN tunnel antara **MikroTik RouterOS** (client) dan **strongSwan** di Docker (server), dengan **VPN Manager API** (Go) untuk multi-tunnel management via REST API. Supports **IKEv2 EAP-MSCHAPv2** (primary) and **L2TP/IPsec** (fallback) for maximum RouterOS compatibility.

## Architecture

```
┌─────────────────┐                        ┌──────────────────────────────────┐
│   MikroTik      │   UDP 500/4500 + ESP    │   VPS (Oracle Cloud ARM)        │
│   (Client)      │ ◄═════════════════════► │                                  │
│                 │                         │  ┌────────────────────────────┐  │
│  LAN: 192.168   │    IKEv2 EAP / L2TP     │  │ vpn-server (strongSwan)    │  │
│  88.0/24        │                         │  │ + xl2tpd                    │  │
│                 │                         │  │ network_mode: host         │  │
│  RouterOS 6/7   │                         │  └────────────────────────────┘  │
│                 │                         │  ┌────────────────────────────┐  │
│                 │                         │  │ vpn-manager (Go REST API)  │  │
│                 │                         │  │ :8080 CRUD tunnels          │  │
└─────────────────┘                         │  └──────────┬─────────────────┘  │
                                            │  ┌──────────▼─────────────────┐  │
                                            │  │ postgres (16-alpine)       │  │
                                            │  │ vpn_tunnels + vpn_ip_pool  │  │
                                            │  └────────────────────────────┘  │
                                            │                                  │
                                            │  VPN Pool: 10.10.10.0/24        │
                                            └──────────────────────────────────┘
```

## Features

| Feature | Detail |
|---------|--------|
| **Dual protocol** | IKEv2 EAP-MSCHAPv2 (primary) + L2TP/IPsec (fallback) |
| **Multi-tenant** | Per-router username+password via API |
| **API-driven** | REST API for tunnel CRUD, config generation, reload |
| **Auto-routing** | `updown.sh` adds LAN subnet routes per tunnel |
| **Encrypted passwords** | AES-256-GCM at rest, bcrypt hash in DB |
| **Rate limiting** | 10 req/s per IP, 429 + Retry-After header |
| **CI/CD** | Auto-build GHCR → auto-deploy to Oracle VPS |
| **Security scan** | govulncheck + golangci-lint on every push |

## Quick Start

### 1. Clone & Configure

```bash
git clone https://github.com/ajianaz/mikrotik-strongswan-vpn.git
cd mikrotik-strongswan-vpn
git checkout develop

cp .env.example .env
nano .env  # Fill required fields
```

### 2. Required `.env` Variables

```env
# Server — VPS public IPv4
SERVER_PUBLIC_IP=152.70.xx.xx

# Authentication — EAP mode (default, recommended)
AUTH_TYPE=eap

# Database
POSTGRES_PASSWORD=your_secure_password

# API
API_KEY=your_api_key_here

# VPN Pool — virtual IP range for connected routers
VPN_POOL_SUBNET=10.10.10.0/24
```

### 3. Deploy

```bash
docker compose up -d
```

Docker will:
1. Start PostgreSQL and run auto-migration (creates tables + seeds IP pool)
2. Start strongSwan VPN server (host network for ESP protocol)
3. Start VPN Manager API on port 8080

### 4. Verify

```bash
# Check container health
docker compose ps

# Check API health
curl http://localhost:8080/healthz

# Check strongSwan connections
docker exec vpn-server swanctl --list-sas
```

### 5. Create Tunnel

```bash
# Create EAP tunnel (RouterOS 6.45+)
curl -X POST http://SERVER:8080/api/v1/tunnels \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "ISP-Jakarta", "local_subnet": "192.168.88.0/24"}'

# Response includes credentials (shown ONCE):
# {"tunnel_id": "tun-abc12345", "username": "vpn-isp-jakarta", "password": "...", ...}

# Create L2TP tunnel (RouterOS < 6.45 fallback)
curl -X POST http://SERVER:8080/api/v1/tunnels \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "ISP-Legacy", "local_subnet": "192.168.1.0/24", "auth_type": "l2tp"}'
```

### 6. Import to MikroTik

```bash
# Download RouterOS script
curl http://SERVER:8080/api/v1/tunnels/tun-abc12345/rsc \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -o mikrotik.rsc

# Upload to MikroTik, then import:
/import file=mikrotik.rsc
```

## RouterOS Compatibility

| Version | IKEv2 EAP | L2TP/IPsec | Template |
|---------|:---------:|:----------:|----------|
| ≥ 6.45 | ✅ | ✅ | EAP (recommended) |
| 7.x | ✅ | ✅ | EAP (recommended) |
| < 6.45 | ❌ | ✅ | L2TP (fallback) |

**Why EAP primary:** IKEv2 EAP-MSCHAPv2 is the simplest — 1 layer (native IKEv2), no extra daemon. L2TP requires xl2tpd + pppd (3 processes). EAP covers RouterOS 6.45+ (Jul 2019, 7+ years ago).

## VPN Manager API

REST API for managing tunnels. All endpoints require `Authorization: Bearer <API_KEY>` header.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/healthz` | Health check (no auth) |
| `POST` | `/api/v1/tunnels` | Create a new tunnel |
| `GET` | `/api/v1/tunnels` | List all tunnels |
| `GET` | `/api/v1/tunnels/{id}` | Get tunnel details |
| `DELETE` | `/api/v1/tunnels/{id}` | Delete a tunnel + release IP |
| `GET` | `/api/v1/tunnels/{id}/rsc` | Download MikroTik RouterOS import script |
| `POST` | `/api/v1/reload` | Reload strongSwan configuration |

**Tunnel lifecycle:**
```
POST /tunnels → auto-allocate IP → generate credentials →
write config → swanctl reload → return credentials (shown ONCE)
```

## Crypto Suite

| Component | Algorithm |
|-----------|-----------|
| IKE (Phase 1) | AES-256-CBC + SHA-256 + ECP384 |
| ESP (Phase 2) | AES-256-CBC + HMAC-SHA2-256 + DH ECP384 |
| Authentication | EAP-MSCHAPv2 (primary) / L2TP CHAP (fallback) |
| Key Exchange | IKEv2 only |
| DH Group | ECP384 (NIST P-384) — **NOT** modp2048 |

> **Why CBC not GCM:** RouterOS 6.x does not support ESP GCM mode via IKEv2. CBC is maximum-compatible across RouterOS versions.

## Environment Variables

### Required

| Variable | Description |
|----------|-------------|
| `SERVER_PUBLIC_IP` | VPS public IPv4 address |
| `POSTGRES_PASSWORD` | PostgreSQL password |
| `API_KEY` | API key for VPN Manager |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_TYPE` | `eap` | `eap`, `l2tp`, or `both` |
| `VPN_POOL_SUBNET` | `10.10.10.0/24` | Virtual IP pool for connected routers |
| `ENCRYPTION_KEY` | auto-generated | AES-256-GCM key (base64). **⚠️ Persist — loss = password loss** |
| `EAP_MAX_LOGIN_ATTEMPTS` | `5` | Max failed login attempts before lockout |
| `EAP_LOCKOUT_DURATION_MINUTES` | `15` | Account lockout duration |
| `POSTGRES_USER` | `vpnuser` | PostgreSQL username |
| `POSTGRES_DB` | `vpnmgr` | PostgreSQL database name |
| `LISTEN` | `:8080` | API HTTP listen address |
| `VPN_CONTAINER` | `vpn-server` | strongSwan container name |
| `STRONGSWAN_LOGLEVEL` | `3` | charon log level (0=none → 5=private) |

## VPS Firewall

Open these ports/protocols on your VPS security list:

| Port/Protocol | Purpose |
|---------------|---------|
| UDP 500 | IKE (key exchange) |
| UDP 4500 | NAT-T (ESP-in-UDP for NAT traversal) |
| UDP 1701 | L2TP (when `AUTH_TYPE=l2tp` or `both`) |
| Protocol 50 | ESP (encrypted data channel) |

## CI/CD Pipeline

```
push to develop
       │
       ▼
┌──────────────────┐     ┌──────────────────┐
│ docker.yml (CI)  │────►│ deploy.yml (CD)  │
│ lint + test +    │     │ SSH to VPS       │
│ security + build │     │ compose pull     │
│ Push to GHCR     │     │ compose up -d    │
└──────────────────┘     │ health verify     │
                         └──────────────────┘
```

### CI Quality Gates

| Gate | Tool | Fail = Block |
|------|------|:---:|
| Lint | golangci-lint (13 linters) | ✅ |
| Security | govulncheck + SARIF | ⚠️ (informational) |
| Tests | `go test -race ./...` (125 tests) | ✅ |
| Build | Docker multi-arch | ✅ |

### Required GitHub Secrets (environment: `OCI`)

| Secret | Description |
|--------|-------------|
| `DEPLOY_HOST` | VPS IP address |
| `DEPLOY_USER` | SSH username |
| `DEPLOY_SSH_KEY` | SSH private key |
| `DEPLOY_PORT` | SSH port |
| `DEPLOY_PATH` | Repo path on server |

## Project Structure

```
.
├── .env.example              # Configuration template
├── .github/workflows/
│   ├── docker.yml            # CI — lint, test, security, build + GHCR
│   └── deploy.yml            # CD — SSH deploy + self-verify
├── docker-compose.yml        # vpn-server + vpn-manager + postgres
├── api/                      # VPN Manager API (Go)
│   ├── cmd/server/main.go    # Entrypoint (chi v5, graceful shutdown)
│   ├── internal/
│   │   ├── config/           # Env var loading
│   │   ├── crypto/           # AES-256-GCM encrypt/decrypt
│   │   ├── db/               # PostgreSQL migration + connection pool
│   │   ├── handler/          # HTTP handlers (CRUD + health)
│   │   ├── middleware/        # Bearer auth + rate limiting
│   │   ├── service/          # Business logic (CRUD, IP allocation)
│   │   ├── strongswan/       # swanctl config + secret file management
│   │   └── template/         # MikroTik .rsc rendering (Go templates)
│   └── Dockerfile
├── scripts/                  # Manual setup scripts
│   ├── validate.sh           # Pre-flight validation (7 checks)
│   ├── setup.sh              # Template → config generation
│   ├── deploy.sh             # Docker compose up + verify
│   └── verify.sh             # Tunnel status check
└── server/                   # strongSwan VPN server
    ├── Dockerfile            # ARM64 Ubuntu 24.04 + plugin whitelist
    ├── strongswan.conf       # charon daemon config
    ├── entrypoint.sh          # Bootstrap + start charon + xl2tpd
    ├── updown.sh              # Dynamic LAN routing via API
    └── xl2tpd.conf            # L2TP daemon config
```

## Security

### Hardening

| Layer | Mechanism | Details |
|-------|-----------|---------|
| **Authentication** | EAP-MSCHAPv2 | Per-router username+password, bcrypt in DB |
| **Password storage** | AES-256-GCM | Encrypted at rest, decrypted on-demand |
| **API auth** | Bearer token | Constant-time comparison, rate limiting |
| **Input validation** | Regex + length | Tunnel name, tunnel ID format validation |
| **File locking** | `syscall.Flock` | TOCTOU-safe secret file operations |
| **Container isolation** | Least privilege | `NET_ADMIN` only, no `privileged` mode |
| **Image pinning** | Fixed tags | `ubuntu:24.04` + `postgres:16-alpine` |
| **Health monitoring** | Docker healthcheck | `wget /healthz` every 30s |
| **Database** | Auto-migrate | Idempotent on startup |
| **Brute-force** | Lockout | Configurable max attempts + lockout duration |
| **Crypto** | ECP384 | No modp2048 or weaker DH groups |

### Docker Socket Note

`docker.sock` is mounted read-only for `docker exec swanctl --reload`. For multi-tenant deployments, replace with [Tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy).

## Why `network_mode: host`?

Docker **cannot proxy IP protocol 50** (ESP). Host networking is required for native ESP traffic. NAT-T (UDP 4500) works as fallback when MikroTik is behind NAT.

## Scaling

```
Phase 1 (MVP):     10.10.10.0/24  → 253 IP  (current)
Phase 2 (extend):  10.10.11.0/24  → +253 IP (INSERT INTO vpn_ip_pool)
Phase 3 (dynamic): Auto-extend on pool exhaustion
Max capacity:      254 subnets × 253 IP = 64,262 routers
```

## License

Private repository. All rights reserved.
