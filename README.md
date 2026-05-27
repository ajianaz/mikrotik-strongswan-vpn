# MikroTik ↔ strongSwan VPN — Multi-Tenant Dual-Protocol

Site-to-site VPN tunnel antara **MikroTik RouterOS** (client) dan **strongSwan** di Docker (server), dengan **VPN Manager API** (Go) untuk multi-tunnel management via REST API. Supports **IKEv2 EAP** and **L2TP/IPsec** dual-protocol for maximum RouterOS compatibility.

## Architecture

```
┌─────────────────┐                        ┌──────────────────────────────────┐
│   MikroTik      │   UDP 500/4500 + ESP    │   VPS (Oracle Cloud)             │
│   (Client)      │ ◄═════════════════════► │                                  │
│                 │                         │  ┌────────────────────────────┐  │
│  LAN: 192.168   │    IKEv2 EAP / L2TP     │  │ vpn-server (strongSwan)    │  │
│  88.0/24        │                         │  │ + xl2tpd                    │  │
│                 │                         │  │ network_mode: host         │  │
│  RouterOS 6/7   │                         │  └────────────────────────────┘  │
│                 │                         │  ┌────────────────────────────┐  │
│                 │                         │  │ vpn-manager (Go API)       │  │
│                 │                         │  │ :8080 CRUD tunnels         │  │
└─────────────────┘                         │  └──────────┬─────────────────┘  │
                                            │  ┌──────────▼─────────────────┐  │
                                            │  │ postgres (16-alpine)       │  │
                                            │  │ vpn_tunnels + vpn_ip_pool  │  │
                                            │  └────────────────────────────┘  │
                                            │                                  │
                                            │  VPN Pool: 10.10.10.0/24        │
                                            └──────────────────────────────────┘
```

```
Mikrotik (EAP/L2TP) → VPN Server (Oracle) → BOND App
                     strongSwan + xl2tpd
                     PostgreSQL + vpn-manager API
```

## Multi-Tenant VPN

### Quick Start

1. Set `AUTH_TYPE=eap` in `.env` (default)
2. Run `bash scripts/setup.sh`
3. Deploy via CI (push to `develop`)
4. `POST /api/v1/tunnels` to create a tunnel
5. Import generated Mikrotik config (`.rsc`)

### API Usage Examples

```bash
# Create EAP tunnel (RouterOS 6.45+)
curl -X POST http://SERVER:6060/api/v1/tunnels \
  -H "Authorization: Bearer API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "ISP-Jakarta", "local_subnet": "192.168.88.0/24"}'

# Create L2TP tunnel (RouterOS < 6.45)
curl -X POST http://SERVER:6060/api/v1/tunnels \
  -H "Authorization: Bearer API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "ISP-Legacy", "local_subnet": "192.168.1.0/24", "auth_type": "l2tp"}'

# Download Mikrotik config
curl http://SERVER:6060/api/v1/tunnels/tun-xxx/rsc \
  -H "Authorization: Bearer API_KEY" -o config.rsc

# Delete tunnel
curl -X DELETE http://SERVER:6060/api/v1/tunnels/tun-xxx \
  -H "Authorization: Bearer API_KEY"
```

### RouterOS Compatibility Table

| Version | IKEv2 EAP | L2TP/IPsec | Template |
|---------|-----------|------------|----------|
| ≥ 6.45 | ✅ | ✅ | EAP (recommended) |
| 7.x | ✅ | ✅ | EAP (recommended) |
| < 6.45 | ❌ | ✅ | L2TP (fallback) |

### Multi-Tenant Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_TYPE` | `eap` | Authentication mode: `eap`, `l2tp`, or `both` |
| `EAP_MAX_LOGIN_ATTEMPTS` | `5` | Max failed login attempts before lockout |
| `EAP_LOCKOUT_DURATION_MINUTES` | `15` | Account lockout duration after max attempts |

---

## VPN Manager API

REST API for managing tunnels. All endpoints require `Authorization: Bearer ***` header.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/tunnels` | Create a new tunnel |
| `GET` | `/api/v1/tunnels` | List all tunnels |
| `GET` | `/api/v1/tunnels/{id}` | Get tunnel details |
| `DELETE` | `/api/v1/tunnels/{id}` | Delete a tunnel |
| `GET` | `/api/v1/tunnels/{id}/rsc` | Download MikroTik RouterOS import script |
| `POST` | `/api/v1/reload` | Reload strongSwan configuration |

### Import to MikroTik

Upload the generated `.rsc` file to MikroTik, then:

```
/import file=mikrotik.rsc
```

## Crypto Suite

| Component | Algorithm |
|-----------|-----------|
| IKE (Phase 1) | AES-256-CBC + SHA-256 + ECP384 |
| ESP (Phase 2) | AES-256-CBC + HMAC-SHA2-256 + DH ECP384 |
| Authentication | EAP-MSCHAPv2 (recommended) / PSK (legacy) |
| Key Exchange | IKEv2 only |
| DH Group | ECP384 (NIST P-384) — **NOT** modp2048 |

> **Compatibility:** RouterOS 6.45+ (EAP), all versions (L2TP fallback)

## Environment Variables

### Required

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PUBLIC_IP` | — | VPS public IPv4 address |
| `VPN_POOL_SUBNET` | — | VPN virtual IP pool (CIDR) |
| `POSTGRES_PASSWORD` | — | PostgreSQL password |
| `API_KEY` | — | API key for VPN Manager |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_TYPE` | `eap` | Authentication mode: `eap`, `l2tp`, or `both` |
| `EAP_MAX_LOGIN_ATTEMPTS` | `5` | Max failed login attempts before lockout |
| `EAP_LOCKOUT_DURATION_MINUTES` | `15` | Account lockout duration after max attempts |
| `VPN_PSK` | — | Pre-Shared Key for legacy PSK mode (min 24 chars) |
| `CLIENT_LAN_SUBNET` | — | MikroTik LAN subnet (CIDR) — legacy single-tunnel |
| `CLIENT_FQDN` | — | MikroTik identity FQDN — legacy single-tunnel |
| `SERVER_FQDN` | — | Optional server FQDN |
| `STRONGSWAN_LOGLEVEL` | `3` | charon log level (0=none → 5=private) |
| `POSTGRES_USER` | `vpnuser` | PostgreSQL username |
| `POSTGRES_DB` | `vpnmgr` | PostgreSQL database name |
| `LISTEN` | `:8080` | API HTTP listen address |
| `VPN_CONTAINER` | `vpn-server` | strongSwan container name |
| `VPN_CONFIG_DIR` | `/etc/swanctl/conf.d` | swanctl config directory |
| `VPN_SECRET_FILE` | `/etc/swanctl/secret` | swanctl secret file path |

---

## Legacy: Single-Tunnel PSK Mode

> **⚠️ This is the original single-tunnel PSK setup. For new deployments, use the [Multi-Tenant VPN](#multi-tenant-vpn) mode with EAP authentication instead.**

### 1. Clone & Configure

```bash
git clone https://github.com/ajianaz/mikrotik-strongswan-vpn.git
cd mikrotik-strongswan-vpn
git checkout develop

cp .env.example .env
nano .env  # Fill ALL required fields
```

### 2. Set Required Variables

**Minimal `.env` for legacy PSK server deployment:**

```env
# Server
SERVER_PUBLIC_IP=152.70.xx.xx

# Authentication (legacy)
AUTH_TYPE=psk
VPN_PSK=<output of generate-psk.sh>
CLIENT_LAN_SUBNET=192.168.88.0/24
CLIENT_FQDN=branch1.example.com

# Database (PostgreSQL)
POSTGRES_PASSWORD=your_secure_password

# API
API_KEY=your_api_key_here

# VPN Pool
VPN_POOL_SUBNET=10.10.10.0/24
```

### 3. Deploy

```bash
docker compose up -d
```

Docker will:
1. Start PostgreSQL and run auto-migration (creates tables + seeds IP pool)
2. Start strongSwan VPN server (host network for ESP)
3. Start VPN Manager API on port 8080

### 4. Verify

```bash
# Check container status
docker compose ps

# Check API health
curl http://localhost:8080/healthz

# Check strongSwan status
docker exec vpn-server swanctl --stats
```

### Legacy API Example

```bash
# Create tunnel (PSK mode)
curl -X POST http://localhost:8080/api/v1/tunnels \
  -H "Authorization: Bearer ***" \
  -H "Content-Type: application/json" \
  -d '{"name": "branch-office"}'

# Download MikroTik script
curl http://localhost:8080/api/v1/tunnels/tun-abc12345/rsc \
  -H "Authorization: Bearer ***" \
  -o mikrotik.rsc
```

## Manual Setup (Scripts)

For single-tunnel setup without the API, use the bash scripts:

```bash
# Generate PSK
bash scripts/generate-psk.sh

# Validate environment
bash scripts/validate.sh

# Generate configs from templates
bash scripts/setup.sh

# Deploy
bash scripts/deploy.sh

# Verify tunnel
bash scripts/verify.sh
```

## VPS Firewall (Oracle Cloud / iptables)

Open these ports/protocols on your VPS security list:

| Port/Protocol | Purpose |
|---------------|---------|
| UDP 500 | IKE (key exchange) |
| UDP 4500 | NAT-T (ESP-in-UDP for NAT traversal) |
| UDP 1701 | L2TP (when using `AUTH_TYPE=l2tp` or `both`) |
| Protocol 50 | ESP (native encrypted data channel) |

## CI/CD Pipeline

```
push to develop
       │
       ▼
┌──────────────────┐     ┌──────────────────┐
│ docker.yml (CI)  │     │ deploy.yml (CD)  │
│ Build per-arch   │────►│ SSH to VPS       │
│ Push to GHCR     │     │ compose pull     │
│ vpn-server       │     │ compose up -d    │
│ vpn-manager      │     └──────────────────┘
└──────────────────┘
```

- **`docker.yml`** — Builds multi-arch images (amd64 + arm64), pushes to GHCR
- **`deploy.yml`** — Triggered after build success, deploys via SSH

### Required GitHub Secrets (environment: `OCI`)

| Secret | Description |
|--------|-------------|
| `DEPLOY_HOST` | VPS IP address |
| `DEPLOY_USER` | SSH username |
| `DEPLOY_SSH_KEY` | SSH private key |
| `DEPLOY_PORT` | SSH port |
| `DEPLOY_PATH` | Repo path on server (e.g. `/opt/vpn`) |

## Project Structure

```
.
├── .env.example              # Configuration template
├── .github/
│   └── workflows/
│       ├── docker.yml        # CI — build & push to GHCR
│       └── deploy.yml        # CD — SSH deploy to server
├── docker-compose.yml        # vpn-server + vpn-manager + postgres
├── README.md
├── api/                      # VPN Manager API (Go)
│   ├── cmd/server/main.go
│   ├── internal/
│   │   ├── config/           # Env var loading
│   │   ├── db/               # PostgreSQL migration + connection pool
│   │   ├── handler/          # HTTP handlers (chi router)
│   │   ├── service/          # Business logic (CRUD, IP allocation)
│   │   ├── strongswan/       # swanctl config management
│   │   └── template/         # MikroTik .rsc rendering
│   └── Dockerfile
├── scripts/                  # Manual setup scripts
│   ├── validate.sh           # Pre-flight validation
│   ├── generate-psk.sh       # PSK generator
│   ├── setup.sh              # Template → config generation
│   ├── deploy.sh             # Docker up + verify
│   └── verify.sh             # Tunnel status check
├── server/                   # strongSwan VPN server
│   ├── Dockerfile
│   ├── strongswan.conf       # charon daemon config
│   └── swanctl/
│       └── vpn.conf.example  # Server config template
└── client/
    └── mikrotik.rsc.example  # MikroTik RouterOS template
```

## Why `network_mode: host`?

Docker **cannot proxy IP protocol 50** (ESP). Host networking is required for native ESP traffic. NAT-T (UDP 4500) works as fallback behind NAT.

## Security Notes

- EAP-MSCHAPv2 authentication with per-tunnel credentials (recommended)
- PSK minimum 24 characters, entropy validated automatically (legacy mode)
- API key required for all tunnel management endpoints
- Brute-force protection: configurable max login attempts + lockout
- Generated configs (`vpn.conf`, `mikrotik.rsc`) are `chmod 600` — never committed
- `.env` is in `.gitignore` — never committed
- ECP384 DH group — no modp2048 or weaker groups

### Hardening

| Layer | Mechanism | Details |
|-------|-----------|---------|
| **Input validation** | Regex sanitize | All `.env` values validated before use |
| **Injection prevention** | Env var passing | PSK passed via env vars, never interpolated |
| **Container isolation** | Least privilege | `NET_ADMIN` capability only — no `privileged` mode |
| **Image pinning** | Fixed tag | `ubuntu:24.04` + `postgres:16-alpine` (pinned) |
| **Health monitoring** | Docker healthcheck | `swanctl --stats` every 30s, 3 retries |
| **Database** | Auto-migrate | Idempotent migrations on startup |
| **Brute-force** | Lockout | Configurable max attempts + lockout duration (EAP) |

## License

Private repository. All rights reserved.
