# MikroTik ↔ strongSwan VPN — IKEv2 IPsec

Site-to-site VPN tunnel antara **MikroTik RouterOS** (client) dan **strongSwan** di Docker (server), dengan **VPN Manager API** (Go) untuk multi-tunnel management via REST API.

## Architecture

```
┌─────────────────┐                        ┌──────────────────────────────────┐
│   MikroTik      │   UDP 500/4500 + ESP    │   VPS (Oracle Cloud)             │
│   (Client)      │ ◄═════════════════════► │                                  │
│                 │                         │  ┌────────────────────────────┐  │
│  LAN: 192.168   │    IKEv2 IPsec Tunnel   │  │ vpn-server (strongSwan)    │  │
│  88.0/24        │                         │  │ network_mode: host         │  │
│                 │                         │  └────────────────────────────┘  │
│  RouterOS 6/7   │                         │  ┌────────────────────────────┐  │
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

## Crypto Suite

| Component | Algorithm |
|-----------|-----------|
| IKE (Phase 1) | AES-256-CBC + SHA-256 + ECP384 |
| ESP (Phase 2) | AES-256-CBC + HMAC-SHA2-256 + DH ECP384 |
| Authentication | Pre-Shared Key (PSK) |
| Key Exchange | IKEv2 only |
| DH Group | ECP384 (NIST P-384) — **NOT** modp2048 |

> **Compatibility:** RouterOS 6.49.x and 7.x

## Quick Start

### 1. Clone & Configure

```bash
git clone https://github.com/ajianaz/mikrotik-strongswan-vpn.git
cd mikrotik-strongswan-vpn
git checkout develop

cp .env.example .env
nano .env  # Fill ALL required fields
```

### 2. Set Required Variables

**Minimal `.env` for server deployment:**

```env
# Server
SERVER_PUBLIC_IP=152.70.xx.xx

# Database (PostgreSQL)
POSTGRES_PASSWORD=your_secure_password

# API
API_KEY=your_api_key_here

# VPN Pool
VPN_POOL_SUBNET=10.10.10.0/24
```

> See [Environment Variables](#environment-variables) for the full list.

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

## VPN Manager API

REST API for managing tunnels. All endpoints require `Authorization: Bearer <API_KEY>` header.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/tunnels` | Create a new tunnel |
| `GET` | `/api/v1/tunnels` | List all tunnels |
| `GET` | `/api/v1/tunnels/{id}` | Get tunnel details |
| `DELETE` | `/api/v1/tunnels/{id}` | Delete a tunnel |
| `GET` | `/api/v1/tunnels/{id}/rsc` | Download MikroTik RouterOS import script |
| `POST` | `/api/v1/reload` | Reload strongSwan configuration |

### Example

```bash
# Create tunnel
curl -X POST http://localhost:8080/api/v1/tunnels \
  -H "Authorization: Bearer your_api_key" \
  -H "Content-Type: application/json" \
  -d '{"name": "branch-office"}'

# Download MikroTik script
curl http://localhost:8080/api/v1/tunnels/tun-abc12345/rsc \
  -H "Authorization: Bearer your_api_key" \
  -o mikrotik.rsc
```

### Import to MikroTik

Upload the generated `.rsc` file to MikroTik, then:

```
/import file=mikrotik.rsc
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

## Environment Variables

### Required

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PUBLIC_IP` | — | VPS public IPv4 address |
| `VPN_PSK` | — | Pre-Shared Key (min 24 chars, use `generate-psk.sh`) |
| `CLIENT_LAN_SUBNET` | — | MikroTik LAN subnet (CIDR) |
| `CLIENT_FQDN` | — | MikroTik identity FQDN |
| `VPN_POOL_SUBNET` | — | VPN virtual IP pool (CIDR) |
| `POSTGRES_PASSWORD` | — | PostgreSQL password |
| `API_KEY` | — | API key for VPN Manager |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_FQDN` | — | Optional server FQDN |
| `STRONGSWAN_LOGLEVEL` | `3` | charon log level (0=none → 5=private) |
| `POSTGRES_USER` | `vpnuser` | PostgreSQL username |
| `POSTGRES_DB` | `vpnmgr` | PostgreSQL database name |
| `LISTEN` | `:8080` | API HTTP listen address |
| `VPN_CONTAINER` | `vpn-server` | strongSwan container name |
| `VPN_CONFIG_DIR` | `/etc/swanctl/conf.d` | swanctl config directory |
| `VPN_SECRET_FILE` | `/etc/swanctl/secret` | swanctl secret file path |

## Why `network_mode: host`?

Docker **cannot proxy IP protocol 50** (ESP). Host networking is required for native ESP traffic. NAT-T (UDP 4500) works as fallback behind NAT.

## Security Notes

- PSK minimum 24 characters, entropy validated automatically
- API key required for all tunnel management endpoints
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

## License

Private repository. All rights reserved.
