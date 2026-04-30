# MikroTik ↔ strongSwan VPN — IKEv2 IPsec

Site-to-site VPN tunnel antara **MikroTik RouterOS** (client) dan **strongSwan** di Docker (server).

## Crypto Suite

| Component | Algorithm |
|-----------|-----------|
| IKE (Phase 1) | AES-256-CBC + SHA-256 + ECP384 |
| ESP (Phase 2) | AES-256-CBC + HMAC-SHA2-256 + DH ECP384 |
| Authentication | Pre-Shared Key (PSK) |
| Key Exchange | IKEv2 only |
| DH Group | ECP384 (NIST P-384) — **NOT** modp2048 |

> **Compatibility:** RouterOS 6.49.x and 7.x

## Architecture

```
┌─────────────────┐                        ┌─────────────────────────┐
│   MikroTik      │   UDP 500/4500 + ESP    │   VPS (Oracle Cloud)    │
│   (Client)      │ ◄═════════════════════► │   strongSwan (Docker)   │
│                 │                         │   network_mode: host    │
│  LAN: 192.168   │    IKEv2 IPsec Tunnel   │                         │
│  88.0/24        │                         │  VPN Pool: 10.10.10.0/24│
└─────────────────┘                         └─────────────────────────┘
```

## Quick Start

```bash
# 1. Clone
git clone https://github.com/ajianaz/mikrotik-strongswan-vpn.git
cd mikrotik-strongswan-vpn

# 2. Configure
cp .env.example .env
nano .env  # Fill ALL fields

# 3. Generate PSK (or set your own)
bash scripts/generate-psk.sh

# 4. Validate credentials
bash scripts/validate.sh

# 5. Generate configs from templates
bash scripts/setup.sh

# 6. Deploy
bash scripts/deploy.sh

# 7. Import client config on MikroTik
#    Upload client/mikrotik.rsc → Files on MikroTik
#    /import file=mikrotik.rsc
```

## VPS Firewall (Oracle Cloud / iptables)

Open these ports/protocols on your VPS security list:

| Port/Protocol | Purpose |
|---------------|---------|
| UDP 500 | IKE (key exchange) |
| UDP 4500 | NAT-T (ESP-in-UDP for NAT traversal) |
| Protocol 50 | ESP (native encrypted data channel) |

## Scripts

| Script | Purpose |
|--------|---------|
| `scripts/validate.sh` | Validate `.env` credentials (IP, PSK entropy, subnet overlap, Docker, ports) |
| `scripts/generate-psk.sh` | Generate a cryptographically strong PSK (32-byte base64) |
| `scripts/setup.sh` | Generate `vpn.conf` and `mikrotik.rsc` from `.env` + templates |
| `scripts/deploy.sh` | Docker Compose up + container health check |
| `scripts/verify.sh` | Check tunnel status, active SAs, container logs |

## Project Structure

```
.
├── .env.example              # Configuration template
├── .gitignore                # Excludes .env and generated configs
├── docker-compose.yml        # strongSwan Docker (host network)
├── README.md
├── scripts/
│   ├── validate.sh           # Pre-flight validation (8 checks)
│   ├── generate-psk.sh       # PSK generator + entropy report
│   ├── setup.sh              # Template → generated config
│   ├── deploy.sh             # Docker up + verify
│   └── verify.sh             # Tunnel status check
├── server/
│   ├── strongswan.conf       # charon daemon config
│   └── swanctl/
│       └── vpn.conf.example  # Server config template
└── client/
    └── mikrotik.rsc.example  # MikroTik RouterOS template
```

## Why `network_mode: host`?

Docker **cannot proxy IP protocol 50** (ESP). Host networking is required for native ESP traffic. NAT-T (UDP 4500) works as fallback behind NAT.

## Security Notes

- PSK minimum 24 characters, entropy validated automatically
- Generated configs (`vpn.conf`, `mikrotik.rsc`) are `chmod 600` — never committed
- `.env` is in `.gitignore` — never committed
- ECP384 DH group — no modp2048 or weaker groups

## License

Private repository. All rights reserved.
