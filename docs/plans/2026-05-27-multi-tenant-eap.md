# Multi-Tenant EAP-MSCHAPv2 VPN — Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Ubah VPN dari single-tenant PSK site-to-site menjadi multi-tenant EAP-MSCHAPv2 roadwarrior, dimana setiap Mikrotik bisa connect dengan username+password sendiri, dan semua dikelola via API/database — tanpa ganggu existing config.

**Architecture:** strongSwan IKEv2 + EAP-MSCHAPv2 (username/password per tunnel). vpn-manager API manage tenants, users, dan tunnel configs. Secret file format berubah dari PSK ke EAP. Mikrotik client pakai auth-method=eap. Semua perubahan backward-compatible — existing PSK tunnels tetap jalan selama migration.

**Tech Stack:** Go 1.23 (chi + pgx), PostgreSQL 16, strongSwan 5.9+ (Ubuntu 24.04 ARM), Docker

---

## Design Decisions

### DD-1: Auth Model — EAP-MSCHAPv2 per Tunnel
Setiap Mikrotik = 1 akun (username + password). strongSwan auth via EAP-MSCHAPv2. Password disimpan bcrypt di DB, plaintext di secret file (strongSwan requirement).

### DD-2: Single Connection Profile (roadwarrior)
Bukan per-tunnel config file. Satu `roadwarrior.conf` yang menerima `%any` remote. Auth ditangani oleh EAP secret file, bukan connection-level config.

### DD-3: Backward Compatibility
Tabel `vpn_tunnels` ditambah kolom `auth_type` (psk | eap). PSK tunnels tetap jalan dengan config terpisah. EAP tunnels pakai shared roadwarrior profile.

### DD-4: Password Storage
- DB: bcrypt hash (secure storage, untuk API management)
- Secret file: plaintext (strongSwan requirement, file permissions 640)
- Password generated oleh API saat create tunnel, ditampilkan sekali saja

### DD-5: Template System
Mikrotik RSC template dibuat per-tunnel via API endpoint `GET /api/v1/tunnels/{id}/rsc`. Template berisi username + password + server IP + subnet. Satu template, banyak tunnel.

---

## Current State Analysis

```
Files yang perlu diubah:
  server/Dockerfile         — tambah EAP plugins ke whitelist
  api/internal/db/migrate.go    — tambah kolom auth_type + username + password_hash
  api/internal/service/service.go — tambah EAP support di CreateTunnel
  api/internal/strongswan/strongswan.go — EAP config + secret format
  api/internal/template/templates/mikrotik.rsc.tmpl — EAP auth variant
  config/swanctl.conf            — tambah roadwarrior EAP connection

Files baru:
  api/internal/template/templates/eap-secret.tmpl
  server/swanctl/roadwarrior-eap.conf.example

Files yang TIDAK diubah (backward compatible):
  api/internal/middleware/auth.go
  api/internal/config/config.go
  api/cmd/server/main.go
  docker-compose.yml
  .github/workflows/*
```

---

## Task Breakdown

### Task 1: Add EAP Plugins to Server Dockerfile

**Objective:** Tambah 4 EAP plugin ke whitelist tanpa trigger SIGSEGV

**Files:**
- Modify: `server/Dockerfile:52-56`

**Step 1: Update plugin whitelist**

Ganti comment dan plugin list di Dockerfile:

```dockerfile
# Keep ONLY required plugins — whitelist approach.
# ARM Ubuntu 24.04 ignores load_modular=no, so we must physically remove .so files.
#
# Crypto: aes, sha1, sha2, sha384, sha512, md5, mgf1, random, nonce, hmac, gmp, fips-prf, rc2
# Auth: pubkey, pkcs1, x509, eap, eap-identity, eap-mschapv2
# Network: kernel-netlink, socket-default
# Management: vici, updown, swanctl, attr, resolve
PLUGIN_KEEP=(
  aes sha1 sha2 sha384 sha512 md5 mgf1 random nonce hmac
  gmp fips-prf rc2 pubkey pkcs1 x509 kernel-netlink
  socket-default vici updown swanctl
  eap eap-identity eap-mschapv2
  attr resolve
)
```

**Step 2: Verify build**

Run: `docker build -f server/Dockerfile server/ --no-cache -t test-vpn-server`
Expected: Build succeeds, 26 plugins listed at startup.

**Step 3: Commit**

```bash
git add server/Dockerfile
git commit -m "feat(server): add EAP-MSCHAPv2 plugins to whitelist (26 plugins)"
```

---

### Task 2: Add auth_type + EAP Columns to DB Schema

**Objective:** Extend `vpn_tunnels` table untuk support EAP tanpa break existing data

**Files:**
- Modify: `api/internal/db/migrate.go:45-57`

**Step 1: Add new migration block**

Tambahkan di `Migrate()` setelah existing CREATE TABLE (di dalam transaction, setelah seed):

```go
// ── v2: Multi-tenant EAP support ──────────────────────────────────────
// Add auth_type column (default 'psk' for backward compat)
_, err = tx.Exec(ctx, `
    ALTER TABLE vpn_tunnels
      ADD COLUMN IF NOT EXISTS auth_type TEXT NOT NULL DEFAULT 'psk'
        CHECK (auth_type IN ('psk', 'eap')),
      ADD COLUMN IF NOT EXISTS username TEXT,
      ADD COLUMN IF NOT EXISTS password_hash TEXT,
      ADD COLUMN IF NOT EXISTS password_plain TEXT;
`)
if err != nil {
    return fmt.Errorf("add eap columns: %w", err)
}
```

**Step 2: Add index on username**

```go
_, err = tx.Exec(ctx, `
    CREATE UNIQUE INDEX IF NOT EXISTS idx_vpn_tunnels_username
      ON vpn_tunnels(username) WHERE username IS NOT NULL;
`)
if err != nil {
    return fmt.Errorf("create username index: %w", err)
}
```

**Step 3: Update Tunnel struct**

Di `api/internal/service/service.go`, tambah field:

```go
type Tunnel struct {
    ID            string          `json:"id"`
    TunnelID      string          `json:"tunnel_id"`
    Name          string          `json:"name"`
    PeerIP        string          `json:"peer_ip"`
    LocalSubnet   string          `json:"local_subnet"`
    AuthType      string          `json:"auth_type"`
    Username      string          `json:"username,omitempty"`
    PasswordPlain string          `json:"-"`           // never in JSON response
    PSK           string          `json:"psk,omitempty"` // only for PSK tunnels
    Status        string          `json:"status"`
    Metadata      json.RawMessage `json:"metadata,omitempty"`
    CreatedAt     time.Time       `json:"created_at"`
    UpdatedAt     time.Time       `json:"updated_at"`
}
```

**Step 4: Commit**

```bash
git add api/internal/db/migrate.go api/internal/service/service.go
git commit -m "feat(db): add auth_type, username, password columns for EAP support"
```

---

### Task 3: Create EAP Secret Writer in strongswan.go

**Objective:** Tambah fungsi untuk menulis EAP credentials ke secret file

**Files:**
- Modify: `api/internal/strongswan/strongswan.go`

**Step 1: Add WriteEAPSecret function**

```go
// WriteEAPSecret writes EAP-MSCHAPv2 credentials to the secret file.
// Format: {username} : EAP "{password}"
func WriteEAPSecret(cfg Config, username, password string) error {
    entry := fmt.Sprintf("# tunnel-eap\n%s : EAP \"%s\"\n", username, password)

    secretPath := cfg.SecretFile
    f, err := os.OpenFile(secretPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
    if err != nil {
        return fmt.Errorf("open secret file: %w", err)
    }
    defer f.Close()

    if _, err := f.WriteString(entry); err != nil {
        return fmt.Errorf("write EAP secret: %w", err)
    }
    return nil
}
```

**Step 2: Add RemoveEAPSecret function**

```go
// RemoveEAPSecret removes an EAP secret entry from the secret file.
func RemoveEAPSecret(cfg Config, username string) error {
    return RemoveSecretEntry(cfg.SecretFile, fmt.Sprintf("# tunnel-eap\n%s : EAP", username))
}
```

**Step 3: Commit**

```bash
git add api/internal/strongswan/strongswan.go
git commit -m "feat(strongswan): add EAP secret write/remove functions"
```

---

### Task 4: Update CreateTunnel Service for EAP

**Objective:** Support `auth_type=eap` di CreateTunnel — generate username, password, write EAP secret

**Files:**
- Modify: `api/internal/service/service.go`

**Step 1: Update CreateTunnelInput**

```go
type CreateTunnelInput struct {
    Name        string          `json:"name"`
    LocalSubnet string          `json:"local_subnet,omitempty"` // default "10.10.10.0/24"
    AuthType    string          `json:"auth_type,omitempty"`    // "psk" (default) or "eap"
    Metadata    json.RawMessage `json:"metadata,omitempty"`
}
```

**Step 2: Update CreateTunnel method**

Di fungsi `CreateTunnel`, tambah branching:

```go
authType := input.AuthType
if authType == "" {
    authType = "psk"
}

var psk, username, password, passwordHash string
switch authType {
case "eap":
    // Generate username from name: lowercase, replace spaces/sp chars with hyphens
    username = generateUsername(input.Name)
    password = generatePassword()
    passwordHash = hashPassword(password)
case "psk":
    psk = generatePSK()
default:
    return Tunnel{}, fmt.Errorf("invalid auth_type: %s (must be 'psk' or 'eap')", authType)
}

// INSERT with new columns:
_, err = tx.Exec(ctx, `
    INSERT INTO vpn_tunnels (tunnel_id, name, peer_ip, local_subnet, psk, auth_type, username, password_hash, password_plain)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    RETURNING id, created_at, updated_at
`, tunnelID, input.Name, "0.0.0.0", subnet, psk, authType, username, passwordHash, password)
```

**Step 3: Write secrets conditionally**

```go
if authType == "eap" {
    if err := strongswan.WriteEAPSecret(s.swanCfg, username, password); err != nil {
        log.Printf("WARN: failed to write EAP secret for %s: %v", tunnelID, err)
    }
} else {
    if err := strongswan.WritePSK(s.swanCfg, tunnelID, psk); err != nil {
        log.Printf("WARN: failed to write PSK for %s: %v", tunnelID, err)
    }
}
```

**Step 4: Add helper functions**

```go
func generateUsername(name string) string {
    re := regexp.MustCompile(`[^a-zA-Z0-9]+`)
    clean := re.ReplaceAllString(strings.ToLower(name), "-")
    clean = strings.Trim(clean, "-")
    if len(clean) > 32 {
        clean = clean[:32]
    }
    // Append random suffix to ensure uniqueness
    suffix := make([]byte, 4)
    rand.Read(suffix)
    return fmt.Sprintf("%s-%x", clean, suffix)
}

func generatePassword() string {
    b := make([]byte, 24)
    rand.Read(b)
    return base64.StdEncoding.EncodeToString(b)
}

func hashPassword(password string) string {
    hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(hash)
}
```

**Step 5: Add `golang.org/x/crypto` dependency**

Run: `cd api && go get golang.org/x/crypto/bcrypt`

**Step 6: Update DeleteTunnel for EAP**

Di fungsi `DeleteTunnel`, cek auth_type sebelum hapus secret:

```go
// Get auth_type before deleting
var authType, username string
err = row.Scan(&tunnel.ID, &tunnel.TunnelID, &tunnel.Name, &tunnel.PeerIP,
    &tunnel.LocalSubnet, &tunnel.AuthType, &tunnel.Username, &tunnel.PSK, ...)

if authType == "eap" && username != "" {
    strongswan.RemoveEAPSecret(s.swanCfg, username)
} else {
    strongswan.RemovePSK(s.swanCfg, tunnelID)
}
```

**Step 7: Return password once on creation**

Di CreateTunnel response, password_plain HANYA muncul di response creation. Setelah itu, hanya bcrypt hash di DB.

```go
type CreateTunnelResponse struct {
    Tunnel
    Password string `json:"password,omitempty"` // only on create, for EAP tunnels
}
```

**Step 8: Commit**

```bash
git add api/internal/service/service.go api/go.mod api/go.sum
git commit -m "feat(service): support EAP auth type in CreateTunnel"
```

---

### Task 5: Create Roadwarrior EAP Server Config

**Objective:** Satu connection profile yang menerima semua EAP client dengan `%any`

**Files:**
- Create: `server/swanctl/roadwarrior-eap.conf.example`

**Step 1: Write config template**

```conf
# strongSwan swanctl — IKEv2 Roadwarrior EAP-MSCHAPv2 (TEMPLATE)
#
# DO NOT EDIT THIS FILE DIRECTLY.
# This is placed in config/conf.d/ by setup.sh or vpn-manager.
#
# PLACEHOLDERS:
#   {{SERVER_PUBLIC_IP}}    — VPS public IPv4
#   {{VPN_POOL_SUBNET}}     — Client virtual IP pool
#
# Auth: EAP-MSCHAPv2 — credentials in config/secret file

connections {

    roadwarrior-eap {
        version = 2

        local {
            addrs = {{SERVER_PUBLIC_IP}}
            auth = pubkey
        }

        remote {
            addrs = %any
            auth = eap-mschapv2
            eap_id = %any
        }

        children {
            net {
                local_ts = 0.0.0.0::0
                remote_ts = dynamic
                esp_proposals = aes256-sha256-ecp384
                dpd_delay = 30s
                dpd_timeout = 120s
                rekey_time = 1h
                start_action = trap
            }
        }

        proposals = aes256-sha256-ecp384
        rekey_time = 4h
        keyingtries = 0
    }
}

pools {
    vpn-pool {
        addrs = {{VPN_POOL_SUBNET}}
    }
}
```

**Step 2: Commit**

```bash
git add server/swanctl/roadwarrior-eap.conf.example
git commit -m "feat(server): add roadwarrior EAP-MSCHAPv2 connection template"
```

---

### Task 6: Update Mikrotik RSC Template for EAP

**Objective:** Template Mikrotik yang pakai EAP auth (username + password)

**Files:**
- Modify: `api/internal/template/templates/mikrotik.rsc.tmpl`
- Modify: `api/internal/template/template.go`

**Step 1: Add EAP fields to TunnelData**

```go
type TunnelData struct {
    TunnelID    string
    PeerIP      string
    LocalIP     string
    LocalSubnet string
    PSK         string
    AuthType    string // "psk" or "eap"
    Username    string
    Password    string
}
```

**Step 2: Create EAP Mikrotik template**

Buat `api/internal/template/templates/mikrotik-eap.rsc.tmpl`:

```
# VPN Tunnel: {{.TunnelID}}
# Auth: EAP-MSCHAPv2
# Generated by vpn-manager — import via: /import file=mikrotik-eap-{{.TunnelID}}.rsc

# ── STEP 1: IPsec Proposal (Child SA / data plane) ──
/ip ipsec proposal
add name=vpn-{{.TunnelID}} \
    auth-algorithms=sha256 \
    enc-algorithms=aes-256-cbc \
    pfs-group=ecp384 \
    lifetime=1h


# ── STEP 2: IPsec Profile (IKE SA / control channel) ──
/ip ipsec profile
add name=vpn-{{.TunnelID}} \
    dh-group=ecp384 \
    enc-algorithm=aes-256 \
    hash-algorithm=sha256 \
    nat-traversal=yes \
    proposal-check=obey \
    exchange-mode=ike2


# ── STEP 3: IPsec Peer (remote server) ──
/ip ipsec peer
add address={{.PeerIP}}/32 \
    name=vpn-{{.TunnelID}} \
    profile=vpn-{{.TunnelID}} \
    auth-method=eap \
    eap-methods=mschapv2 \
    username="{{.Username}}" \
    password="{{.Password}}"


# ── STEP 4: Mode Config (request virtual IP) ──
/ip ipsec mode-config
add name=vpn-{{.TunnelID}}-mode-config \
    address={{.LocalSubnet}} \
    connection-mark=default


# ── STEP 5: IPsec Policy (traffic selector) ──
/ip ipsec policy
add src-address={{.LocalSubnet}} \
    dst-address=0.0.0.0/0 \
    proposal=vpn-{{.TunnelID}} \
    sa-src-address=0.0.0.0 \
    sa-dst-address={{.PeerIP}} \
    tunnel=yes \
    action=encrypt \
    comment="VPN: {{.TunnelID}}"


# ── VERIFICATION ──
# /ip ipsec active-peers print
# /ip ipsec installed-sa print
# /log print follow where topics=ipsec
```

**Step 3: Update template.go to parse EAP template**

```go
eapRscTmpl = template.Must(template.ParseFS(templatesFS, "templates/mikrotik-eap.rsc.tmpl"))
```

Tambah method:
```go
func RenderMikroTikEAPRSC(data TunnelData) (string, error) {
    var buf bytes.Buffer
    if err := eapRscTmpl.Execute(&buf, data); err != nil {
        return "", err
    }
    return buf.String(), nil
}
```

**Step 4: Update GetMikroTikRSC handler**

Di `service.go` `GetMikroTikRSC()`, branch berdasarkan auth_type:

```go
if tunnel.AuthType == "eap" {
    data := template.TunnelData{
        TunnelID: tunnel.TunnelID,
        PeerIP:   serverPublicIP,
        LocalSubnet: tunnel.LocalSubnet,
        AuthType:  "eap",
        Username:  tunnel.Username,
        Password:  tunnel.PasswordPlain,
    }
    return template.RenderMikroTikEAPRSC(data)
}
```

**Step 5: Commit**

```bash
git add api/internal/template/
git commit -m "feat(template): add EAP Mikrotik RSC template + rendering"
```

---

### Task 7: Update Setup Script for EAP Mode

**Objective:** setup.sh bisa generate EAP roadwarrior config

**Files:**
- Modify: `scripts/setup.sh`
- Modify: `.env.example`

**Step 1: Add AUTH_TYPE to .env.example**

```bash
# ── Authentication Method ──────────────────────────────────────
# "psk" = site-to-site with pre-shared key (legacy, single tunnel)
# "eap" = multi-tenant roadwarrior with username/password (recommended)
AUTH_TYPE=eap
```

**Step 2: Update setup.sh to handle EAP mode**

Tambahkan di setup.sh setelah section generate swanctl.conf:

```bash
# ── Generate EAP roadwarrior config ──
if [[ "${AUTH_TYPE:-psk}" == "eap" ]]; then
  TEMPLATE_EAP="${REPO_ROOT}/server/swanctl/roadwarrior-eap.conf.example"
  OUTPUT_EAP="${CONF_DIR}/roadwarrior-eap.conf"

  if [[ -f "${TEMPLATE_EAP}" ]]; then
    sed \
      -e "s|{{SERVER_PUBLIC_IP}}|${SERVER_PUBLIC_IP}|g" \
      -e "s|{{VPN_POOL_SUBNET}}|${VPN_POOL_SUBNET}|g" \
      "${TEMPLATE_EAP}" > "${OUTPUT_EAP}"
    chmod 600 "${OUTPUT_EAP}"
    pass "Generated: config/conf.d/roadwarrior-eap.conf (EAP mode)"
  else
    fail "Template not found: ${TEMPLATE_EAP}"
    exit 1
  fi

  # For EAP mode, secret file is managed by vpn-manager API
  # Don't generate PSK secret
  warn "EAP mode: credentials managed via API (POST /api/v1/tunnels)"
else
  # Existing PSK flow (unchanged)
  ...
fi
```

**Step 3: Commit**

```bash
git add scripts/setup.sh .env.example
git commit -m "feat(setup): support AUTH_TYPE=eap in setup.sh"
```

---

### Task 8: Update Deploy Verification for EAP

**Objective:** deploy.yml cek EAP connection loaded + auth plugins present

**Files:**
- Modify: `.github/workflows/deploy.yml:162-165`

**Step 1: Update swanctl check**

Di deploy.yml, setelah `CONN_COUNT` check:

```yaml
# Check loaded plugins include EAP
EAP_CHECK=$(docker exec vpn-server swanctl --list-plugins 2>/dev/null | grep -c "eap-mschapv2" || echo "0")
if [ "$EAP_CHECK" -ge 1 ]; then
  echo "  ✅ EAP-MSCHAPv2 plugin loaded"
else
  echo "  ⚠️ EAP-MSCHAPv2 plugin not loaded (PSK-only mode)"
fi
```

**Step 2: Commit**

```bash
git add .github/workflows/deploy.yml
git commit -m "feat(deploy): add EAP plugin verification"
```

---

### Task 9: Update GetTunnel Response — Mask Password

**Objective:** Password hanya muncul di CreateTunnel response, bukan di GetTunnel/ListTunnels

**Files:**
- Modify: `api/internal/service/service.go`

**Step 1: Ensure SELECT excludes password_plain for list/get**

Di `GetTunnel` dan `ListTunnels`, scan query JANGAN include `password_plain`. Kolom ini cuma dipakai internal saat CreateTunnel (generate + write ke secret file) dan saat render RSC.

**Step 2: Verify scan doesn't leak**

Run: `grep -n "password_plain" api/internal/service/service.go`
Expected: hanya di INSERT dan di GetMikroTikRSC (internal, tidak di JSON response)

**Step 3: Commit**

```bash
git add api/internal/service/service.go
git commit -m "security: exclude password_plain from list/get responses"
```

---

### Task 10: Documentation & README Update

**Objective:** Update README dengan flow EAP + API usage examples

**Files:**
- Modify: `README.md`

**Step 1: Add EAP section to README**

```markdown
## EAP Multi-Tenant Mode (Recommended)

### Quick Start

1. Set `AUTH_TYPE=eap` in `.env`
2. Run `bash scripts/setup.sh` — generates roadwarrior EAP config
3. Deploy via CI

### Add a Mikrotik Client

```bash
# Create tunnel (returns username + password ONCE)
curl -X POST http://SERVER:6060/api/v1/tunnels \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "ISP-Bandung", "local_subnet": "192.168.1.0/24", "auth_type": "eap"}'

# Response:
# {
#   "data": {
#     "tunnel_id": "tun-a1b2c3d4",
#     "name": "ISP-Bandung",
#     "username": "isp-bandung-f7a3b2c1",
#     "password": "xK9mP2nQ8vL5wR7yT4jH1dF6sA3bN0cE",
#     ...
#   }
# }

# Download Mikrotik config
curl http://SERVER:6060/api/v1/tunnels/tun-a1b2c3d4/rsc \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -o mikrotik-bandung.rsc

# Import to Mikrotik
# Upload mikrotik-bandung.rsc → /import file=mikrotik-bandung.rsc
```

### Revoke a Client

```bash
curl -X DELETE http://SERVER:6060/api/v1/tunnels/tun-a1b2c3d4 \
  -H "Authorization: Bearer YOUR_API_KEY"
# Auto-removes from secret file + reloads strongSwan
```
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "docs: add EAP multi-tenant usage guide"
```

---

## Summary

| Task | What | Effort | Risk |
|------|------|--------|------|
| 1 | Dockerfile EAP plugins | Low | Medium — ARM SIGSEGV history |
| 2 | DB schema migration | Low | Low — ALTER with defaults |
| 3 | EAP secret writer | Low | Low — file I/O |
| 4 | Service EAP support | High | Medium — core business logic |
| 5 | Roadwarrior EAP config | Low | Low — static template |
| 6 | Mikrotik EAP template | Medium | Medium — need real RouterOS test |
| 7 | Setup script EAP mode | Low | Low — bash branching |
| 8 | Deploy verification | Low | Low — informational check |
| 9 | Password masking | Low | High — security sensitive |
| 10 | Documentation | Low | None |

**Total: 10 tasks, ~1-2 hari kerja**

**Critical path: Task 1 (Dockerfile) → Task 5 (config) → Task 4 (service) → Task 6 (template)**
Tasks 2, 3, 7, 8, 9, 10 can parallel.

**Backward compatibility:** PSK tunnels tetap jalan. `auth_type` default = `psk`. EAP = opt-in.

---

## Open Questions (untuk Sibung)

1. **RouterOS version** — EAP support di RouterOS 7.x native. 6.49.x perlu cek. Semua Mikrotik target sudah 7.x?
2. **Password policy** — Sekarang generate random 24-char base64. Mau bisa custom (admin-defined password) juga?
3. **Rate limiting** — Perlu login attempt limit per username? (anti brute force)
4. **IP pool management** — Setiap tunnel dapat IP dari pool yang sama (10.10.10.x), atau per-tenant IP range?
