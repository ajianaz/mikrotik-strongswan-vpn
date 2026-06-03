# Production Hardening — VPN Manager ✅ COMPLETE

**Goal:** Clear remaining QA audit findings to reach 100% production readiness.

**Branch:** `fix/production-hardening`
**Target:** merge to `develop`
**Effort:** ~2 hours (sequential, 5 tasks)
**Status:** All tasks completed. 125 tests passing. Zero QA findings remaining.

---

## Current State

| Metric | Value |
|--------|-------|
| CI | ✅ Green (last build 3 Jun 2026) |
| Tests | 116 passing |
| Critical issues | 0 (all fixed in PR #50) |
| Remaining | 1 medium + 3 low |

---

## Task Breakdown

### Task 1: H4 — Validate TunnelID in strongswan.go (defense-in-depth)

**Objective:** Add regexp validation before using tunnelID in file path operations.

**File:** `api/internal/strongswan/strongswan.go`

**Why:** `WriteTunnelConfig` and `RemoveTunnelConfig` use `tunnelID` directly in `fmt.Sprintf("%s/%s.conf", ...)` and `fmt.Sprintf("# tunnel:%s", ...)`. Currently safe because server-generated (`tun-` + 8 hex chars), but defense-in-depth.

**Steps:**

1. Add a `validateTunnelID` helper at the top of `strongswan.go`:

```go
// tunnelIDRe validates server-generated tunnel IDs: tun- + 8 lowercase hex chars.
var tunnelIDRe = regexp.MustCompile(`^tun-[a-f0-9]{8}$`)

// validateTunnelID checks that a tunnel ID is safe for use in file paths.
// Returns error if the ID does not match the expected server-generated format.
func validateTunnelID(tunnelID string) error {
	if !tunnelIDRe.MatchString(tunnelID) {
		return fmt.Errorf("invalid tunnel ID format %q: must match tun-[a-f0-9]{8}", tunnelID)
	}
	return nil
}
```

2. Add `regexp` to imports (already imported in service.go — add to strongswan.go).
3. Call `validateTunnelID(tunnelID)` at the top of:
   - `WriteTunnelConfig(cfg Config, data TunnelData) error` — validate `data.TunnelID`
   - `RemoveTunnelConfig(cfg Config, tunnelID string) error` — validate `tunnelID`
   - `RemovePSK(cfg Config, tunnelID string) error` — validate `tunnelID`

4. Add test in `api/internal/strongswan/strongswan_test.go`:

```go
func TestValidateTunnelID(t *testing.T) {
	tests := []struct {
		name    string
		tunnelID string
		wantErr bool
	}{
		{"valid", "tun-abc12345", false},
		{"valid lowercase hex", "tun-00000000", false},
		{"valid all f", "tun-ffffffff", false},
		{"empty", "", true},
		{"no prefix", "abc12345", true},
		{"uppercase", "tun-ABC12345", true},
		{"too short", "tun-abc1234", true},
		{"too long", "tun-abc123456", true},
		{"path traversal", "tun-../etc/passwd", true},
		{"null byte", "tun-\x00abcdef", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTunnelID(tt.tunnelID)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTunnelID(%q) error = %v, wantErr %v", tt.tunnelID, err, tt.wantErr)
			}
		})
	}
}
```

5. Run tests: `cd api && go test ./internal/strongswan/... -v -run TestValidateTunnelID`
6. Commit: `fix(strongswan): validate tunnel ID format in file path operations (H4)`

**Verify:** Test passes, `go vet ./...` clean.

---

### Task 2: M3 — File-level locking on secret file operations

**Objective:** Prevent TOCTOU race on `Remove*Secret` read-modify-write patterns using `syscall.Flock`.

**File:** `api/internal/strongswan/strongswan.go`

**Why:** `RemovePSK`, `RemoveEAPSecret`, `RemoveL2TPSecret` do read→filter→write without locking. Concurrent delete+create could lose secret entries. The service-level mutex protects API calls, but direct file access (e.g., updown.sh, manual edits) is unprotected.

**Steps:**

1. Add a helper function for file locking:

```go
import (
	"io"
	"os"
	"syscall"
)

// withFileLock acquires an exclusive flock on f, calls fn, then releases.
// The file must be opened with at least O_RDWR.
func withFileLock(f *os.File, fn func() error) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("flock: %w", err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:errcheck
	return fn()
}
```

2. Refactor `RemovePSK` to use file locking:

```go
func RemovePSK(cfg Config, tunnelID string) error {
	// Open with RDWR for locking (create if missing).
	f, err := os.OpenFile(cfg.SecretFile, os.O_RDWR|os.O_CREATE, 0o640)
	if err != nil {
		return fmt.Errorf("open secret file: %w", err)
	}
	defer f.Close()

	return withFileLock(f, func() error {
		content, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("read secret file: %w", err)
		}

		tag := fmt.Sprintf("# tunnel:%s", tunnelID)
		lines := strings.Split(string(content), "\n")
		var filtered []string
		skipNext := false

		for _, line := range lines {
			if skipNext {
				skipNext = false
				continue
			}
			if strings.TrimSpace(line) == tag {
				skipNext = true
				continue
			}
			filtered = append(filtered, line)
		}

		// Truncate and rewrite.
		if err := f.Truncate(0); err != nil {
			return fmt.Errorf("truncate secret file: %w", err)
		}
		if _, err := f.Seek(0, 0); err != nil {
			return fmt.Errorf("seek secret file: %w", err)
		}
		if _, err := f.WriteString(strings.Join(filtered, "\n")); err != nil {
			return fmt.Errorf("rewrite secret file: %w", err)
		}

		slog.Info("removed psk entry", "tunnel_id", tunnelID)
		return nil
	})
}
```

3. Apply same pattern to `RemoveEAPSecret` (identical read-modify-write, different tag).
4. Apply same pattern to `RemoveL2TPSecret` (different file, username-based filter instead of tag).
5. Run tests: `cd api && go test ./internal/strongswan/... -v`
6. Commit: `fix(strongswan): add file-level flock on secret file read-modify-write (M3)`

**Verify:** All 116+ tests pass, no data race warnings with `go test -race ./...`

---

### Task 3: L1 — Remove redundant LOCAL_IP_DEFAULT constant

**Objective:** Remove the hardcoded constant that duplicates config.go's default.

**File:** `api/internal/service/service.go`

**Why:** `LOCAL_IP_DEFAULT = "10.10.10.1"` duplicates `config.go`'s `envOr("VPN_LOCAL_IP", "10.10.10.1")`. The constant is only used in the `NewService` function comment context — `localIP` comes from `cfg.VPNLocalIP` (set by config.go). The constant is never actually referenced in code.

**Steps:**

1. Check if `LOCAL_IP_DEFAULT` is used anywhere:

```bash
cd api && grep -rn 'LOCAL_IP_DEFAULT' .
```

2. If only defined but never used, remove lines 29-31:

```go
// DELETE these lines:
// LOCAL_IP_DEFAULT is the default VPN server gateway address inside the tunnel subnet.
// Configurable at runtime via the VPN_LOCAL_IP environment variable.
const LOCAL_IP_DEFAULT = "10.10.10.1"
```

3. Run lint: `cd api && golangci-lint run ./...`
4. Run tests: `cd api && go test ./...`
5. Commit: `refactor: remove unused LOCAL_IP_DEFAULT constant (L1)`

**Verify:** Lint clean, tests pass.

---

### Task 4: L2 — Remove dead template code

**Objective:** Remove `RenderSwanctlConfig` and `RenderPSK` from template.go that are never called.

**File:** `api/internal/template/template.go`

**Why:** Only `RenderMikroTikRSC`, `RenderMikroTikEAPRSC`, and `RenderMikroTikL2TPRSC` are called from `service.go`. `RenderSwanctlConfig` and `RenderPSK` are dead code from PSK era.

**Steps:**

1. Verify unused:

```bash
cd api && grep -rn 'RenderSwanctlConfig\|RenderPSK' --include='*.go' | grep -v template.go
```

2. Remove `RenderSwanctlConfig` function and its associated template file (if any in `templates/`).
3. Remove `RenderPSK` function and its associated template file.
4. Remove any template files from `api/internal/template/templates/` that are only used by deleted functions.
5. Update test file `template_test.go` — remove `TestRenderSwanctlConfig` and `TestRenderPSK` if they exist.
6. Run tests: `cd api && go test ./internal/template/... -v`
7. Commit: `refactor: remove dead PSK-era template code (L2)`

**Verify:** Tests pass, no imports broken.

---

### Task 5: M5 — Document docker-socket-proxy as future enhancement

**Objective:** Add a TODO comment and GitHub issue reference. NOT implementing socket-proxy now (single-tenant acceptable).

**File:** `docker-compose.yml`

**Why:** docker-socket-proxy adds complexity (extra container, config). Single-tenant VPN deployment doesn't justify it yet. Document for multi-tenant future.

**Steps:**

1. Update the existing SECURITY NOTE comment in `docker-compose.yml`:

```yaml
# SECURITY NOTE (#54): Mounting the Docker socket (even read-only) exposes
# container metadata to the vpn-manager API process. For multi-tenant
# deployments, replace with Tecnativa/docker-socket-proxy. For single-tenant
# (one VPN manager per host) this is acceptable — the API is behind Bearer
# auth and rate limiting. See: https://github.com/Tecnativa/docker-socket-proxy
```

2. Commit: `docs: clarify docker-socket-proxy guidance (M5)`

**Verify:** No code change, comment-only.

---

## Execution Order

| Order | Task | Finding | Effort | Risk |
|:-----:|------|---------|:------:|:----:|
| 1 | Task 3 (L1) | Remove dead constant | 5m | None |
| 2 | Task 4 (L2) | Remove dead templates | 10m | Low |
| 3 | Task 5 (M5) | Comment only | 5m | None |
| 4 | Task 1 (H4) | TunnelID validation | 20m | Low |
| 5 | Task 2 (M3) | File locking | 45m | Medium |

**Rationale:** Dead code cleanup first (no risk), then defensive hardening (low risk), then file locking (most impactful change last).

---

## Post-Implementation Checklist

- [ ] `cd api && go test ./... -v -count=1 -race` — all pass, no races
- [ ] `cd api && golangci-lint run ./...` — clean
- [ ] `cd api && govulncheck ./...` — no new vulns
- [ ] Verify README still accurate
- [ ] Update QA audit findings doc with fix status
- [ ] Push to `fix/production-hardening` → PR → `develop`
- [ ] Verify CI green → auto-deploy

---

## Expected Outcome

| Before | After |
|--------|-------|
| 85% production ready | **100%** |
| 1 medium + 3 low remaining | **0 remaining** |
| 116 tests | 125+ tests (new H4 + M3 tests) |
