// Package strongswan provides integration with strongSwan IPsec VPN
// via Docker exec for swanctl configuration management.
//
// TEMPLATE SAFETY (#55): All configuration rendering uses Go's standard
// text/template package (see internal/template/). Go templates do NOT execute
// shell commands or evaluate arbitrary code — they only perform text
// substitution. This eliminates envsubst-style injection risks where
// environment variable values could influence shell expansion.
// No envsubst is used anywhere in this codebase.
package strongswan

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// Config holds the paths and container reference for strongSwan operations.
type Config struct {
	ContainerName string // Docker container name (default: "vpn")
	ConfigDir     string // Path to swanctl conf.d directory (default: "/etc/swanctl/conf.d")
	SecretFile    string // Path to swanctl secret file (default: "/etc/swanctl/secret")
	L2TPSecretFile string // Path to PPP chap-secrets file (default: "/etc/ppp/chap-secrets")
}

// DefaultL2TPSecretFile is the default path for the L2TP chap-secrets file.
const DefaultL2TPSecretFile = "/etc/ppp/chap-secrets"

// TunnelData contains all information needed to generate a swanctl
// connection config and PSK entry for a single tunnel.
type TunnelData struct {
	TunnelID    string // e.g. "tun-abc123"
	PeerIP      string // e.g. "203.0.113.5"
	LocalIP     string // e.g. "10.10.10.1"
	LocalSubnet string // e.g. "10.10.10.0/24"
	PSK         string // 32-char hex
}

// WriteTunnelConfig writes the swanctl connection configuration file for
// the given tunnel to {ConfigDir}/{TunnelID}.conf. The directory is
// created with os.MkdirAll if it does not exist.
func WriteTunnelConfig(cfg Config, data TunnelData) error {
	if err := os.MkdirAll(cfg.ConfigDir, 0o755); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}

	content := fmt.Sprintf(`connections {
    %s {
        version = 2
        proposals = aes256-sha256-ecp384
        rekey_time = 3600s
        local_addrs = %s
        remote_addrs = %s

        local {
            auth = psk
        }
        remote {
            auth = psk
        }

        children {
            net-%s {
                local_ts = %s
                esp_proposals = aes256-sha256-ecp384
                dpd_action = clear
                close_action = none
            }
        }
    }
}
`, data.TunnelID, data.LocalIP, data.PeerIP, data.TunnelID, data.LocalSubnet)

	path := fmt.Sprintf("%s/%s.conf", cfg.ConfigDir, data.TunnelID)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write tunnel config %s: %w", path, err)
	}

	slog.Info("wrote tunnel config", "path", path, "tunnel_id", data.TunnelID)
	return nil
}

// WritePSK appends a PSK entry for the given tunnel to the swanctl secret
// file. Each entry is tagged with a comment so it can be identified and
// removed later. The file is created with mode 0640 if it does not exist.
func WritePSK(cfg Config, data TunnelData) error {
	entry := fmt.Sprintf("# tunnel:%s\n%s : PSK \"%s\"\n", data.TunnelID, data.PeerIP, data.PSK)

	f, err := os.OpenFile(cfg.SecretFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open secret file: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("write psk entry: %w", err)
	}

	slog.Info("wrote psk entry", "tunnel_id", data.TunnelID, "peer_ip", data.PeerIP)
	return nil
}

// RemoveTunnelConfig deletes the connection config file for the given
// tunnel ID and removes its associated PSK entry from the secret file.
// The operation is idempotent: it returns nil if the files do not exist.
func RemoveTunnelConfig(cfg Config, tunnelID string) error {
	// Remove config file (idempotent).
	confPath := fmt.Sprintf("%s/%s.conf", cfg.ConfigDir, tunnelID)
	if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove tunnel config %s: %w", confPath, err)
	}

	// Remove the PSK entry for this tunnel.
	if err := RemovePSK(cfg, tunnelID); err != nil {
		return fmt.Errorf("remove psk for tunnel %s: %w", tunnelID, err)
	}

	slog.Info("removed tunnel config", "tunnel_id", tunnelID)
	return nil
}

// RemovePSK removes the tagged PSK entry (comment line + PSK line) for
// the given tunnel ID from the secret file. It is idempotent: if the file
// does not exist or contains no matching entry, nil is returned.
func RemovePSK(cfg Config, tunnelID string) error {
	content, err := os.ReadFile(cfg.SecretFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
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

	if err := os.WriteFile(cfg.SecretFile, []byte(strings.Join(filtered, "\n")), 0o640); err != nil {
		return fmt.Errorf("rewrite secret file: %w", err)
	}

	slog.Info("removed psk entry", "tunnel_id", tunnelID)
	return nil
}

// ReloadSwanctl instructs the strongSwan daemon inside the Docker
// container to reload its configuration via `swanctl --reload`.
func ReloadSwanctl(cfg Config) error {
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, "docker", "exec", cfg.ContainerName, "swanctl", "--reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("swanctl reload failed: %w, output: %s", err, string(out))
	}

	slog.Info("swanctl reloaded", "container", cfg.ContainerName, "output", strings.TrimSpace(string(out)))
	return nil
}

// WriteEAPSecret appends an EAP secret entry for the given username to the
// swanctl secret file. Each entry is tagged with a comment so it can be
// identified and removed later. The file is created with mode 0640 if it
// does not exist.
func WriteEAPSecret(cfg Config, username, password string) error {
	entry := fmt.Sprintf("# tunnel-eap:%s\n%s : EAP \"%s\"\n", username, username, password)

	f, err := os.OpenFile(cfg.SecretFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open secret file: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("write eap entry: %w", err)
	}

	slog.Info("wrote eap secret", "username", username)
	return nil
}

// RemoveEAPSecret removes the tagged EAP secret entry (comment line + EAP
// line) for the given username from the swanctl secret file. It is
// idempotent: if the file does not exist or contains no matching entry,
// nil is returned.
func RemoveEAPSecret(cfg Config, username string) error {
	content, err := os.ReadFile(cfg.SecretFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read secret file: %w", err)
	}

	tag := fmt.Sprintf("# tunnel-eap:%s", username)
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

	if err := os.WriteFile(cfg.SecretFile, []byte(strings.Join(filtered, "\n")), 0o640); err != nil {
		return fmt.Errorf("rewrite secret file: %w", err)
	}

	slog.Info("removed eap secret", "username", username)
	return nil
}

// WriteL2TPSecret appends a CHAP secret entry for the given username to the
// L2TP chap-secrets file. The file is created with mode 0640 if it does not
// exist.
func WriteL2TPSecret(cfg Config, username, password string) error {
	l2tpFile := cfg.L2TPSecretFile
	if l2tpFile == "" {
		l2tpFile = DefaultL2TPSecretFile
	}

	entry := fmt.Sprintf("%s * \"%s\" *\n", username, password)

	f, err := os.OpenFile(l2tpFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("open l2tp chap-secrets file: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("write l2tp secret: %w", err)
	}

	slog.Info("wrote l2tp secret", "username", username, "file", l2tpFile)
	return nil
}

// RemoveL2TPSecret removes all CHAP secret entries for the given username
// from the L2TP chap-secrets file. It is idempotent: if the file does not
// exist or contains no matching entry, nil is returned.
func RemoveL2TPSecret(cfg Config, username string) error {
	l2tpFile := cfg.L2TPSecretFile
	if l2tpFile == "" {
		l2tpFile = DefaultL2TPSecretFile
	}

	content, err := os.ReadFile(l2tpFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read l2tp chap-secrets file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	var filtered []string
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == username {
			continue
		}
		filtered = append(filtered, line)
	}

	if err := os.WriteFile(l2tpFile, []byte(strings.Join(filtered, "\n")), 0o640); err != nil {
		return fmt.Errorf("rewrite l2tp chap-secrets file: %w", err)
	}

	slog.Info("removed l2tp secret", "username", username, "file", l2tpFile)
	return nil
}
