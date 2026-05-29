package config

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/ajianaz/vpn-manager/internal/crypto"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	// DB_URL is the PostgreSQL connection string (required).
	DBURL string
	// LISTEN is the HTTP listen address (default ":8080").
	Listen string
	// VPN_CONTAINER is the Docker container name for the VPN service (default "vpn").
	VPNContainer string
	// VPNConfigDir is the path to strongSwan config directory (default "/etc/swanctl/conf.d").
	VPNConfigDir string
	// VPNSecretFile is the path to the strongSwan secrets file (default "/etc/swanctl/secret").
	VPNSecretFile string
	// VPNL2TPSecretFile is the path to the pppd chap-secrets file (default "/etc/ppp/chap-secrets").
	VPNL2TPSecretFile string
	// VPNLocalIP is the VPN server gateway address inside the tunnel subnet (default "10.10.10.1").
	VPNLocalIP string
	// API_KEY is the shared secret for authenticating API requests (required).
	APIKey string
	// EncryptionKey is the AES-256 key (base64-encoded, 32 bytes) for
	// encrypting sensitive data at rest (password_encrypted column).
	// Auto-generated on first run if not set.
	EncryptionKey []byte
}

// Load reads configuration from environment variables. Returns an error if
// any required variable (DB_URL, API_KEY) is missing.
func Load() (*Config, error) {
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("required env var DB_URL is not set")
	}

	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("required env var API_KEY is not set")
	}

	cryptoKeyStr := os.Getenv("ENCRYPTION_KEY")
	var (
		cryptoKey []byte
		err       error
	)
	if cryptoKeyStr != "" {
		cryptoKey, err = crypto.DecodeKey(cryptoKeyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid ENCRYPTION_KEY: %w", err)
		}
	} else {
		// Auto-generate encryption key on first run.
		cryptoKeyStr, err = crypto.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("generate encryption key: %w", err)
		}
		cryptoKey, _ = crypto.DecodeKey(cryptoKeyStr)
		slog.Warn("ENCRYPTION_KEY not set — auto-generated a new key. "+
			"Persist it in your .env file or all encrypted passwords will be lost on restart!",
			"generated_key", cryptoKeyStr)
	}

	cfg := &Config{
		DBURL:            dbURL,
		Listen:           envOr("LISTEN", ":8080"),
		VPNContainer:     envOr("VPN_CONTAINER", "vpn"),
		VPNConfigDir:     envOr("VPN_CONFIG_DIR", "/etc/swanctl/conf.d"),
		VPNSecretFile:    envOr("VPN_SECRET_FILE", "/etc/swanctl/secret"),
		VPNL2TPSecretFile: envOr("VPN_L2TP_SECRET_FILE", "/etc/ppp/chap-secrets"),
		VPNLocalIP:       envOr("VPN_LOCAL_IP", "10.10.10.1"),
		APIKey:           apiKey,
		EncryptionKey:    cryptoKey,
	}

	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
