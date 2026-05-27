package config

import (
	"fmt"
	"os"
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
	// API_KEY is the shared secret for authenticating API requests (required).
	APIKey string
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

	cfg := &Config{
		DBURL:        dbURL,
		Listen:       envOr("LISTEN", ":8080"),
		VPNContainer: envOr("VPN_CONTAINER", "vpn"),
		VPNConfigDir: envOr("VPN_CONFIG_DIR", "/etc/swanctl/conf.d"),
		VPNSecretFile:     envOr("VPN_SECRET_FILE", "/etc/swanctl/secret"),
		VPNL2TPSecretFile: envOr("VPN_L2TP_SECRET_FILE", "/etc/ppp/chap-secrets"),
		APIKey:            apiKey,
	}

	return cfg, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
