// Package service implements the core business logic for VPN tunnel management:
// CRUD operations, IP allocation from a pool, strongSwan config generation,
// and MikroTik RouterOS script rendering.
package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/ajianaz/vpn-manager/internal/strongswan"
	"github.com/ajianaz/vpn-manager/internal/template"
)

// LOCAL_IP is the VPN server gateway address inside the tunnel subnet.
const LOCAL_IP = "10.10.10.1"

// Sentinel errors.
var (
	ErrNotFound     = errors.New("tunnel not found")
	ErrNoAvailableIP = errors.New("no available IP addresses in pool")
)

// NotFoundError is returned when a specific tunnel cannot be found by tunnel_id.
type NotFoundError struct {
	TunnelID string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("tunnel %s not found", e.TunnelID)
}

// Tunnel represents a single VPN tunnel stored in the vpn_tunnels table.
type Tunnel struct {
	ID           string          `json:"id"`
	TunnelID     string          `json:"tunnel_id"`
	Name         string          `json:"name"`
	PeerIP       string          `json:"peer_ip"`
	LocalSubnet  string          `json:"local_subnet"`
	AuthType     string          `json:"auth_type"`
	PSK          string          `json:"psk,omitempty"`
	Username     string          `json:"username,omitempty"`
	PasswordHash string          `json:"-"`
	PasswordPlain string         `json:"-"` // never exposed in JSON responses
	Status       string          `json:"status"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

// CreateTunnelInput is the user-supplied data for creating a new tunnel.
type CreateTunnelInput struct {
	Name        string          `json:"name"`
	LocalSubnet string          `json:"local_subnet,omitempty"` // default "10.10.10.0/24"
	AuthType    string          `json:"auth_type,omitempty"`    // "eap" (default), "l2tp", or "psk"
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

// Service holds dependencies for the tunnel business logic.
type Service struct {
	pool    *pgxpool.Pool
	swanCfg strongswan.Config
}

// NewService creates a new Service instance.
func NewService(pool *pgxpool.Pool, swanCfg strongswan.Config) *Service {
	return &Service{
		pool:    pool,
		swanCfg: swanCfg,
	}
}

// CreateTunnel creates a new VPN tunnel: allocates an IP, persists the tunnel,
// writes strongSwan config + credentials, and reloads swanctl.
func (s *Service) CreateTunnel(ctx context.Context, input CreateTunnelInput) (*Tunnel, error) {
	// 1. Generate tunnel_id.
	tunnelID, err := generateTunnelID()
	if err != nil {
		return nil, fmt.Errorf("generate tunnel id: %w", err)
	}

	// 2. Determine auth type (default "eap").
	authType := strings.ToLower(strings.TrimSpace(input.AuthType))
	if authType == "" {
		authType = "eap"
	}

	// 3. Generate credentials based on auth type.
	var (
		psk          string
		username     string
		password     string
		passwordHash string
	)

	switch authType {
	case "eap", "l2tp":
		username = generateUsername(input.Name)
		password, err = generatePassword()
		if err != nil {
			return nil, fmt.Errorf("generate password: %w", err)
		}
		passwordHash, err = hashPassword(password)
		if err != nil {
			return nil, fmt.Errorf("hash password: %w", err)
		}
	case "psk":
		psk, err = generatePSK()
		if err != nil {
			return nil, fmt.Errorf("generate psk: %w", err)
		}
	default:
		return nil, fmt.Errorf("invalid auth_type %q: must be \"eap\", \"l2tp\", or \"psk\"", authType)
	}

	// 4. Default local subnet.
	localSubnet := input.LocalSubnet
	if localSubnet == "" {
		localSubnet = "10.10.10.0/24"
	}

	// 5. Allocate IP from pool.
	var peerIP string
	err = s.pool.QueryRow(ctx,
		`UPDATE vpn_ip_pool SET is_allocated=true, allocated_to=$1, updated_at=NOW()
		 WHERE is_allocated=false
		 ORDER BY ip_address
		 LIMIT 1
		 RETURNING ip_address`,
		tunnelID,
	).Scan(&peerIP)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoAvailableIP, err)
	}

	// 6. Insert tunnel record.
	var t Tunnel
	err = s.pool.QueryRow(ctx,
		`INSERT INTO vpn_tunnels (tunnel_id, name, peer_ip, local_subnet, auth_type, psk, username, password_hash, password_plain, status, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', $10)
		 RETURNING id, tunnel_id, name, peer_ip, local_subnet, auth_type, psk, username, password_hash, password_plain, status, metadata, created_at, updated_at`,
		tunnelID, input.Name, peerIP, localSubnet, authType, psk, username, passwordHash, password, input.Metadata,
	).Scan(&t.ID, &t.TunnelID, &t.Name, &t.PeerIP, &t.LocalSubnet, &t.AuthType, &t.PSK, &t.Username, &t.PasswordHash, &t.PasswordPlain, &t.Status, &t.Metadata, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		// Release allocated IP on insert failure.
		s.releaseIP(ctx, tunnelID)
		return nil, fmt.Errorf("insert tunnel: %w", err)
	}

	// Build TunnelData for strongSwan operations.
	data := strongswan.TunnelData{
		TunnelID:    t.TunnelID,
		PeerIP:      t.PeerIP,
		LocalIP:     LOCAL_IP,
		LocalSubnet: t.LocalSubnet,
		PSK:         t.PSK,
	}
	// Only PSK tunnels need per-tunnel connection config
	if authType == "psk" || authType == "" {
		if err := strongswan.WriteTunnelConfig(s.swanCfg, data); err != nil {
			// Cleanup: remove DB entry and release IP.
			s.deleteTunnelDB(ctx, t.TunnelID)
			s.releaseIP(ctx, t.TunnelID)
			return nil, fmt.Errorf("write tunnel config: %w", err)
		}
	}

	// 7. Write secrets based on auth type.
	switch authType {
	case "eap":
		if err := strongswan.WriteEAPSecret(s.swanCfg, t.Username, t.PasswordPlain); err != nil {
			strongswan.RemoveTunnelConfig(s.swanCfg, t.TunnelID)
			s.deleteTunnelDB(ctx, t.TunnelID)
			s.releaseIP(ctx, t.TunnelID)
			return nil, fmt.Errorf("write eap secret: %w", err)
		}
	case "l2tp":
		if err := strongswan.WriteL2TPSecret(s.swanCfg, t.Username, t.PasswordPlain); err != nil {
			strongswan.RemoveTunnelConfig(s.swanCfg, t.TunnelID)
			s.deleteTunnelDB(ctx, t.TunnelID)
			s.releaseIP(ctx, t.TunnelID)
			return nil, fmt.Errorf("write l2tp secret: %w", err)
		}
	case "psk":
		if err := strongswan.WritePSK(s.swanCfg, data); err != nil {
			// Cleanup: remove DB entry, release IP, remove config file.
			strongswan.RemoveTunnelConfig(s.swanCfg, t.TunnelID)
			s.deleteTunnelDB(ctx, t.TunnelID)
			s.releaseIP(ctx, t.TunnelID)
			return nil, fmt.Errorf("write psk: %w", err)
		}
	}

	// 8. Reload swanctl.
	if err := strongswan.ReloadSwanctl(s.swanCfg); err != nil {
		// Cleanup: remove DB entry, release IP, remove config + secrets.
		strongswan.RemoveTunnelConfig(s.swanCfg, t.TunnelID)
		s.removeSecretByAuthType(ctx, t)
		s.deleteTunnelDB(ctx, t.TunnelID)
		s.releaseIP(ctx, t.TunnelID)
		return nil, fmt.Errorf("reload swanctl: %w", err)
	}

	return &t, nil
}

// GetTunnel retrieves a tunnel by its human-readable tunnel_id.
func (s *Service) GetTunnel(ctx context.Context, tunnelID string) (*Tunnel, error) {
	var t Tunnel
	err := s.pool.QueryRow(ctx,
		`SELECT id, tunnel_id, name, peer_ip, local_subnet, auth_type, psk, username, password_hash, password_plain, status, metadata, created_at, updated_at
		 FROM vpn_tunnels WHERE tunnel_id=$1`,
		tunnelID,
	).Scan(&t.ID, &t.TunnelID, &t.Name, &t.PeerIP, &t.LocalSubnet, &t.AuthType, &t.PSK, &t.Username, &t.PasswordHash, &t.PasswordPlain, &t.Status, &t.Metadata, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &NotFoundError{TunnelID: tunnelID}
		}
		return nil, fmt.Errorf("get tunnel %s: %w", tunnelID, err)
	}
	return &t, nil
}

// ListTunnels returns tunnels ordered by creation time (newest first).
// If username is non-empty, filters by that username (used by updown.sh routing).
func (s *Service) ListTunnels(ctx context.Context, username string) ([]Tunnel, error) {
	query := `SELECT id, tunnel_id, name, peer_ip, local_subnet, auth_type, psk, username, password_hash, password_plain, status, metadata, created_at, updated_at
		 FROM vpn_tunnels`
	var args []interface{}
	if username != "" {
		query += ` WHERE username = $1`
		args = append(args, username)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list tunnels: %w", err)
	}
	defer rows.Close()

	var tunnels []Tunnel
	for rows.Next() {
		var t Tunnel
		if err := rows.Scan(&t.ID, &t.TunnelID, &t.Name, &t.PeerIP, &t.LocalSubnet, &t.AuthType, &t.PSK, &t.Username, &t.PasswordHash, &t.PasswordPlain, &t.Status, &t.Metadata, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan tunnel row: %w", err)
		}
		tunnels = append(tunnels, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tunnels: %w", err)
	}
	return tunnels, nil
}

// DeleteTunnel removes a tunnel: its strongSwan config, IP allocation, and DB record.
func (s *Service) DeleteTunnel(ctx context.Context, tunnelID string) error {
	// 1. Verify tunnel exists and get auth info.
	var authType, username string
	err := s.pool.QueryRow(ctx,
		`SELECT auth_type, COALESCE(username, '') FROM vpn_tunnels WHERE tunnel_id=$1`,
		tunnelID,
	).Scan(&authType, &username)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &NotFoundError{TunnelID: tunnelID}
		}
		return fmt.Errorf("get tunnel %s: %w", tunnelID, err)
	}

	// 2. Remove strongSwan config (best-effort, PSK only).
	if authType == "psk" {
		if err := strongswan.RemoveTunnelConfig(s.swanCfg, tunnelID); err != nil {
			slog.Error("failed to remove tunnel config, continuing cleanup",
				"tunnel_id", tunnelID, "error", err)
		}
	}

	// 3. Remove secrets based on auth type (best-effort).
	switch authType {
	case "eap":
		if username != "" {
			if err := strongswan.RemoveEAPSecret(s.swanCfg, username); err != nil {
				slog.Error("failed to remove eap secret", "tunnel_id", tunnelID, "error", err)
			}
		}
	case "l2tp":
		if username != "" {
			if err := strongswan.RemoveL2TPSecret(s.swanCfg, username); err != nil {
				slog.Error("failed to remove l2tp secret", "tunnel_id", tunnelID, "error", err)
			}
		}
	case "psk":
		if err := strongswan.RemovePSK(s.swanCfg, tunnelID); err != nil {
			slog.Error("failed to remove psk", "tunnel_id", tunnelID, "error", err)
		}
	}

	// 4. Release IP allocation (best-effort).
	s.releaseIP(ctx, tunnelID)

	// 5. Delete DB record.
	if err := s.deleteTunnelDB(ctx, tunnelID); err != nil {
		return fmt.Errorf("delete tunnel %s: %w", tunnelID, err)
	}

	// 6. Reload swanctl (best-effort).
	if err := strongswan.ReloadSwanctl(s.swanCfg); err != nil {
		slog.Error("failed to reload swanctl after delete",
			"tunnel_id", tunnelID, "error", err)
	}

	return nil
}

// GetMikroTikRSC returns a rendered MikroTik RouterOS import script for the tunnel.
func (s *Service) GetMikroTikRSC(ctx context.Context, tunnelID string) (string, error) {
	t, err := s.GetTunnel(ctx, tunnelID)
	if err != nil {
		return "", err
	}

	data := template.TunnelData{
		TunnelID:    t.TunnelID,
		PeerIP:      t.PeerIP,
		LocalIP:     LOCAL_IP,
		LocalSubnet: t.LocalSubnet,
		PSK:         t.PSK,
		AuthType:    t.AuthType,
		Username:    t.Username,
		Password:    t.PasswordPlain,
	}

	var rendered string
	switch strings.ToLower(t.AuthType) {
	case "eap":
		rendered, err = template.RenderMikroTikEAPRSC(data)
	case "l2tp":
		rendered, err = template.RenderMikroTikL2TPRSC(data)
	case "psk":
		rendered, err = template.RenderMikroTikRSC(data)
	default:
		rendered, err = template.RenderMikroTikRSC(data)
	}
	if err != nil {
		return "", fmt.Errorf("render mikrotik rsc for %s: %w", tunnelID, err)
	}
	return rendered, nil
}

// ReloadAll reloads the strongSwan daemon configuration.
func (s *Service) ReloadAll(_ context.Context) error {
	if err := strongswan.ReloadSwanctl(s.swanCfg); err != nil {
		return fmt.Errorf("reload all: %w", err)
	}
	return nil
}

// --- helpers ---

// generateTunnelID creates a human-readable tunnel ID: "tun-" + 8 random hex chars.
func generateTunnelID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "tun-" + hex.EncodeToString(b), nil
}

// generatePSK creates a 32-character hex string for use as a pre-shared key.
func generatePSK() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// releaseIP marks an IP in the pool as unallocated (best-effort logging).
func (s *Service) releaseIP(ctx context.Context, tunnelID string) {
	_, err := s.pool.Exec(ctx,
		`UPDATE vpn_ip_pool SET is_allocated=false, allocated_to=NULL, updated_at=NOW()
		 WHERE allocated_to=$1`,
		tunnelID,
	)
	if err != nil {
		slog.Error("failed to release IP", "tunnel_id", tunnelID, "error", err)
	}
}

// deleteTunnelDB removes the tunnel row from the database.
func (s *Service) deleteTunnelDB(ctx context.Context, tunnelID string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM vpn_tunnels WHERE tunnel_id=$1`, tunnelID)
	if err != nil {
		return fmt.Errorf("db delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &NotFoundError{TunnelID: tunnelID}
	}
	return nil
}

// CreateTunnelResponse wraps a Tunnel with the plaintext password (only
// returned on create for EAP/L2TP auth types).
type CreateTunnelResponse struct {
	Tunnel
	Password string `json:"password,omitempty"` // only shown on create for EAP/L2TP
}

// removeSecretByAuthType removes the appropriate secret file entry during
// rollback based on the tunnel's auth_type.
func (s *Service) removeSecretByAuthType(_ context.Context, t Tunnel) {
	switch t.AuthType {
	case "eap":
		if t.Username != "" {
			if err := strongswan.RemoveEAPSecret(s.swanCfg, t.Username); err != nil {
				slog.Error("failed to remove eap secret during rollback",
					"tunnel_id", t.TunnelID, "error", err)
			}
		}
	case "l2tp":
		if t.Username != "" {
			if err := strongswan.RemoveL2TPSecret(s.swanCfg, t.Username); err != nil {
				slog.Error("failed to remove l2tp secret during rollback",
					"tunnel_id", t.TunnelID, "error", err)
			}
		}
	case "psk":
		if err := strongswan.RemovePSK(s.swanCfg, t.TunnelID); err != nil {
			slog.Error("failed to remove psk during rollback",
				"tunnel_id", t.TunnelID, "error", err)
		}
	}
}

var nonAlnumRe = regexp.MustCompile(`[^a-z0-9]+`)

// generateUsername creates a deterministic-ish username from the tunnel name:
// lowercase, replace non-alnum with hyphens, trim to 28 chars, append 4-byte hex suffix.
func generateUsername(name string) string {
	lower := strings.ToLower(name)
	clean := nonAlnumRe.ReplaceAllString(lower, "-")
	clean = strings.Trim(clean, "-")
	if len(clean) > 28 {
		clean = clean[:28]
	}

	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		suffix = []byte{0, 0, 0, 0}
	}
	return clean + "-" + hex.EncodeToString(suffix)
}

// generatePassword creates a random password: 24 random bytes, base64-encoded.
func generatePassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// hashPassword returns a bcrypt hash of the given password.
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
