// Package service implements the core business logic for VPN tunnel management:
// CRUD operations, IP allocation from a pool, strongSwan config generation,
// and MikroTik RouterOS script rendering.
package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

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
// writes strongSwan config + PSK, and reloads swanctl.
func (s *Service) CreateTunnel(ctx context.Context, input CreateTunnelInput) (*Tunnel, error) {
	// 1. Generate tunnel_id.
	tunnelID, err := generateTunnelID()
	if err != nil {
		return nil, fmt.Errorf("generate tunnel id: %w", err)
	}

	// 2. Generate PSK.
	psk, err := generatePSK()
	if err != nil {
		return nil, fmt.Errorf("generate psk: %w", err)
	}

	// 3. Default local subnet.
	localSubnet := input.LocalSubnet
	if localSubnet == "" {
		localSubnet = "10.10.10.0/24"
	}

	// 4. Allocate IP from pool.
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

	// 5. Insert tunnel record.
	var t Tunnel
	err = s.pool.QueryRow(ctx,
		`INSERT INTO vpn_tunnels (tunnel_id, name, peer_ip, local_subnet, psk, status, metadata)
		 VALUES ($1, $2, $3, $4, $5, 'active', $6)
		 RETURNING id, tunnel_id, name, peer_ip, local_subnet, psk, status, metadata, created_at, updated_at`,
		tunnelID, input.Name, peerIP, localSubnet, psk, input.Metadata,
	).Scan(&t.ID, &t.TunnelID, &t.Name, &t.PeerIP, &t.LocalSubnet, &t.PSK, &t.Status, &t.Metadata, &t.CreatedAt, &t.UpdatedAt)
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
	if err := strongswan.WriteTunnelConfig(s.swanCfg, data); err != nil {
		// Cleanup: remove DB entry and release IP.
		s.deleteTunnelDB(ctx, t.TunnelID)
		s.releaseIP(ctx, t.TunnelID)
		return nil, fmt.Errorf("write tunnel config: %w", err)
	}

	// 7. Write PSK.
	if err := strongswan.WritePSK(s.swanCfg, data); err != nil {
		// Cleanup: remove DB entry, release IP, remove config file.
		strongswan.RemoveTunnelConfig(s.swanCfg, t.TunnelID)
		s.deleteTunnelDB(ctx, t.TunnelID)
		s.releaseIP(ctx, t.TunnelID)
		return nil, fmt.Errorf("write psk: %w", err)
	}

	// 8. Reload swanctl.
	if err := strongswan.ReloadSwanctl(s.swanCfg); err != nil {
		// Cleanup: remove DB entry, release IP, remove config + PSK.
		strongswan.RemoveTunnelConfig(s.swanCfg, t.TunnelID)
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
		`SELECT id, tunnel_id, name, peer_ip, local_subnet, psk, status, metadata, created_at, updated_at
		 FROM vpn_tunnels WHERE tunnel_id=$1`,
		tunnelID,
	).Scan(&t.ID, &t.TunnelID, &t.Name, &t.PeerIP, &t.LocalSubnet, &t.PSK, &t.Status, &t.Metadata, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, &NotFoundError{TunnelID: tunnelID}
		}
		return nil, fmt.Errorf("get tunnel %s: %w", tunnelID, err)
	}
	return &t, nil
}

// ListTunnels returns all tunnels ordered by creation time (newest first).
func (s *Service) ListTunnels(ctx context.Context) ([]Tunnel, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, tunnel_id, name, peer_ip, local_subnet, psk, status, metadata, created_at, updated_at
		 FROM vpn_tunnels ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list tunnels: %w", err)
	}
	defer rows.Close()

	var tunnels []Tunnel
	for rows.Next() {
		var t Tunnel
		if err := rows.Scan(&t.ID, &t.TunnelID, &t.Name, &t.PeerIP, &t.LocalSubnet, &t.PSK, &t.Status, &t.Metadata, &t.CreatedAt, &t.UpdatedAt); err != nil {
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
	// 1. Verify tunnel exists.
	if _, err := s.GetTunnel(ctx, tunnelID); err != nil {
		return err
	}

	// 2. Remove strongSwan config (best-effort).
	if err := strongswan.RemoveTunnelConfig(s.swanCfg, tunnelID); err != nil {
		slog.Error("failed to remove tunnel config, continuing cleanup",
			"tunnel_id", tunnelID, "error", err)
	}

	// 3. Release IP allocation (best-effort).
	s.releaseIP(ctx, tunnelID)

	// 4. Delete DB record.
	if err := s.deleteTunnelDB(ctx, tunnelID); err != nil {
		return fmt.Errorf("delete tunnel %s: %w", tunnelID, err)
	}

	// 5. Reload swanctl (best-effort).
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
	}

	rendered, err := template.RenderMikroTikRSC(data)
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
