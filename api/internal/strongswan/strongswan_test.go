package strongswan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testConfig(t *testing.T) (Config, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		SecretFile:     filepath.Join(dir, "secret"),
		L2TPSecretFile: filepath.Join(dir, "chap-secrets"),
		ConfigDir:      filepath.Join(dir, "conf.d"),
	}
	return cfg, dir
}

// --- WriteEAPSecret / RemoveEAPSecret ---

func TestWriteEAPSecret(t *testing.T) {
	cfg, _ := testConfig(t)

	err := WriteEAPSecret(cfg, "testuser", "testpass123")
	if err != nil {
		t.Fatalf("WriteEAPSecret() error: %v", err)
	}

	data, err := os.ReadFile(cfg.SecretFile)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "# tunnel-eap:testuser") {
		t.Error("secret file missing EAP comment tag for testuser")
	}
	if !strings.Contains(content, "testuser : EAP \"testpass123\"") {
		t.Error("secret file missing EAP entry line")
	}
}

func TestRemoveEAPSecret(t *testing.T) {
	cfg, _ := testConfig(t)

	// Write two entries
	WriteEAPSecret(cfg, "user1", "pass1")
	WriteEAPSecret(cfg, "user2", "pass2")

	// Remove user1
	err := RemoveEAPSecret(cfg, "user1")
	if err != nil {
		t.Fatalf("RemoveEAPSecret() error: %v", err)
	}

	data, _ := os.ReadFile(cfg.SecretFile)
	content := string(data)

	if strings.Contains(content, "# tunnel-eap:user1") {
		t.Error("user1 EAP entry should be removed")
	}
	if !strings.Contains(content, "# tunnel-eap:user2") {
		t.Error("user2 EAP entry should still exist")
	}
}

func TestRemoveEAPSecret_NonExistentFile(t *testing.T) {
	cfg, _ := testConfig(t)
	// Don't write anything — file doesn't exist

	err := RemoveEAPSecret(cfg, "nonexistent")
	if err != nil {
		t.Errorf("RemoveEAPSecret() on non-existent file should return nil, got: %v", err)
	}
}

// --- WriteL2TPSecret / RemoveL2TPSecret ---

func TestWriteL2TPSecret(t *testing.T) {
	cfg, _ := testConfig(t)

	err := WriteL2TPSecret(cfg, "l2tpuser", "l2tppass")
	if err != nil {
		t.Fatalf("WriteL2TPSecret() error: %v", err)
	}

	data, err := os.ReadFile(cfg.L2TPSecretFile)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	content := string(data)
	// chap-secrets format: username * "password" *
	if !strings.Contains(content, "l2tpuser * \"l2tppass\" *") {
		t.Errorf("chap-secrets file content = %q, want line containing l2tpuser entry", content)
	}
}

func TestRemoveL2TPSecret(t *testing.T) {
	cfg, _ := testConfig(t)

	// Write two entries
	WriteL2TPSecret(cfg, "user-a", "pass-a")
	WriteL2TPSecret(cfg, "user-b", "pass-b")

	// Remove user-a
	err := RemoveL2TPSecret(cfg, "user-a")
	if err != nil {
		t.Fatalf("RemoveL2TPSecret() error: %v", err)
	}

	data, _ := os.ReadFile(cfg.L2TPSecretFile)
	content := string(data)

	if strings.Contains(content, "user-a") {
		t.Error("user-a L2TP entry should be removed")
	}
	if !strings.Contains(content, "user-b") {
		t.Error("user-b L2TP entry should still exist")
	}
}

// --- WritePSK / RemovePSK ---

func TestWritePSK(t *testing.T) {
	cfg, _ := testConfig(t)
	data := TunnelData{
		TunnelID: "tun-abc123",
		PeerIP:   "203.0.113.5",
		PSK:      "abcdef1234567890abcdef1234567890",
	}

	err := WritePSK(cfg, data)
	if err != nil {
		t.Fatalf("WritePSK() error: %v", err)
	}

	fileData, err := os.ReadFile(cfg.SecretFile)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	content := string(fileData)
	if !strings.Contains(content, "# tunnel:tun-abc123") {
		t.Error("secret file missing PSK comment tag for tun-abc123")
	}
	if !strings.Contains(content, "203.0.113.5 : PSK \"abcdef1234567890abcdef1234567890\"") {
		t.Error("secret file missing PSK entry line")
	}
}

func TestRemovePSK(t *testing.T) {
	cfg, _ := testConfig(t)

	// Write two PSK entries
	WritePSK(cfg, TunnelData{TunnelID: "tun-111", PeerIP: "1.2.3.4", PSK: "psk111"})
	WritePSK(cfg, TunnelData{TunnelID: "tun-222", PeerIP: "5.6.7.8", PSK: "psk222"})

	// Remove tun-111
	err := RemovePSK(cfg, "tun-111")
	if err != nil {
		t.Fatalf("RemovePSK() error: %v", err)
	}

	fileData, _ := os.ReadFile(cfg.SecretFile)
	content := string(fileData)

	if strings.Contains(content, "# tunnel:tun-111") {
		t.Error("tun-111 PSK entry should be removed")
	}
	if !strings.Contains(content, "# tunnel:tun-222") {
		t.Error("tun-222 PSK entry should still exist")
	}
}

func TestRemovePSK_NonExistentFile(t *testing.T) {
	cfg, _ := testConfig(t)

	err := RemovePSK(cfg, "tun-nonexistent")
	if err != nil {
		t.Errorf("RemovePSK() on non-existent file should return nil, got: %v", err)
	}
}

// --- WriteTunnelConfig / RemoveTunnelConfig ---

func TestWriteTunnelConfig(t *testing.T) {
	cfg, dir := testConfig(t)
	data := TunnelData{
		TunnelID:    "tun-testconf",
		PeerIP:      "203.0.113.10",
		LocalIP:     "10.10.10.1",
		LocalSubnet: "10.10.10.0/24",
		PSK:         "testpsk123",
	}

	err := WriteTunnelConfig(cfg, data)
	if err != nil {
		t.Fatalf("WriteTunnelConfig() error: %v", err)
	}

	expectedPath := filepath.Join(dir, "conf.d", "tun-testconf.conf")
	if _, statErr := os.Stat(expectedPath); os.IsNotExist(statErr) {
		t.Errorf("config file %s should exist", expectedPath)
	}

	fileData, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}

	content := string(fileData)
	if !strings.Contains(content, "tun-testconf") {
		t.Error("config file should contain tunnel_id")
	}
	if !strings.Contains(content, "203.0.113.10") {
		t.Error("config file should contain peer_ip")
	}
	if !strings.Contains(content, "10.10.10.1") {
		t.Error("config file should contain local_ip")
	}
	if !strings.Contains(content, "10.10.10.0/24") {
		t.Error("config file should contain local_subnet")
	}
}

func TestRemoveTunnelConfig(t *testing.T) {
	cfg, dir := testConfig(t)
	data := TunnelData{
		TunnelID:    "tun-remove",
		PeerIP:      "1.2.3.4",
		LocalIP:     "10.10.10.1",
		LocalSubnet: "10.10.10.0/24",
		PSK:         "removeme",
	}

	WriteTunnelConfig(cfg, data)
	WritePSK(cfg, data)

	// RemoveTunnelConfig also removes the PSK entry
	err := RemoveTunnelConfig(cfg, "tun-remove")
	if err != nil {
		t.Fatalf("RemoveTunnelConfig() error: %v", err)
	}

	confPath := filepath.Join(dir, "conf.d", "tun-remove.conf")
	if _, statErr := os.Stat(confPath); !os.IsNotExist(statErr) {
		t.Error("config file should be deleted")
	}
}

func TestRemoveTunnelConfig_NonExistent(t *testing.T) {
	cfg, _ := testConfig(t)

	err := RemoveTunnelConfig(cfg, "tun-nonexistent")
	if err != nil {
		t.Errorf("RemoveTunnelConfig() on non-existent file should return nil, got: %v", err)
	}
}

// --- Idempotency tests ---

func TestRemoveEAPSecret_Idempotent(t *testing.T) {
	cfg, _ := testConfig(t)
	WriteEAPSecret(cfg, "user1", "pass1")

	// Remove twice — second call should not error
	err := RemoveEAPSecret(cfg, "user1")
	if err != nil {
		t.Fatalf("first RemoveEAPSecret() error: %v", err)
	}
	err = RemoveEAPSecret(cfg, "user1")
	if err != nil {
		t.Errorf("second RemoveEAPSecret() (idempotent) should return nil, got: %v", err)
	}
}

func TestRemoveL2TPSecret_Idempotent(t *testing.T) {
	cfg, _ := testConfig(t)
	WriteL2TPSecret(cfg, "user1", "pass1")

	err := RemoveL2TPSecret(cfg, "user1")
	if err != nil {
		t.Fatalf("first RemoveL2TPSecret() error: %v", err)
	}
	err = RemoveL2TPSecret(cfg, "user1")
	if err != nil {
		t.Errorf("second RemoveL2TPSecret() (idempotent) should return nil, got: %v", err)
	}
}

func TestWriteEAPSecret_AppendMultiple(t *testing.T) {
	cfg, _ := testConfig(t)

	WriteEAPSecret(cfg, "user-a", "pass-a")
	WriteEAPSecret(cfg, "user-b", "pass-b")
	WriteEAPSecret(cfg, "user-c", "pass-c")

	data, _ := os.ReadFile(cfg.SecretFile)
	content := string(data)

	for _, user := range []string{"user-a", "user-b", "user-c"} {
		if !strings.Contains(content, "# tunnel-eap:"+user) {
			t.Errorf("missing EAP entry for %s", user)
		}
	}
}
