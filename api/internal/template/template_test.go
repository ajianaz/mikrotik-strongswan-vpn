package template

import (
	"strings"
	"testing"
)
func testTunnelData() TunnelData {
	return TunnelData{
		TunnelID:    "tun-abc12345",
		PeerIP:      "203.0.113.5",
		LocalIP:     "10.10.10.1",
		LocalSubnet: "10.10.10.0/24",
		PSK:         "abcdef1234567890abcdef1234567890",
		AuthType:    "psk",
		Username:    "test-user",
		Password:    "test-password-123",
	}
}

func TestRenderMikroTikRSC(t *testing.T) {
	data := testTunnelData()
	data.AuthType = "psk"

	out, err := RenderMikroTikRSC(data)
	if err != nil {
		t.Fatalf("RenderMikroTikRSC() error: %v", err)
	}
	if out == "" {
		t.Fatal("RenderMikroTikRSC() returned empty string")
	}
	if !strings.Contains(out, data.TunnelID) {
		t.Errorf("output missing tunnel_id %q", data.TunnelID)
	}
	if !strings.Contains(out, data.PeerIP) {
		t.Errorf("output missing peer_ip %q", data.PeerIP)
	}
	if !strings.Contains(out, data.LocalSubnet) {
		t.Errorf("output missing local_subnet %q", data.LocalSubnet)
	}
	if !strings.Contains(out, data.PSK) {
		t.Errorf("output missing psk %q", data.PSK)
	}
}

func TestRenderMikroTikEAPRSC(t *testing.T) {
	data := testTunnelData()
	data.AuthType = "eap"

	out, err := RenderMikroTikEAPRSC(data)
	if err != nil {
		t.Fatalf("RenderMikroTikEAPRSC() error: %v", err)
	}
	if out == "" {
		t.Fatal("RenderMikroTikEAPRSC() returned empty string")
	}
	if !strings.Contains(out, data.Username) {
		t.Errorf("output missing username %q", data.Username)
	}
	if !strings.Contains(out, data.Password) {
		t.Errorf("output missing password %q", data.Password)
	}
}

func TestRenderMikroTikL2TPRSC(t *testing.T) {
	data := testTunnelData()
	data.AuthType = "l2tp"

	out, err := RenderMikroTikL2TPRSC(data)
	if err != nil {
		t.Fatalf("RenderMikroTikL2TPRSC() error: %v", err)
	}
	if out == "" {
		t.Fatal("RenderMikroTikL2TPRSC() returned empty string")
	}
	if !strings.Contains(out, data.Username) {
		t.Errorf("output missing username %q", data.Username)
	}
	if !strings.Contains(out, data.Password) {
		t.Errorf("output missing password %q", data.Password)
	}
}
