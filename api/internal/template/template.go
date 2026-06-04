// Package template provides template-based rendering of VPN configuration files
// (MikroTik RouterOS scripts) using embedded templates.
package template

import (
	"bytes"
	"embed"
	"text/template"
)

//go:embed templates/*
var templatesFS embed.FS

// TunnelData holds data for template rendering.
type TunnelData struct {
	TunnelID    string
	PeerIP      string
	LocalIP     string
	LocalSubnet string
	PSK         string
	AuthType    string
	Username    string
	Password    string
	ServerIP    string // VPN server public IP (used by L2TP template for connect-to)
	L2TPPSK     string // L2TP/IPSec transport mode PSK
}

var (
	eapRscTmpl  *template.Template
	l2tpRscTmpl *template.Template
)

func init() {
	eapRscTmpl = template.Must(template.ParseFS(templatesFS, "templates/mikrotik-eap.rsc.tmpl"))
	l2tpRscTmpl = template.Must(template.ParseFS(templatesFS, "templates/mikrotik-l2tp.rsc.tmpl"))
}

// RenderMikroTikEAPRSC renders the MikroTik RouterOS script for IKEv2 EAP-MSCHAPv2 auth.
func RenderMikroTikEAPRSC(data TunnelData) (string, error) {
	var buf bytes.Buffer
	if err := eapRscTmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// RenderMikroTikL2TPRSC renders the MikroTik RouterOS script for L2TP/IPsec MS-CHAPv2 auth.
func RenderMikroTikL2TPRSC(data TunnelData) (string, error) {
	var buf bytes.Buffer
	if err := l2tpRscTmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
