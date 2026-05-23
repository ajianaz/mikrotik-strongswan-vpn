// Package template provides template-based rendering of VPN configuration files
// (swanctl.conf, PSK secrets, MikroTik RouterOS scripts) using embedded templates.
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
}

var (
	swanctlTmpl  *template.Template
	pskTmpl      *template.Template
	mikrotikTmpl *template.Template
)

func init() {
	swanctlTmpl = template.Must(template.ParseFS(templatesFS, "templates/swanctl.conf.tmpl"))
	pskTmpl = template.Must(template.ParseFS(templatesFS, "templates/psk.tmpl"))
	mikrotikTmpl = template.Must(template.ParseFS(templatesFS, "templates/mikrotik.rsc.tmpl"))
}

// RenderSwanctlConfig renders the swanctl connection config.
func RenderSwanctlConfig(data TunnelData) (string, error) {
	var buf bytes.Buffer
	if err := swanctlTmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// RenderPSK renders the PSK secret entry.
func RenderPSK(data TunnelData) (string, error) {
	var buf bytes.Buffer
	if err := pskTmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// RenderMikroTikRSC renders the MikroTik RouterOS import script.
func RenderMikroTikRSC(data TunnelData) (string, error) {
	var buf bytes.Buffer
	if err := mikrotikTmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
