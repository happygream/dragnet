package scan

import (
	"strings"
	"testing"

	"github.com/happygream/dragnet/internal/model"
)

func TestFingerprint_Synology(t *testing.T) {
	h := &model.Host{IP: "192.168.1.6",
		OpenPorts: []model.PortState{{Port: 22, Banner: "SSH-2.0-OpenSSH_8.2"}, {Port: 443}},
		TLS:       []model.TLSInfo{{Subject: "synology", Issuer: "Synology Inc. CA"}}}
	Fingerprint(h)
	if !strings.Contains(h.Device, "Synology") {
		t.Fatalf("want Synology, got %q", h.Device)
	}
}

func TestFingerprint_iDRAC(t *testing.T) {
	h := &model.Host{IP: "192.168.1.64",
		OpenPorts: []model.PortState{{Port: 22, Banner: "SSH-2.0-OpenSSH_7.4"}, {Port: 5900}},
		TLS:       []model.TLSInfo{{Subject: "idrac-F8WRSM2", Issuer: "idrac-F8WRSM2"}}}
	Fingerprint(h)
	if !strings.Contains(h.Device, "iDRAC") {
		t.Fatalf("want iDRAC, got %q", h.Device)
	}
}

func TestFingerprint_UvicornUbuntu(t *testing.T) {
	h := &model.Host{IP: "192.168.1.98",
		OpenPorts: []model.PortState{{Port: 22, Banner: "SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.2"}, {Port: 8080}},
		HTTP:      []model.HTTPInfo{{Port: 8080, Server: "uvicorn"}}}
	Fingerprint(h)
	if !strings.Contains(h.Device, "Ubuntu") || !strings.Contains(h.Device, "Python") {
		t.Fatalf("want Ubuntu + Python, got %q", h.Device)
	}
}

func TestFingerprint_WindowsBox(t *testing.T) {
	h := &model.Host{IP: "192.168.1.140",
		OpenPorts: []model.PortState{{Port: 135}, {Port: 139}, {Port: 445}}}
	Fingerprint(h)
	if !strings.Contains(h.Device, "Windows") {
		t.Fatalf("want Windows, got %q", h.Device)
	}
}
