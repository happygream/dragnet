package scan

import (
	"strings"

	"github.com/happygream/dragnet/internal/model"
)

// Fingerprint synthesizes a best-guess device/OS label from signals already
// gathered during the scan: SSH banners, TLS certificate subjects/issuers,
// HTTP Server headers, vendor (from MAC), and port composition. It writes the
// guess into h.Device. This is heuristic and clearly labelled as a guess.
func Fingerprint(h *model.Host) {
	var clues []string

	if h.Vendor != "" {
		clues = append(clues, h.Vendor)
	}

	for _, p := range h.OpenPorts {
		b := strings.ToLower(p.Banner)
		switch {
		case strings.Contains(b, "ubuntu"):
			clues = appendUnique(clues, "Ubuntu Linux")
		case strings.Contains(b, "debian"):
			clues = appendUnique(clues, "Debian Linux")
		case strings.Contains(b, "raspbian"):
			clues = appendUnique(clues, "Raspberry Pi OS")
		case strings.Contains(b, "dropbear"):
			clues = appendUnique(clues, "embedded device (Dropbear)")
		case strings.Contains(b, "freebsd"):
			clues = appendUnique(clues, "FreeBSD")
		case strings.Contains(b, "mikrotik") || strings.Contains(b, "routeros"):
			clues = appendUnique(clues, "MikroTik router")
		}
	}

	for _, t := range h.TLS {
		s := strings.ToLower(t.Subject + " " + t.Issuer)
		switch {
		case strings.Contains(s, "synology"):
			clues = appendUnique(clues, "Synology NAS")
		case strings.Contains(s, "idrac"):
			clues = appendUnique(clues, "Dell iDRAC")
		case strings.Contains(s, "unifi") || strings.Contains(s, "udm"):
			clues = appendUnique(clues, "UniFi / UDM")
		case strings.Contains(s, "qnap"):
			clues = appendUnique(clues, "QNAP NAS")
		case strings.Contains(s, "truenas") || strings.Contains(s, "freenas"):
			clues = appendUnique(clues, "TrueNAS")
		case strings.Contains(s, "proxmox"):
			clues = appendUnique(clues, "Proxmox")
		}
	}

	for _, ht := range h.HTTP {
		srv := strings.ToLower(ht.Server)
		switch {
		case strings.Contains(srv, "uvicorn") || strings.Contains(srv, "gunicorn"):
			clues = appendUnique(clues, "Python web service")
		case strings.Contains(srv, "synology"):
			clues = appendUnique(clues, "Synology NAS")
		case strings.Contains(srv, "lighttpd"):
			clues = appendUnique(clues, "embedded/appliance web UI")
		case strings.Contains(srv, "iis") || strings.Contains(srv, "microsoft"):
			clues = appendUnique(clues, "Windows / IIS")
		}
	}

	if len(clues) == 0 {
		if hasPorts(h, 135, 139, 445) {
			clues = append(clues, "Windows host")
		} else if hasPorts(h, 139, 445) {
			clues = append(clues, "SMB file server")
		} else if hasPort(h, 53) && hasPort(h, 22) {
			clues = append(clues, "Linux server (DNS)")
		}
	}

	h.Device = strings.Join(dedupe(clues), ", ")
}

func appendUnique(s []string, v string) []string {
	for _, e := range s {
		if e == v {
			return s
		}
	}
	return append(s, v)
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range s {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}

func hasPort(h *model.Host, port int) bool {
	for _, p := range h.OpenPorts {
		if p.Port == port {
			return true
		}
	}
	return false
}

func hasPorts(h *model.Host, ports ...int) bool {
	for _, p := range ports {
		if !hasPort(h, p) {
			return false
		}
	}
	return true
}
