package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/happygream/dragnet/internal/model"
)

// TLSPorts are the ports we attempt a TLS handshake against by default.
var tlsPorts = map[int]bool{
	443: true, 465: true, 993: true, 995: true, 8443: true, 2376: true,
}

// IsTLSPort reports whether a port is a candidate for TLS inspection.
func IsTLSPort(port int) bool { return tlsPorts[port] }

var tlsVersionNames = map[uint16]string{
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

// InspectTLS performs a handshake and reports certificate + protocol details.
func InspectTLS(ctx context.Context, ip string, port int, timeout time.Duration) (model.TLSInfo, bool) {
	info := model.TLSInfo{Port: port}

	d := net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
	if err != nil {
		return info, false
	}
	defer raw.Close()

	conn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, // we are inspecting, not trusting
		ServerName:         ip,
	})
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := conn.Handshake(); err != nil {
		return info, false
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info.Version = tlsVersionNames[state.Version]
	info.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.Subject = cert.Subject.CommonName
		info.Issuer = cert.Issuer.CommonName
		info.NotBefore = cert.NotBefore
		info.NotAfter = cert.NotAfter
		info.DNSNames = cert.DNSNames
		info.DaysUntilExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
		info.SelfSigned = cert.Subject.CommonName == cert.Issuer.CommonName
	}

	info.Warnings = tlsWarnings(info, state.Version)
	return info, true
}

func tlsWarnings(info model.TLSInfo, version uint16) []string {
	var w []string
	if version == tls.VersionTLS10 || version == tls.VersionTLS11 {
		w = append(w, "outdated TLS version negotiated")
	}
	if info.DaysUntilExpiry < 0 {
		w = append(w, "certificate EXPIRED")
	} else if info.DaysUntilExpiry < 14 {
		w = append(w, fmt.Sprintf("certificate expires in %d days", info.DaysUntilExpiry))
	}
	if info.SelfSigned {
		w = append(w, "self-signed certificate")
	}
	return w
}
