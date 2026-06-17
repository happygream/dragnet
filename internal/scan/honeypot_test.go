package scan

import (
	"testing"

	"github.com/happygream/dragnet/internal/model"
)

func ports(spec ...[2]interface{}) []model.PortState {
	var ps []model.PortState
	for _, s := range spec {
		ps = append(ps, model.PortState{Port: s[0].(int), Open: true, Banner: s[1].(string)})
	}
	return ps
}

func TestHoneypot_RealDecoy(t *testing.T) {
	// 192.168.1.2 from the live scan: 9 ports, classic lures, no banners.
	h := &model.Host{IP: "192.168.1.2", OpenPorts: ports(
		[2]interface{}{21, ""}, [2]interface{}{22, ""}, [2]interface{}{23, ""},
		[2]interface{}{25, ""}, [2]interface{}{80, ""}, [2]interface{}{110, ""},
		[2]interface{}{445, ""}, [2]interface{}{1433, ""}, [2]interface{}{8000, ""},
	)}
	DetectHoneypot(h)
	if !h.Honeypot {
		t.Fatalf("expected honeypot flag, got none")
	}
	t.Logf("flagged: %s", h.HoneypotReason)
}

func TestHoneypot_RealGateway(t *testing.T) {
	// 192.168.1.1 UDM: 6 ports but real services, only one lure (none here).
	h := &model.Host{IP: "192.168.1.1", OpenPorts: ports(
		[2]interface{}{53, ""}, [2]interface{}{80, "HTTP/1.1 301 Moved Permanently"},
		[2]interface{}{443, ""}, [2]interface{}{5060, ""},
		[2]interface{}{8080, "HTTP/1.1 400"}, [2]interface{}{8443, ""},
	)}
	DetectHoneypot(h)
	if h.Honeypot {
		t.Fatalf("gateway wrongly flagged as honeypot: %s", h.HoneypotReason)
	}
}

func TestHoneypot_RealMailServer(t *testing.T) {
	// A genuine busy server: smtp/pop3/imap that DO greet should not flag.
	h := &model.Host{IP: "10.0.0.5", OpenPorts: ports(
		[2]interface{}{21, "220 ftp ready"}, [2]interface{}{22, "SSH-2.0-OpenSSH_9.6"},
		[2]interface{}{25, "220 mail.example.com ESMTP"}, [2]interface{}{110, "+OK POP3 ready"},
		[2]interface{}{143, "* OK IMAP ready"}, [2]interface{}{445, ""},
	)}
	DetectHoneypot(h)
	if h.Honeypot {
		t.Fatalf("real mail server wrongly flagged: %s", h.HoneypotReason)
	}
}
