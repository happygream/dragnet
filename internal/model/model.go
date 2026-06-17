package model

import "time"

// ScanMode reflects the privilege level / technique in use.
type ScanMode string

const (
	ModeConnect ScanMode = "tcp-connect" // no-admin, net.Dialer
	ModeSYN     ScanMode = "syn"         // admin + Npcap, raw packets
)

// PortState is the result for a single probed port.
type PortState struct {
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

// TLSInfo captures certificate and protocol findings for a TLS port.
type TLSInfo struct {
	Port            int       `json:"port"`
	Subject         string    `json:"subject,omitempty"`
	Issuer          string    `json:"issuer,omitempty"`
	NotBefore       time.Time `json:"not_before,omitempty"`
	NotAfter        time.Time `json:"not_after,omitempty"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
	Version         string    `json:"version,omitempty"`
	CipherSuite     string    `json:"cipher_suite,omitempty"`
	DNSNames        []string  `json:"dns_names,omitempty"`
	SelfSigned      bool      `json:"self_signed"`
	Warnings        []string  `json:"warnings,omitempty"`
}

// HTTPInfo captures the security-header audit for a web port.
type HTTPInfo struct {
	Port           int               `json:"port"`
	StatusCode     int               `json:"status_code"`
	Server         string            `json:"server,omitempty"`
	Title          string            `json:"title,omitempty"`
	SecurityScore  int               `json:"security_score"` // 0-100
	PresentHeaders map[string]string `json:"present_headers,omitempty"`
	MissingHeaders []string          `json:"missing_headers,omitempty"`
}

// Host is the full picture for a single discovered IP.
type Host struct {
	IP        string      `json:"ip"`
	Hostname  string      `json:"hostname,omitempty"`
	MAC       string      `json:"mac,omitempty"`
	Vendor    string      `json:"vendor,omitempty"`
	Alive     bool        `json:"alive"`
	RTT       string      `json:"rtt,omitempty"`
	OpenPorts []PortState `json:"open_ports,omitempty"`
	TLS       []TLSInfo   `json:"tls,omitempty"`
	HTTP      []HTTPInfo  `json:"http,omitempty"`

	// Honeypot is set when the host's response pattern suggests a decoy
	// (many classic-service ports open, but services that normally greet
	// stay silent). HoneypotReason explains the call.
	Honeypot       bool   `json:"honeypot,omitempty"`
	HoneypotReason string `json:"honeypot_reason,omitempty"`
}

// Report is the top-level saved artifact.
type Report struct {
	Tool      string    `json:"tool"`
	Version   string    `json:"version"`
	Target    string    `json:"target"`
	Mode      ScanMode  `json:"mode"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Duration  string    `json:"duration"`
	HostsUp   int       `json:"hosts_up"`
	Hosts     []Host    `json:"hosts"`
}
