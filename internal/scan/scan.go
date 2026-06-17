package scan

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/happygream/dragnet/internal/model"
)

// services maps well-known ports to a service label.
var services = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
	139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
	443: "https", 445: "smb", 465: "smtps", 587: "submission",
	993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
	2049: "nfs", 2375: "docker", 2376: "docker-tls", 3000: "http-alt",
	3306: "mysql", 3389: "rdp", 5060: "sip", 5432: "postgres",
	5900: "vnc", 5985: "winrm", 6379: "redis", 8000: "http-alt",
	8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
	8888: "http-alt", 9000: "http-alt", 9200: "elasticsearch",
	11211: "memcached", 27017: "mongodb",
}

// TopPorts is a sensible default set for a fast-but-useful scan.
var TopPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443,
	445, 465, 587, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389,
	5060, 5432, 5900, 5985, 6379, 8000, 8080, 8081, 8443, 8888, 9000,
	9200, 11211, 27017,
}

// PortsFromRange returns every port in [lo, hi].
func PortsFromRange(lo, hi int) []int {
	if lo < 1 {
		lo = 1
	}
	if hi > 65535 {
		hi = 65535
	}
	var p []int
	for i := lo; i <= hi; i++ {
		p = append(p, i)
	}
	return p
}

// ServiceName returns the label for a port, or "unknown".
func ServiceName(port int) string {
	if s, ok := services[port]; ok {
		return s
	}
	return "unknown"
}

// ScanHost runs a concurrent TCP connect scan across ports for one IP.
// Open ports come back sorted, with a best-effort banner where one is offered.
func ScanHost(ctx context.Context, ip string, ports []int, concurrency int, timeout time.Duration) []model.PortState {
	if concurrency <= 0 {
		concurrency = 512
	}
	jobs := make(chan int)
	results := make(chan model.PortState)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if ps, open := probe(ctx, ip, port, timeout); open {
					results <- ps
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, p := range ports {
			select {
			case jobs <- p:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var open []model.PortState
	for ps := range results {
		open = append(open, ps)
	}
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
}

func probe(ctx context.Context, ip string, port int, timeout time.Duration) (model.PortState, bool) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
	if err != nil {
		return model.PortState{}, false
	}
	defer conn.Close()

	ps := model.PortState{Port: port, Open: true, Service: ServiceName(port)}
	ps.Banner = grabBanner(conn, port)
	return ps, true
}

// grabBanner reads any greeting the service volunteers. For silent protocols
// (HTTP) we send a minimal nudge first. Best-effort only; never blocks long.
func grabBanner(conn net.Conn, port int) string {
	_ = conn.SetDeadline(time.Now().Add(600 * time.Millisecond))

	switch port {
	case 80, 8080, 8000, 8081, 3000, 9000, 8888:
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	}

	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	line = strings.TrimSpace(line)
	if len(line) > 120 {
		line = line[:120] + "..."
	}
	return line
}
