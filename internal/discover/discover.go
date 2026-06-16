package discover

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/happygream/dragnet/internal/model"
)

// commonPingPorts are TCP ports we knock on to decide a host is alive when
// running without raw-socket/ICMP privileges. Most live hosts answer on at
// least one of these.
var commonPingPorts = []int{443, 80, 22, 445, 3389, 139, 135, 8080}

// ExpandCIDR returns every usable host address in a CIDR block.
// For a single IP (no slash) it returns just that address.
func ExpandCIDR(target string) ([]string, error) {
	if _, _, err := net.ParseCIDR(target); err != nil {
		// Maybe a bare IP.
		if ip := net.ParseIP(target); ip != nil {
			return []string{ip.String()}, nil
		}
		return nil, fmt.Errorf("invalid target %q: not a CIDR or IP", target)
	}

	ip, ipnet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, err
	}

	var ips []string
	for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); inc(cur) {
		ips = append(ips, cur.String())
	}

	// Drop network and broadcast addresses for IPv4 /n where it makes sense.
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Result is emitted per-host as discovery completes.
type Result struct {
	Host model.Host
}

// Sweep probes liveness across all addresses using a bounded worker pool.
// Found-alive hosts are streamed on the returned channel as they resolve.
// extraPorts, when non-nil, are probed in addition to (actually instead of)
// the common set — used for single-host targets so unusual listeners are seen.
func Sweep(ctx context.Context, ips []string, concurrency int, perHostTimeout time.Duration, extraPorts []int) <-chan Result {
	probePorts := commonPingPorts
	if len(extraPorts) > 0 {
		probePorts = extraPorts
	}
	out := make(chan Result)
	jobs := make(chan string)

	if concurrency <= 0 {
		concurrency = 256
	}

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}
				if h, ok := ping(ctx, ip, perHostTimeout, probePorts); ok {
					select {
					case out <- Result{Host: h}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ip := range ips {
			select {
			case jobs <- ip:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// ping attempts a quick TCP connect against common ports. The first successful
// connection marks the host alive and records the round-trip time.
func ping(ctx context.Context, ip string, timeout time.Duration, ports []int) (model.Host, bool) {
	h := model.Host{IP: ip}
	if len(ports) == 0 {
		ports = commonPingPorts
	}
	per := timeout / time.Duration(len(ports))
	if per < 80*time.Millisecond {
		per = 80 * time.Millisecond
	}

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return h, false
		default:
		}
		start := time.Now()
		d := net.Dialer{Timeout: per}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
		if err == nil {
			_ = conn.Close()
			h.Alive = true
			h.RTT = time.Since(start).Round(time.Millisecond).String()
			h.Hostname = lookupPTR(ip)
			return h, true
		}
	}
	return h, false
}

func lookupPTR(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	// Trim trailing dot.
	n := names[0]
	if len(n) > 0 && n[len(n)-1] == '.' {
		n = n[:len(n)-1]
	}
	return n
}
