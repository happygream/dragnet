package scan

import (
	"context"
	"sync"
	"time"

	"github.com/happygream/dragnet/internal/discover"
	"github.com/happygream/dragnet/internal/model"
)

// Config controls a full run.
type Config struct {
	Target          string
	Ports           []int
	Mode            model.ScanMode
	Concurrency     int // per-host concurrent port probes
	HostConcurrency int // number of hosts scanned in parallel
	Timeout         time.Duration
}

// Event is streamed to the UI during a run.
type Event struct {
	Kind  EventKind
	Total int          // for ExpandDone: number of addresses to sweep
	Host  *model.Host  // for HostUp / HostDone
	Err   error        // for Error
	Note  string       // human-readable status line
}

type EventKind int

const (
	EvExpandDone EventKind = iota
	EvHostUp
	EvHostDone
	EvError
	EvFinished
)

// Run executes the full pipeline and streams events. It closes the channel
// when finished. Cancel via ctx.
func Run(ctx context.Context, cfg Config) <-chan Event {
	out := make(chan Event, 64)

	go func() {
		defer close(out)

		ips, err := discover.ExpandCIDR(cfg.Target)
		if err != nil {
			out <- Event{Kind: EvError, Err: err}
			return
		}
		out <- Event{Kind: EvExpandDone, Total: len(ips), Note: "sweeping " + cfg.Target}

		// For a single-host target, fold the requested scan ports into the
		// liveness probe so a host listening only on an unusual port is still
		// detected rather than reported dead.
		pingPorts := cfg.Ports
		if len(ips) != 1 {
			pingPorts = nil // use discover's built-in common set for sweeps
		}

		// Discovery phase: stream live hosts as they surface.
		var live []model.Host
		for res := range discover.Sweep(ctx, ips, cfg.Concurrency, cfg.Timeout, pingPorts) {
			h := res.Host
			live = append(live, h)
			hc := h
			out <- Event{Kind: EvHostUp, Host: &hc, Note: "caught " + h.IP}
		}

		// Deep phase: port + TLS + HTTP per live host, several hosts at once.
		hostConc := cfg.HostConcurrency
		if hostConc <= 0 {
			hostConc = 8
		}
		if hostConc > len(live) {
			hostConc = len(live)
		}

		jobs := make(chan int)
		var wg sync.WaitGroup
		for w := 0; w < hostConc; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					select {
					case <-ctx.Done():
						return
					default:
					}
					h := &live[i]
					deepScan(ctx, h, cfg)
					hc := *h
					out <- Event{Kind: EvHostDone, Host: &hc, Note: "swept " + h.IP}
				}
			}()
		}
		go func() {
			defer close(jobs)
			for i := range live {
				select {
				case jobs <- i:
				case <-ctx.Done():
					return
				}
			}
		}()
		wg.Wait()

		out <- Event{Kind: EvFinished, Note: "done"}
	}()

	return out
}

// deepScan runs MAC resolution, port scan, per-port TLS/HTTP inspection,
// honeypot detection and device fingerprinting for a single host, filling
// the host in place.
func deepScan(ctx context.Context, h *model.Host, cfg Config) {
	// MAC/vendor is only meaningful for on-link hosts; the ARP entry exists
	// because discovery already connected to this IP.
	h.MAC, h.Vendor = ResolveMAC(h.IP)

	h.OpenPorts = ScanHost(ctx, h.IP, cfg.Ports, cfg.Concurrency, cfg.Timeout)

	for _, p := range h.OpenPorts {
		if IsTLSPort(p.Port) {
			if t, ok := InspectTLS(ctx, h.IP, p.Port, cfg.Timeout); ok {
				h.TLS = append(h.TLS, t)
			}
		}
		if IsHTTPPort(p.Port) {
			if ht, ok := AuditHTTP(ctx, h.IP, p.Port, cfg.Timeout); ok {
				h.HTTP = append(h.HTTP, ht)
			}
		}
	}
	DetectHoneypot(h)
	Fingerprint(h)
}
