package scan

import (
	"context"
	"time"

	"github.com/happygream/dragnet/internal/discover"
	"github.com/happygream/dragnet/internal/model"
)

// Config controls a full run.
type Config struct {
	Target      string
	Ports       []int
	Mode        model.ScanMode
	Concurrency int
	Timeout     time.Duration
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

		// Deep phase: port + TLS + HTTP per live host.
		for i := range live {
			select {
			case <-ctx.Done():
				return
			default:
			}
			h := &live[i]
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
			hc := *h
			out <- Event{Kind: EvHostDone, Host: &hc, Note: "swept " + h.IP}
		}

		out <- Event{Kind: EvFinished, Note: "done"}
	}()

	return out
}
