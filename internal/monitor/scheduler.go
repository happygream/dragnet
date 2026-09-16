package monitor

import (
	"context"
	"sync"
	"time"

	"github.com/happygream/dragnet/internal/model"
	"github.com/happygream/dragnet/internal/scan"
)

// Monitor runs scans on a loop, diffs each against the last, and persists both
// the snapshot and the detected changes. It also holds the latest state for
// the dashboard to read.
type Monitor struct {
	cfg      scan.Config
	interval time.Duration
	store    *Store

	mu       sync.RWMutex
	current  []model.Host
	lastScan time.Time
	scanning bool
	runs     int

	// OnChanges, if set, is called with each batch of changes right after they
	// are recorded (used for logging / future alerting).
	OnChanges func([]Change)
}

// New builds a Monitor.
func New(cfg scan.Config, interval time.Duration, store *Store) *Monitor {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	return &Monitor{cfg: cfg, interval: interval, store: store}
}

// Snapshot returns the latest host list and metadata for the dashboard.
func (m *Monitor) Snapshot() (hosts []model.Host, lastScan time.Time, scanning bool, runs int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current, m.lastScan, m.scanning, m.runs
}

// Interval reports the configured scan interval.
func (m *Monitor) Interval() time.Duration { return m.interval }

// Target reports the scan target.
func (m *Monitor) Target() string { return m.cfg.Target }

// Run scans immediately, then every interval, until ctx is cancelled.
// If a scan is still running when the next tick fires, that tick is skipped
// rather than piling a second scan on top of the first.
func (m *Monitor) Run(ctx context.Context) {
	m.scanOnce(ctx)

	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.mu.RLock()
			busy := m.scanning
			m.mu.RUnlock()
			if busy {
				continue // previous scan still running; skip this tick
			}
			m.scanOnce(ctx)
		}
	}
}

func (m *Monitor) scanOnce(ctx context.Context) {
	m.mu.Lock()
	m.scanning = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.scanning = false
		m.mu.Unlock()
	}()

	// Bound the whole scan so a slow/unreachable target can never wedge the
	// loop. Cap at the interval (a scan shouldn't outlast its own cadence),
	// with a sane floor and ceiling.
	budget := m.interval
	if budget < 30*time.Second {
		budget = 30 * time.Second
	}
	if budget > 5*time.Minute {
		budget = 5 * time.Minute
	}
	scanCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	started := time.Now()
	hosts := collect(scanCtx, m.cfg)
	ended := time.Now()

	// Diff against the previous persisted snapshot.
	prev, _ := m.store.LastSnapshot()
	changes := Diff(prev, hosts, ended)

	_, _ = m.store.SaveScan(m.cfg.Target, started, ended, hosts)
	_ = m.store.RecordChanges(changes)

	m.mu.Lock()
	m.current = hosts
	m.lastScan = ended
	m.runs++
	m.mu.Unlock()

	if m.OnChanges != nil && len(changes) > 0 {
		m.OnChanges(changes)
	}
}

// collect drains scan.Run to completion and returns the final host list,
// ordered by IP.
func collect(ctx context.Context, cfg scan.Config) []model.Host {
	byIP := map[string]*model.Host{}
	var order []string
	for ev := range scan.Run(ctx, cfg) {
		switch ev.Kind {
		case scan.EvHostUp:
			if ev.Host != nil {
				if _, ok := byIP[ev.Host.IP]; !ok {
					order = append(order, ev.Host.IP)
				}
				h := *ev.Host
				byIP[ev.Host.IP] = &h
			}
		case scan.EvHostDone:
			if ev.Host != nil {
				h := *ev.Host
				byIP[ev.Host.IP] = &h
			}
		}
	}
	hosts := make([]model.Host, 0, len(order))
	for _, ip := range order {
		hosts = append(hosts, *byIP[ip])
	}
	return hosts
}
