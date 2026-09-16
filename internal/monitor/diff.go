package monitor

import (
	"fmt"
	"sort"
	"time"

	"github.com/happygream/dragnet/internal/model"
)

// certExpiryWarnDays is the threshold at which a cert crossing into this window
// raises a CertExpiring change.
const certExpiryWarnDays = 21

// Diff compares a previous scan to the current one and returns the list of
// changes between them, timestamped at now. A nil or empty prev means this is
// the first scan: hosts are recorded as appeared so the baseline is captured.
func Diff(prev, cur []model.Host, now time.Time) []Change {
	var changes []Change

	prevByIP := indexByIP(prev)
	curByIP := indexByIP(cur)

	// Hosts appeared or changed.
	for ip, ch := range curByIP {
		ph, existed := prevByIP[ip]
		if !existed {
			changes = append(changes, Change{
				At: now, Kind: HostAppeared, IP: ip,
				Detail: appearedDetail(ch),
			})
			// A brand-new host that is already a decoy is worth its own flag.
			if ch.Honeypot {
				changes = append(changes, Change{
					At: now, Kind: DecoyDetected, IP: ip, Detail: ch.HoneypotReason,
				})
			}
			continue
		}

		// Port changes.
		prevPorts := portSet(ph)
		curPorts := portSet(ch)
		for p := range curPorts {
			if _, had := prevPorts[p]; !had {
				changes = append(changes, Change{
					At: now, Kind: PortOpened, IP: ip,
					Detail: fmt.Sprintf("port %d (%s) opened", p, curPorts[p]),
				})
			}
		}
		for p := range prevPorts {
			if _, still := curPorts[p]; !still {
				changes = append(changes, Change{
					At: now, Kind: PortClosed, IP: ip,
					Detail: fmt.Sprintf("port %d (%s) closed", p, prevPorts[p]),
				})
			}
		}

		// Decoy newly detected on a previously-clean host.
		if ch.Honeypot && !ph.Honeypot {
			changes = append(changes, Change{
				At: now, Kind: DecoyDetected, IP: ip, Detail: ch.HoneypotReason,
			})
		}

		// Device fingerprint changed (e.g. an IP now looks like different kit).
		if ch.Device != "" && ph.Device != "" && ch.Device != ph.Device {
			changes = append(changes, Change{
				At: now, Kind: DeviceChanged, IP: ip,
				Detail: fmt.Sprintf("%s → %s", ph.Device, ch.Device),
			})
		}

		// Cert newly inside the expiry-warning window.
		for _, warn := range newlyExpiringCerts(ph, ch) {
			changes = append(changes, Change{
				At: now, Kind: CertExpiring, IP: ip, Detail: warn,
			})
		}
	}

	// Hosts vanished.
	for ip, ph := range prevByIP {
		if _, still := curByIP[ip]; !still {
			label := ph.Device
			if label == "" {
				label = ph.Hostname
			}
			changes = append(changes, Change{
				At: now, Kind: HostVanished, IP: ip,
				Detail: vanishedDetail(label),
			})
		}
	}

	sort.Slice(changes, func(i, j int) bool {
		if changes[i].IP != changes[j].IP {
			return changes[i].IP < changes[j].IP
		}
		return changes[i].Kind < changes[j].Kind
	})
	return changes
}

func indexByIP(hosts []model.Host) map[string]model.Host {
	m := make(map[string]model.Host, len(hosts))
	for _, h := range hosts {
		m[h.IP] = h
	}
	return m
}

// portSet maps open port number -> service label.
func portSet(h model.Host) map[int]string {
	m := make(map[int]string, len(h.OpenPorts))
	for _, p := range h.OpenPorts {
		m[p.Port] = p.Service
	}
	return m
}

func appearedDetail(h model.Host) string {
	label := h.Device
	if label == "" {
		label = h.Hostname
	}
	if label == "" {
		label = fmt.Sprintf("%d open ports", len(h.OpenPorts))
	}
	return "new host: " + label
}

func vanishedDetail(label string) string {
	if label == "" {
		return "host went dark"
	}
	return "went dark: " + label
}

// newlyExpiringCerts returns warnings for certs that were previously outside
// the warning window (or absent) and are now inside it.
func newlyExpiringCerts(prev, cur model.Host) []string {
	prevDays := map[int]int{}
	for _, t := range prev.TLS {
		prevDays[t.Port] = t.DaysUntilExpiry
	}
	var out []string
	for _, t := range cur.TLS {
		if t.DaysUntilExpiry <= certExpiryWarnDays {
			pd, had := prevDays[t.Port]
			if !had || pd > certExpiryWarnDays {
				out = append(out, fmt.Sprintf("cert on :%d expires in %d days", t.Port, t.DaysUntilExpiry))
			}
		}
	}
	return out
}
