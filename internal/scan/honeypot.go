package scan

import (
	"fmt"

	"github.com/happygream/dragnet/internal/model"
)

// lurePorts are classic, attractive service ports a honeypot commonly exposes
// to bait scanners. Real hosts rarely run all of these at once.
var lurePorts = map[int]bool{
	21:   true, // ftp
	23:   true, // telnet
	25:   true, // smtp
	110:  true, // pop3
	143:  true, // imap
	445:  true, // smb
	1433: true, // mssql
	3306: true, // mysql
	3389: true, // rdp
	5900: true, // vnc
}

// bannerExpected are services that almost always send an unprompted greeting
// on connect. Silence on these while the port is open is the key tell: a real
// daemon announces itself, a decoy listener usually does not.
var bannerExpected = map[int]bool{
	21:  true, // ftp  -> "220 ..."
	22:  true, // ssh  -> "SSH-2.0-..."
	25:  true, // smtp -> "220 ..."
	110: true, // pop3 -> "+OK ..."
	143: true, // imap -> "* OK ..."
}

// DetectHoneypot inspects a host's open-port and banner pattern and decides
// whether it looks like a decoy. It is deliberately conservative: the goal is
// to flag the obvious "one of everything, all silent" case without libelling
// a genuinely busy server.
//
// Thresholds, tunable:
//   - at least minLureHits classic lure ports open, and
//   - at least minOpenForCheck open ports total, and
//   - the share of banner-expected ports that stayed silent is high.
func DetectHoneypot(h *model.Host) {
	const (
		minOpenForCheck = 6
		minLureHits     = 4
	)

	if len(h.OpenPorts) < minOpenForCheck {
		return
	}

	lureHits := 0
	bannerExpectedOpen := 0
	bannerSilent := 0
	for _, p := range h.OpenPorts {
		if lurePorts[p.Port] {
			lureHits++
		}
		if bannerExpected[p.Port] {
			bannerExpectedOpen++
			if p.Banner == "" {
				bannerSilent++
			}
		}
	}

	if lureHits < minLureHits {
		return
	}

	// If services that should greet are open but overwhelmingly silent, that
	// is the decoy signature. Require at least 3 silent greeters, or all of
	// them when there are few.
	silentEnough := bannerSilent >= 3 ||
		(bannerExpectedOpen > 0 && bannerSilent == bannerExpectedOpen)

	if !silentEnough {
		return
	}

	h.Honeypot = true
	h.HoneypotReason = fmt.Sprintf(
		"%d classic lure ports open, %d of %d banner-expected services silent",
		lureHits, bannerSilent, bannerExpectedOpen,
	)
}
