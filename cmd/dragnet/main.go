package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/happygream/dragnet/internal/model"
	"github.com/happygream/dragnet/internal/report"
	"github.com/happygream/dragnet/internal/scan"
	"github.com/happygream/dragnet/internal/tui"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		target   = flag.String("target", "", "CIDR or IP to scan, e.g. 192.168.1.0/24")
		portsArg = flag.String("ports", "top", `"top", "all", or range "1-1024"`)
		conc     = flag.Int("concurrency", 512, "max concurrent probes")
		timeout  = flag.Duration("timeout", 800*time.Millisecond, "per-probe timeout")
		outDir   = flag.String("out", ".", "directory for saved reports")
		noTUI    = flag.Bool("no-tui", false, "plain output instead of the TUI")
		keepOpen = flag.Bool("keep-open", false, "keep the TUI open after the scan finishes (default: exit automatically)")
		showVer  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("dragnet", version)
		return
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "dragnet: -target is required (e.g. -target 192.168.1.0/24)")
		flag.Usage()
		os.Exit(2)
	}

	ports, err := parsePorts(*portsArg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dragnet:", err)
		os.Exit(2)
	}

	mode := detectMode()

	cfg := scan.Config{
		Target:      *target,
		Ports:       ports,
		Mode:        mode,
		Concurrency: *conc,
		Timeout:     *timeout,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var hosts []model.Host
	started := time.Now()

	if *noTUI {
		hosts, started = runPlain(ctx, cfg)
	} else {
		m := tui.New(ctx, cfg, !*keepOpen)
		p := tea.NewProgram(m, tea.WithAltScreen())
		final, err := p.Run()
		if err != nil {
			fmt.Fprintln(os.Stderr, "dragnet:", err)
			os.Exit(1)
		}
		hosts, started = final.(tui.Model).Result()
	}

	rep := model.Report{
		Tool:      "dragnet",
		Version:   version,
		Target:    cfg.Target,
		Mode:      cfg.Mode,
		StartedAt: started,
		EndedAt:   time.Now(),
		Duration:  time.Since(started).Round(time.Millisecond).String(),
		Hosts:     hosts,
	}
	for _, h := range hosts {
		if h.Alive {
			rep.HostsUp++
		}
	}

	jsonPath, jErr := report.WriteJSON(*outDir, rep)
	htmlPath, hErr := report.WriteHTML(*outDir, rep)
	if jErr != nil || hErr != nil {
		fmt.Fprintln(os.Stderr, "dragnet: report write error:", jErr, hErr)
	}
	abs, _ := filepath.Abs(htmlPath)
	fmt.Printf("\nReports saved:\n  %s\n  %s\n", jsonPath, abs)
}

// runPlain executes without the TUI and prints a terse running log.
func runPlain(ctx context.Context, cfg scan.Config) ([]model.Host, time.Time) {
	started := time.Now()
	byIP := map[string]*model.Host{}
	var order []string

	for ev := range scan.Run(ctx, cfg) {
		switch ev.Kind {
		case scan.EvExpandDone:
			fmt.Printf("[*] %s (%d addresses)\n", ev.Note, ev.Total)
		case scan.EvHostUp:
			if ev.Host != nil {
				if _, ok := byIP[ev.Host.IP]; !ok {
					order = append(order, ev.Host.IP)
				}
				h := *ev.Host
				byIP[ev.Host.IP] = &h
				fmt.Printf("[+] up   %s %s\n", ev.Host.IP, ev.Host.Hostname)
			}
		case scan.EvHostDone:
			if ev.Host != nil {
				h := *ev.Host
				byIP[ev.Host.IP] = &h
				fmt.Printf("[=] done %s (%d open)\n", ev.Host.IP, len(ev.Host.OpenPorts))
			}
		case scan.EvError:
			fmt.Printf("[!] %v\n", ev.Err)
		case scan.EvFinished:
			fmt.Println("[*] finished")
		}
	}

	var hosts []model.Host
	for _, ip := range order {
		hosts = append(hosts, *byIP[ip])
	}
	return hosts, started
}
