package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/happygream/dragnet/internal/dashboard"
	"github.com/happygream/dragnet/internal/monitor"
	"github.com/happygream/dragnet/internal/scan"
)

// runMonitor implements "dragnet monitor": scan on a loop, diff, persist to
// SQLite, and serve a live localhost dashboard.
func runMonitor(args []string) {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	var (
		target   = fs.String("target", "", "CIDR or IP to watch, e.g. 192.168.1.0/24")
		portsArg = fs.String("ports", "top", `"top", "all", or range "1-1024"`)
		speed    = fs.String("speed", "balanced", `preset: "fast", "balanced", or "thorough"`)
		interval = fs.Duration("interval", 10*time.Minute, "time between scans")
		listen   = fs.String("listen", "127.0.0.1:8787", "dashboard bind address (use 0.0.0.0:PORT to expose)")
		dbPath   = fs.String("db", "dragnet-monitor.db", "SQLite database path")
		conc     = fs.Int("concurrency", 0, "max concurrent probes per host (0 = use preset)")
		hostConc = fs.Int("host-concurrency", 0, "hosts scanned in parallel (0 = use preset)")
		timeout  = fs.Duration("timeout", 0, "per-probe timeout (0 = use preset)")
	)
	_ = fs.Parse(args)

	if *target == "" {
		fmt.Fprintln(os.Stderr, "dragnet monitor: -target is required (e.g. -target 192.168.1.0/24)")
		fs.Usage()
		os.Exit(2)
	}

	ports, err := parsePorts(*portsArg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dragnet monitor:", err)
		os.Exit(2)
	}

	preset, err := resolveSpeed(*speed)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dragnet monitor:", err)
		os.Exit(2)
	}
	if *conc > 0 {
		preset.Concurrency = *conc
	}
	if *hostConc > 0 {
		preset.HostConcurrency = *hostConc
	}
	if *timeout > 0 {
		preset.Timeout = *timeout
	}

	cfg := scan.Config{
		Target:          *target,
		Ports:           ports,
		Mode:            detectMode(),
		Concurrency:     preset.Concurrency,
		HostConcurrency: preset.HostConcurrency,
		Timeout:         preset.Timeout,
	}

	store, err := monitor.OpenStore(*dbPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dragnet monitor: cannot open database:", err)
		os.Exit(1)
	}
	defer store.Close()

	mon := monitor.New(cfg, *interval, store)
	mon.OnChanges = func(changes []monitor.Change) {
		for _, c := range changes {
			fmt.Printf("[change] %s  %s  %s\n", c.Kind, c.IP, c.Detail)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dash := dashboard.New(mon, store, *listen)

	fmt.Printf("dragnet monitor  •  target %s  •  every %s\n", *target, interval.String())
	fmt.Printf("dashboard:  http://%s\n", *listen)
	fmt.Printf("database:   %s\n", *dbPath)
	fmt.Println("press ctrl+c to stop")

	// Run the monitor loop and the dashboard concurrently; stop on ctx.
	go mon.Run(ctx)

	if err := dash.ListenAndServe(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "dragnet monitor: dashboard error:", err)
		os.Exit(1)
	}
	fmt.Println("\nstopped.")
}
