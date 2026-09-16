package main

import (
	"fmt"
	"strings"
	"time"
)

// speedPreset bundles the tuning knobs behind a friendly name.
type speedPreset struct {
	Concurrency     int
	HostConcurrency int
	Timeout         time.Duration
}

// resolveSpeed maps a preset name to concrete parameters.
//
//   - fast:     short timeouts, wide concurrency. Quick sweep of a /24; may
//     miss slow-responding hosts or ports.
//   - balanced: sensible default for a home/office LAN.
//   - thorough: longer timeouts, gentler concurrency. Catches sluggish hosts
//     and firewalled devices at the cost of speed.
func resolveSpeed(name string) (speedPreset, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "fast":
		return speedPreset{Concurrency: 768, HostConcurrency: 16, Timeout: 300 * time.Millisecond}, nil
	case "", "balanced":
		return speedPreset{Concurrency: 512, HostConcurrency: 8, Timeout: 600 * time.Millisecond}, nil
	case "thorough":
		return speedPreset{Concurrency: 256, HostConcurrency: 4, Timeout: 1500 * time.Millisecond}, nil
	default:
		return speedPreset{}, fmt.Errorf("unknown speed %q (use fast, balanced, or thorough)", name)
	}
}
