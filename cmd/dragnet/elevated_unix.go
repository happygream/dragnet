//go:build !windows

package main

import "os"

// isElevated reports whether the process is running as root (uid 0).
func isElevated() bool {
	return os.Geteuid() == 0
}
