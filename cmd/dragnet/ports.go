package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/happygream/dragnet/internal/scan"
)

// parsePorts turns the -ports flag into a concrete list.
//   - "top"     -> curated common ports
//   - "all"     -> 1-65535
//   - "1-1024"  -> inclusive range
//   - "22,80,443" -> explicit list
func parsePorts(arg string) ([]int, error) {
	arg = strings.TrimSpace(strings.ToLower(arg))
	switch arg {
	case "", "top":
		return scan.TopPorts, nil
	case "all":
		return scan.PortsFromRange(1, 65535), nil
	}

	if strings.Contains(arg, "-") && !strings.Contains(arg, ",") {
		parts := strings.SplitN(arg, "-", 2)
		lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err1 != nil || err2 != nil || lo > hi {
			return nil, fmt.Errorf("bad port range %q", arg)
		}
		return scan.PortsFromRange(lo, hi), nil
	}

	var ports []int
	for _, tok := range strings.Split(arg, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		p, err := strconv.Atoi(tok)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("bad port %q", tok)
		}
		ports = append(ports, p)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no valid ports in %q", arg)
	}
	return ports, nil
}
