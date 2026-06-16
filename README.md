# dragnet

`cast the net` — a portable network scanner that runs from a USB stick on
Windows with no install and no admin rights. Single static `.exe`, amber/noir
terminal UI, saves JSON + HTML reports next to the binary.

## What it does

- **Host discovery** — sweeps a CIDR (or a single IP) and surfaces live hosts
  as they answer, with reverse-DNS and round-trip time.
- **Port scan** — concurrent TCP connect scan, curated top ports by default or
  any range you ask for.
- **Service + banner** — labels known ports and grabs greeting banners.
- **TLS inspection** — handshakes TLS ports and reports subject, issuer,
  version, cipher, expiry, self-signed and weak-protocol warnings.
- **HTTP audit** — grades security headers (HSTS, CSP, X-Frame-Options, etc.)
  and gives a 0-100 score per web port.
- **Reports** — every run writes a timestamped `dragnet-*.json` and a
  self-contained, styled `dragnet-*.html` you can open in any browser.

## Usage

```
dragnet -target 192.168.1.0/24
dragnet -target 10.0.0.5 -ports all
dragnet -target 192.168.1.0/24 -ports 1-1024 -out E:\reports
dragnet -target 10.0.0.5 -ports 22,80,443 -no-tui
```

Flags:

| flag | default | meaning |
|------|---------|---------|
| `-target` | (required) | CIDR or IP, e.g. `192.168.1.0/24` |
| `-ports` | `top` | `top`, `all`, a range `1-1024`, or a list `22,80,443` |
| `-concurrency` | `512` | max concurrent probes |
| `-timeout` | `800ms` | per-probe timeout |
| `-out` | `.` | directory for saved reports (point at your USB) |
| `-no-tui` | `false` | plain log instead of the TUI |
| `-version` | | print version and exit |

In the TUI: `q` / `esc` / `ctrl+c` to quit.

## Build

Requires Go 1.23+. From the repo root:

```
# native build for your current OS
go build -o dragnet ./cmd/dragnet

# portable Windows exe (stripped, smaller)
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dragnet.exe ./cmd/dragnet
```

On Windows with the Go toolchain installed, the Makefile equivalent is:

```
go build -ldflags="-s -w" -o dragnet.exe ./cmd/dragnet
```

Drop `dragnet.exe` on the USB stick and run it from there. Point `-out` at the
stick (e.g. `-out E:\`) so reports land on the drive, not the host.

## Privilege model

v1 ships **TCP-connect** mode, which works everywhere with no admin and no
driver. This is the portable default and what you want when plugging into a
machine you do not control.

**SYN mode** is wired through the data model but intentionally not enabled.
A raw SYN scan on Windows needs:

1. **Npcap** installed on the host (admin install — breaks the no-install goal), and
2. the process running **elevated**.

`detectMode()` in `cmd/dragnet/mode.go` already checks for elevation per-OS and
will switch to `ModeSYN` once `hasRawCapture()` returns true. To add it:

- add `github.com/google/gopacket` + a `pcap` build tag,
- implement `hasRawCapture()` in a tagged file that opens an Npcap device,
- implement the SYN sender/receiver in `internal/scan`.

Until then everything runs portably in connect mode, which is the right default
for a USB tool.

## Layout

```
cmd/dragnet/        CLI: flags, privilege detection, report writing
internal/model/     shared data types (Host, PortState, TLSInfo, HTTPInfo, Report)
internal/discover/  CIDR expansion + liveness sweep
internal/scan/      port scan, banner grab, TLS, HTTP audit, orchestrator
internal/tui/       Bubble Tea amber/noir interface
internal/report/    JSON + self-contained HTML writers
```

## Notes

- Connect scans are detectable and will show in target logs. Only scan networks
  you are authorised to test.
- Reports are written world-readable; treat them as sensitive — they map a network.
