# Changelog

All notable changes to dragnet are documented here.

## [0.4.0] — 2026-09-16

- Monitor mode: `dragnet monitor -target ... -interval 10m`. Runs scans on a
  loop, diffs each against the last, and serves a live localhost web dashboard
  (amber/noir) showing current hosts and a change timeline.
- Change detection: host appeared / went dark, port opened / closed, TLS cert
  crossing into the expiry-warning window, honeypot newly detected, device
  fingerprint changed.
- SQLite persistence (pure-Go `modernc.org/sqlite`, no CGO): scan snapshots and
  change events survive restarts. `-db` sets the path.
- Dashboard binds to `127.0.0.1:8787` by default; `-listen 0.0.0.0:PORT` to
  reach it from another machine.
- Robustness: each scan is bounded by a time budget, a tick is skipped if the
  previous scan is still running, and the ARP table is read once per scan
  (bounded) rather than shelling out per host.

## [0.3.0] — 2026-06-17

- Concurrent host scanning. The deep phase (ports, TLS, HTTP) now runs several
  hosts in parallel instead of one at a time. Tunable with `-host-concurrency`.
- MAC address + vendor lookup. For on-link hosts, dragnet reads the ARP table
  and maps the OUI to a vendor.
- Device/OS fingerprinting from SSH banners, TLS cert subjects, HTTP Server
  headers, MAC vendor and port composition. Surfaced in the TUI and reports.
- Speed presets: `-speed fast|balanced|thorough`. Explicit `-timeout`,
  `-concurrency` and `-host-concurrency` flags override the chosen preset.

## [0.2.0] — 2026-06-16

- Honeypot/decoy detection. Hosts that expose many classic lure ports
  (telnet, ftp, smtp, pop3, mssql, vnc, rdp, smb...) while staying silent on
  services that normally send a greeting banner are now flagged as a probable
  decoy, in both the TUI and the HTML/JSON reports.
- TUI now exits automatically when the scan finishes instead of waiting for a
  keypress; the elapsed timer freezes at completion. Pass `-keep-open` to keep
  it up for scrolling.
- Banner-read timeout reduced from 1200ms to 600ms. Real services greet in
  milliseconds; the long wait mainly punished silent/decoy ports and inflated
  scan times.

## [0.1.0] — 2026-06-14

Initial release.

- Host discovery across a CIDR or single IP, with reverse-DNS and round-trip time.
- Concurrent TCP-connect port scan: curated top ports, full range, explicit lists.
- Service labelling and best-effort banner grabbing.
- TLS inspection: subject, issuer, version, cipher, expiry, self-signed and
  weak-protocol warnings.
- HTTP security-header audit with a 0-100 score per web port.
- Amber/noir Bubble Tea terminal UI; live host table as results arrive.
- Self-contained JSON and styled HTML reports written per run.
- Portable single static binary; runs from a USB stick with no install or admin.
- SYN-scan path scaffolded behind privilege/Npcap detection (not yet enabled).
