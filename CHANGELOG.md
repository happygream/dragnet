# Changelog

All notable changes to dragnet are documented here.

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
