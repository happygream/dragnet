# Changelog

All notable changes to dragnet are documented here.

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
