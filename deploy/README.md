# Running dragnet monitor on the homelab (Docker)

Continuous network monitoring in a container, with the dashboard bound to
localhost and viewed over an SSH tunnel.

## What you need on the box

- Docker + the compose plugin (`docker compose version` to check)
- The Linux binary for your CPU: `dragnet-linux-amd64` (most servers) or
  `dragnet-linux-arm64` (Pi / ARM boards). Run `uname -m` on the box —
  `x86_64` means amd64, `aarch64` means arm64.

## Setup

1. Copy three files to a folder on the homelab, e.g. `~/dragnet/`:
   - the right binary, **renamed to `dragnet`**
   - `Dockerfile`
   - `docker-compose.yml`

   From your machine (adjust host/path):
   ```
   scp dragnet-linux-amd64 you@homelab:~/dragnet/dragnet
   scp deploy/Dockerfile deploy/docker-compose.yml you@homelab:~/dragnet/
   ```

2. Edit `docker-compose.yml` and set `-target` to your subnet if it isn't
   `192.168.1.0/24`, and `-interval` to how often you want scans.

3. Build and start:
   ```
   cd ~/dragnet
   docker compose up -d --build
   ```

4. Confirm it's running and watch the first scan:
   ```
   docker compose logs -f
   ```
   You'll see `[change] host_appeared ...` lines as the baseline is captured.
   Ctrl+C stops following the logs (the container keeps running).

## Viewing the dashboard

The dashboard binds to `127.0.0.1:8787` inside host networking, so it's only
reachable from the box itself. Tunnel to it from your laptop:

```
ssh -L 8787:127.0.0.1:8787 you@homelab
```

Leave that SSH session open and browse to `http://127.0.0.1:8787` locally.
Close the SSH session and the tunnel closes with it — nothing is exposed on
the LAN.

## Why host networking

A scanner in Docker's default bridge network is isolated: it can't reliably
reach your LAN hosts and can't read the host ARP table, so MAC/vendor lookup
returns nothing. `network_mode: host` (already set in the compose file) gives
the container the host's real network view, which is what a scanner needs.

## Lifecycle

```
docker compose up -d          # start (after first build)
docker compose down           # stop and remove the container
docker compose logs -f        # follow live output / changes
docker compose restart        # restart
docker compose up -d --build  # rebuild after dropping in a new binary
```

`restart: unless-stopped` means the monitor comes back automatically after a
reboot or a crash. The SQLite database lives in the `dragnet-data` named
volume, so scan history and the change timeline survive restarts. To wipe
history, `docker compose down -v` (the `-v` removes the volume).

## Updating to a new dragnet version

Drop the new binary in as `dragnet`, then:
```
docker compose up -d --build
```
The existing database is reused, so the change timeline continues unbroken.
