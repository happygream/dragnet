# dragnet monitor — container image built around a prebuilt static binary.
#
# The binary is fully static (CGO_ENABLED=0, pure-Go SQLite), so it needs no
# base OS at all. We copy in ca-certificates from a builder stage only so that
# HTTPS/TLS inspection against hosts with public CAs works cleanly; scanning
# itself needs nothing.
#
# Build (from the folder containing this file and the binary):
#   docker build -t dragnet:latest .
#
# The binary must be named `dragnet` and sit next to this Dockerfile.

FROM alpine:3.20 AS certs
RUN apk add --no-cache ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --chmod=755 dragnet /dragnet

# Data (the SQLite db) lives here; mount a volume over it to persist.
VOLUME ["/data"]

# Dashboard port. With --network host this is informational only.
EXPOSE 8787

ENTRYPOINT ["/dragnet"]
