# syntax=docker/dockerfile:1
#
# tsctl container — static, no CGO, runs as nonroot, no special capabilities.
# tsnet uses USERSPACE networking, so this needs NO /dev/net/tun and NO
# NET_ADMIN — perfect for a NAS (Synology/QNAP/TrueNAS/Unraid) Docker runtime.
# The web UI is served on the TAILNET only (reach it at http://<hostname>/ over
# Tailscale); /healthz stays loopback-inside-the-container by design.
#
# Multi-arch via CROSS-COMPILATION: the build stage pins to $BUILDPLATFORM (runs
# natively on the build host) and Go cross-compiles to $TARGETOS/$TARGETARCH, so
# building a linux/amd64 image on an arm64 Mac needs NO qemu emulation. The final
# distroless layer only copies files (no exec), so it's target-arch-clean.

FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH VERSION=dev
ENV GOTOOLCHAIN=auto CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Static, stripped, version-stamped (web assets are embedded via embed.FS).
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/tsctl ./cmd/tsctl
# State dir owned by the distroless nonroot uid (65532) so a mounted named volume
# inherits writable ownership.
RUN install -d -o 65532 -g 65532 /out/state

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.title="tsctl" \
      org.opencontainers.image.description="Tailscale exit-node manager" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/lifeart/tsctl"
COPY --from=build /out/tsctl /tsctl
COPY --from=build --chown=65532:65532 /out/state /var/lib/tsctl
ENV TSCTL_STATE_DIR=/var/lib/tsctl \
    TSCTL_LISTEN=:80 \
    TSCTL_HEALTH_ADDR=127.0.0.1:8088
VOLUME ["/var/lib/tsctl"]
# distroless/static:nonroot already runs as uid 65532 (no NET_ADMIN, no TUN).
ENTRYPOINT ["/tsctl"]
