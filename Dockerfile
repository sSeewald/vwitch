# Production image: one static vwitch binary on distroless (no shell, no
# package manager, ~10 MB). Multi-arch (linux/amd64, linux/arm64) by
# cross-compiling on the build platform. All base images pinned by digest.
#
# vwitch must manage host interfaces, routes and nftables, so it runs as
# container root, but with every capability dropped except NET_ADMIN,
# NET_RAW and NET_BIND_SERVICE, no-new-privileges and a read-only rootfs.
# See examples/docker/compose.yaml.
FROM --platform=$BUILDPLATFORM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS build
ARG VERSION=dev
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags "-s -w -X github.com/sseewald/vwitch/internal/version.version=${VERSION}" -o /out/vwitch ./cmd/vwitch

FROM gcr.io/distroless/static-debian13@sha256:448810357cc8e67b7208988abdba0f5ec3d3aebee0a5b13eb624979792cffc0f
LABEL org.opencontainers.image.title="vwitch" \
      org.opencontainers.image.description="Egress switch for an AmneziaWG relay" \
      org.opencontainers.image.source="https://github.com/sseewald/vwitch" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/vwitch /usr/bin/vwitch
VOLUME ["/etc/vwitch", "/var/lib/vwitch"]
ENTRYPOINT ["/usr/bin/vwitch"]
CMD ["serve", "--init"]
