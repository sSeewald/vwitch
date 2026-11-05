# Integration test image: runs vwitch, a WireGuard "home" exit and an
# AmneziaWG client in separate network namespaces. Needs --privileged.
FROM golang:1.27.3-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/vwitch ./cmd/vwitch \
 && CGO_ENABLED=0 GOBIN=/out go install github.com/amnezia-vpn/amneziawg-go/v3@v3.1.20260828

FROM debian:trixie-slim
RUN apt-get update -q && apt-get install -y -q --no-install-recommends \
      iproute2 nftables wireguard-tools iputils-ping curl netcat-openbsd dnsutils python3 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/vwitch /usr/bin/vwitch
COPY --from=build /out/amneziawg-go /usr/bin/amneziawg-go
COPY test/integration/run.sh /run.sh
ENTRYPOINT ["/bin/sh", "/run.sh"]
