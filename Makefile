# Common tasks. Requires Go (see go.mod) and, for integration tests, Docker.
.PHONY: build test test-linux lint vuln integration image snapshot clean dev dev-logs dev-stop

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-X github.com/sseewald/vwitch/internal/version.version=$(VERSION)" -o bin/vwitch ./cmd/vwitch

test:
	go test ./...

# Unit tests including the linux-only ones (nftables expressions, netlink)
test-linux:
	docker run --rm -v "$(CURDIR)":/src -w /src golang:1.27.3-trixie go test ./...

lint:
	test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...
	GOOS=linux go vet ./...

# Supply chain: module checksums and known vulnerabilities
vuln:
	go mod verify
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

# End-to-end test in network namespaces (privileged container)
integration:
	docker build -f test/integration/Dockerfile -t vwitch-it .
	docker run --rm --privileged vwitch-it

image:
	docker build --build-arg VERSION=$(VERSION) -t vwitch:$(VERSION) .

# Disposable dev instance with demo data on https://127.0.0.1:8090 (isolated
# network namespace in Docker; the host is not reconfigured)
dev:
	docker build -t vwitch:dev --build-arg VERSION=$(VERSION) .
	test/dev/run.sh

dev-logs:
	docker logs -f vwitch-dev

dev-stop:
	docker rm -f vwitch-dev

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf bin dist
