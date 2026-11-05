<p align="center">
  <img src="docs/logo/vwitch-mark.svg" alt="vwitch" width="112">
</p>

<h1 align="center">vwitch</h1>

<p align="center">
  <b>The egress switch for your AmneziaWG relay.</b><br>
  Clients connect to one server. vwitch decides where their traffic leaves the internet.
</p>

<p align="center">
  <a href="https://github.com/sseewald/vwitch/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/sseewald/vwitch?sort=semver&display_name=tag"></a>
  <a href="https://github.com/sseewald/vwitch/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/sseewald/vwitch/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/sseewald/vwitch/actions/workflows/security.yml"><img alt="Security" src="https://github.com/sseewald/vwitch/actions/workflows/security.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/sseewald/vwitch/actions/workflows/release.yml"><img alt="Release build" src="https://github.com/sseewald/vwitch/actions/workflows/release.yml/badge.svg"></a>
  <a href="go.mod"><img alt="Go" src="https://img.shields.io/github/go-mod/go-version/sseewald/vwitch"></a>
  <a href="https://github.com/sseewald/vwitch/pkgs/container/vwitch"><img alt="Container" src="https://img.shields.io/badge/ghcr.io-sseewald%2Fvwitch-2496ED?logo=docker&logoColor=white"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/sseewald/vwitch"></a>
</p>

---

vwitch turns a VPS into an [AmneziaWG](https://docs.amnezia.org/) relay with
several egresses. Clients connect to the obfuscated ingress `awg0`. vwitch forwards
their traffic through one of your **WireGuard egress tunnels**. An egress can be
any standard WireGuard peer: a home router, a gateway or another server. As an
option, traffic can also leave through the VPS's own uplink. vwitch watches every
egress and switches automatically when one fails. It never leaks traffic it isn't
allowed to send.

```
 phone ─┐                      ┌── vwe0 ─ WireGuard ─▶ home router  ─▶ internet
 laptop ┼─ AmneziaWG ─▶ vwitch ┼── vwe1 ─ WireGuard ─▶ office gw    ─▶ internet
 tablet ┘    (awg0)            └── eth0 (optional direct egress)   ─▶ internet
```

## Features

- **Health-based selection.** Each egress is checked by handshake age plus active probes through the tunnel, with hysteresis. Strategies are `failover`, `weighted` (sticky per client) and `fixed`, and each can be overridden per client.
- **Fail-safe by design.** Policy routing ends in a fixed `unreachable` rule and forward policy is drop. A missing egress blocks traffic instead of leaking it.
- **Offline behavior.** When no egress is healthy, vwitch can `block` traffic, show an `ask` page to the user, or fall back to `direct`. It returns to an egress automatically once one recovers.
- **Kill switch and direct mode.** Global or per client, available from the UI and the CLI.
- **Server-enforced DNS.** Client DNS is answered locally or forwarded to a public resolver through the client's own egress. No IPv6 leaks.
- **Local UI names.** `v.witch` and `vwitch.internal` work like `fritz.box`, and the names are configurable.
- **Web UI.**
  - A client view is reachable only from inside the tunnel.
  - An admin view is HTTPS only and reachable only via chosen interfaces (for example NetBird `wt0`), with username and password.
  - A security panel lists open ports on the server that you should close.
  - Live updates via SSE, mobile first, light and dark themes, English and German.
- **Full CLI.** Status, egresses, clients (QR code included), ordering, kill switch and settings, all from the terminal.
- **One-time client configs.** A client's private key is shown once and never stored. Outdated configs are flagged after server changes.
- **Generic.** Import any `wg-quick` config. There is no vendor-specific code.
- **No toolchain on the target.**
  - A single static binary with AmneziaWG embedded in userspace, plus WireGuard via the kernel.
  - Runs on any systemd Linux on amd64 or arm64. No DKMS and no kernel headers.
- **Clean ownership.** vwitch only touches its own nftables tables (`inet vwitch` and `ip vwitch_nat`) and never flushes the ruleset.

## Install

### Installer (Debian, Ubuntu, Fedora, RHEL family, openSUSE, any systemd Linux)

```sh
curl -fsSL https://github.com/sseewald/vwitch/releases/latest/download/install.sh | sudo sh
```

The installer:

1. Downloads the package for your distribution and CPU (`.deb`, `.rpm` or a static tarball).
2. Verifies its SHA-256 checksum.
3. Runs `vwitch setup`, which generates keys, AWG parameters and an admin password.
4. Starts the systemd service.

Pass options after `sh -s --`, for example:

```sh
curl -fsSL https://github.com/sseewald/vwitch/releases/latest/download/install.sh \
  | sudo sh -s -- --allow-direct --admin-interfaces lo,wt0 --language de
```

### Docker

The image is meant for hosts that are managed through containers: Flatcar and
other immutable OSes, NAS and homelab servers, or Docker hosts that already run
other services. vwitch still manages the host's network (host networking and
`NET_ADMIN`), so the container is a way to ship it, not an isolation boundary.
On a regular VPS, prefer the installer. See [`examples/docker`](examples/docker/).

The multi-arch image for amd64 and arm64 is about 15 MB. It is distroless, so it has no shell, and it runs read-only with minimal capabilities:

```sh
cd examples/docker && docker compose up -d
docker compose exec vwitch vwitch status
```

### First sign-in

The admin UI listens on port **8090**, HTTPS only, and by default only on `lo`.
From your machine, open an SSH tunnel and browse to it:

```sh
ssh -L 8090:127.0.0.1:8090 root@<server>
# then open https://127.0.0.1:8090
```

| | |
| --- | --- |
| **Username** | `admin` (or `--admin-user` / `VWITCH_ADMIN_USER`) |
| **Password** | printed by `vwitch setup` at install time, or written to the `--password-file` you passed (cloud-init examples: `/root/vwitch-admin-password`). In Docker it is in `config/admin-password`. |
| **Forgot it?** | `vwitch admin passwd` on the server sets a new one. |

Until you install your own certificate, the browser warns about a
self-signed certificate. Compare its SHA-256 fingerprint with the one vwitch
logs (`journalctl -u vwitch | grep sha256`, or `docker logs vwitch`) before you
accept it. With NetBird, set `vwitch set admin_interfaces lo,wt0` and open the
server's NetBird address instead of using a tunnel.

### Cloud-init

Generate user data for a fresh VPS. The optional NetBird join closes public SSH afterwards:

```sh
vwitch cloud-init --endpoint vpn.example.org --allow-direct \
  --netbird-setup-key XXXX --lockdown-ssh --egress home=./home.conf > user-data.yaml
```

Ready-made examples for Hetzner, DigitalOcean, AWS EC2, plain Debian and Docker are in [`examples/`](examples/).

## Quick start

```sh
vwitch egress add home ./home-wg.conf          # any wg-quick config
vwitch client add phone --qr                   # scan with the AmneziaVPN app (shown once)
vwitch status                                  # egresses, health, clients
```

| Task | Command |
| --- | --- |
| Show status | `vwitch status` (`--json` for scripts) |
| New config for a client (lost or outdated) | `vwitch client renew phone --qr` |
| Order egresses | `vwitch egress order home office` |
| Pin a client to an egress | `vwitch client set phone --strategy fixed --fixed office` |
| Kill switch | `vwitch killswitch on` / `off` |
| Change settings | `vwitch set <key> <value>` |
| Admin password | `vwitch admin passwd` |
| Own certificate for the admin UI | `vwitch tls set cert.pem key.pem` |
| Health check of the host | `vwitch doctor` |

## Configuration

`/etc/vwitch/vwitch.yaml` is the single source of truth. The UI and the CLI
write it atomically, and runtime switches live separately in `/var/lib/vwitch`.
A reconcile loop converges interfaces, routes and firewall to the desired state.
It is idempotent and survives reboots without manual steps.

Defaults:

| Setting | Default |
| --- | --- |
| Client network | `10.8.0.1/24` |
| AmneziaWG port | `51845/udp` |
| MTU | `1340` |
| DNS resolver | `9.9.9.9` |
| Admin UI | `https://…:8090` on `lo`, user `admin` |
| Client portal | port `80` inside the tunnel |

All of these are configurable.

## Security

- **Admin UI.**
  - HTTPS only and reachable only on the configured admin interfaces. VPN clients on `awg0` never reach it.
  - Without your own certificate, vwitch generates a self-signed one, renews it automatically and logs its SHA-256 fingerprint. Upload your own in the UI or with `vwitch tls set`; it applies without a restart.
  - Sign-in uses a username plus a bcrypt-hashed password, with login rate limiting and cross-origin protection. Changing the sign-in requires the current password.
  - Server-side sessions use random tokens (not JWT), expire after 2 h idle or 24 h at most, and end on logout, a password change or a restart.
- **Client keys.** A client's private key exists only in the config shown once at creation. vwitch stores only the public key. A lost or outdated config is replaced with `renew`, which revokes the old one. The UI flags clients whose config is outdated after server changes.
- **Client portal.** Shows each client only its own status, identified by its tunnel address, which WireGuard makes unspoofable. It is protected against cross-site requests.
- **systemd unit.** Runs with a capability bounding set (`NET_ADMIN`, `NET_RAW`, `NET_BIND_SERVICE`), `NoNewPrivileges` and strict sandboxing.
- **Container.** Runs with `cap_drop: ALL` and only the network capabilities added back, plus `no-new-privileges` and a read-only root filesystem. Its base images are pinned by digest.
- **Releases.** Binaries are static (`CGO_ENABLED=0`) and reproducible (`-trimpath`), and every artifact is listed in `checksums.txt`. CI actions are pinned by commit SHA.

- **Supply chain.**
  - Go modules are pinned by `go.sum` and verified against the Go checksum database (`go mod verify` in CI).
  - `govulncheck` and CodeQL run on every push and weekly.
  - Pull requests get a dependency review.
  - Dependabot keeps Go modules, action SHAs and image digests current.

- **Verifiable releases.** Every binary, package and image comes with a signed build provenance attestation (Sigstore, keyless) and an SBOM. The image is also signed with cosign. To check that an artifact was built by this repository's release workflow:
  ```sh
  gh attestation verify vwitch_1.0.0_linux_amd64.deb --repo sseewald/vwitch
  gh attestation verify oci://ghcr.io/sseewald/vwitch:1.0.0 --repo sseewald/vwitch
  cosign verify ghcr.io/sseewald/vwitch:1.0.0 \
    --certificate-identity-regexp '^https://github.com/sseewald/vwitch/\.github/workflows/release\.yml@' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
  ```

Please report vulnerabilities privately via GitHub security advisories.

## Bulletproof hardening

vwitch secures its own ports. Everything else on the server is your call.
The dashboard's **Security** panel lists every service that is reachable from
outside and does not belong to vwitch.

1. **Close everything else.** From the internet, vwitch only needs **UDP 51845**
   (or your `listen_port`). Use your provider's firewall (Hetzner Cloud
   Firewall, AWS security groups, …) or nftables/ufw to drop everything else.
   vwitch never touches tables it does not own, so your own rules stay intact.
2. **Keep admin access off the internet.** Join the server to an overlay VPN
   such as [NetBird](https://netbird.io), then:
   ```sh
   vwitch set admin_interfaces lo,wt0
   vwitch set lockdown_ssh true      # SSH only via lo/wt0 once wt0 is up
   ```
   SSH stays open until the overlay interface is up, so you cannot lock
   yourself out during setup. The cloud-init examples do this automatically
   with `--netbird-setup-key … --lockdown-ssh`.
3. **Use your own certificate** for the admin UI (`vwitch tls set`), or verify
   the SHA-256 fingerprint of the self-signed one (`vwitch` logs it, and the
   settings page shows it).
4. **Keep the kill switch semantics.** Leave `offline: block` (the default)
   unless clients may fall back to the server's own connection.
5. **Update regularly.** Install new releases (`install.sh` again, or bump the
   image tag) and watch the release notes.

## Development

Requirements: Go (version in [`go.mod`](go.mod)) and Docker. vwitch itself runs
on Linux only, so on macOS or Windows the dev instance runs in Docker.

### Run a dev instance

```sh
make dev           # build the image and start vwitch with demo data
```

Then open **https://127.0.0.1:8090** and sign in with username **`admin`** and
password **`vwitch-dev-123`**. Accept the self-signed certificate.

- **Demo data:** two egresses (`home`, `office`) with unreachable demo endpoints, so they show as down, and three clients.
- **Isolation:** the instance runs in its own network namespace with `cap-drop ALL`, and the port is bound to localhost only. It never changes your machine's network.
- **Reset:** every `make dev` starts fresh. Override the defaults with `DEV_PORT`, `DEV_PASSWORD` or `DEV_LANGUAGE` (e.g. `make dev DEV_LANGUAGE=en`).

```sh
make dev-logs                               # follow the logs
docker exec vwitch-dev vwitch status        # use the CLI inside
docker exec vwitch-dev vwitch killswitch on # watch the UI update live
make dev-stop                               # remove it
```

### Tests and checks

```sh
make build         # static binary in bin/
make test          # unit tests (no root needed)
make test-linux    # unit tests incl. Linux-only code, in Docker
make lint          # gofmt + go vet (darwin and linux)
make vuln          # go mod verify + govulncheck
make integration   # end-to-end test in network namespaces (privileged Docker)
make image         # production container image
make snapshot      # local GoReleaser build
```

## License

[MIT](LICENSE)
