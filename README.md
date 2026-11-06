<p align="center">
  <img src="docs/logo/vwitch-mark.svg" alt="vwitch" width="112">
</p>

<h1 align="center">vwitch</h1>

<p align="center">
  <b>The egress switch for your AmneziaWG relay.</b><br>
  Clients connect to one server. vwitch decides which egress their traffic leaves through.
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
several egresses. Clients connect to an obfuscated **ingress** (`awg0`, and more
if you add them). vwitch forwards their traffic through one of your **WireGuard
egress tunnels**. An egress can be
any standard WireGuard peer: a home router, a gateway or another server. As an
option, traffic can also leave through the VPS's own uplink. vwitch watches every
egress and switches automatically when one fails. It never leaks traffic it isn't
allowed to send. What clients reach is whatever the egress offers: its LAN,
the internet through it, or both.

```
 phone  ─┐   ingresses              egresses
 laptop ─┼─▶ awg0 ─┐          ┌── vwe0 ─ WireGuard ─▶ home router ─▶ its network
 tablet ─┘         ├─ vwitch ─┼── vwe1 ─ WireGuard ─▶ office gw   ─▶ its network
 guest  ───▶ awg1 ─┘          └── eth0 (optional direct egress)  ─▶ VPS uplink
```

## Documentation

New to vwitch? Start with **[Getting started](docs/getting-started.md)**: what
vwitch does, installation, and your first egress and client, step by step with
screenshots. Every page of the admin UI has its own guide (overview,
ingresses, egresses, clients, routes, activity, blocking, settings and the
client page), all listed in **[docs/](docs/README.md)**.

## Features

- **Health-based selection.** Each egress is checked by handshake age plus active probes through the tunnel, with hysteresis. Strategies are `failover`, `weighted` (sticky per client) and `fixed`, and each can be overridden per client.
- **Fail-safe by design.** Policy routing ends in a fixed `unreachable` rule and forward policy is drop. A missing egress blocks traffic instead of leaking it.
- **Offline behavior.** When no egress is healthy, vwitch can `block` traffic, show an `ask` page to the user, or fall back to `direct`. It returns to an egress automatically once one recovers.
- **Domain routes.** Send domains such as `google.de` or `netflix.com` (with all subdomains) through a fixed egress, grouped into named routes, configurable in the UI or CLI. Duplicates across routes are rejected.
- **Domain and country blocking.** Block domains (with all subdomains) for every client, and block or allow whole countries by their registered address ranges, for outgoing, incoming or both directions. A block log shows every hit with time, client, address, country and direction.
- **Activity.** A traffic graph over the last hour, day, week or month, overall and per client, and the list of domains clients looked up during the last 24 hours, each with one-tap Block and Route via.
- **Several ingresses.** Run more than one AmneziaWG entry point (`awg0`, `awg1`, …), each with its own UDP port and camouflage. Mark one as strict (AWG 3.1 only) or isolated (its clients reach no other client). Every client picks its ingress.
- **AmneziaWG 3.1 camouflage.** Encrypted padding and no cookie replies; AWG 3.1 configs by default per ingress, switchable per client; an optional strict mode with header protection and random trailers.
- **Kill switch and direct mode.** Global or per client, available from the UI and the CLI.
- **Server-enforced DNS.** Client configs use vwitch itself (`10.8.0.1`) as DNS server. vwitch answers its own names, caches answers per egress, and forwards the rest to a public resolver through the client's own egress. Queries to any other resolver are redirected too. No IPv6 leaks.
- **Local UI names.** `v.witch` and `vwitch.internal` work like a router's local admin name, and the names are configurable.
- **Web UI.**
  - A client view is reachable only from inside the tunnel.
  - An admin view at **https://v.witch** for every VPN client, HTTPS only, with username and password. Each ingress has a switch for it (on by default, off for isolated ones); add NetBird `wt0` for access without the VPN. SSH is never opened to VPN clients.
  - A security panel lists open ports on the server that you should close.
  - Live updates via SSE, mobile first, light and dark themes, English and German.
- **Full CLI.** Status, egresses, clients (QR code included), ordering, kill switch and settings, all from the terminal.
- **One-time client configs.** A client's private key is shown once and never stored. Outdated configs are flagged after server changes.
- **Generic.** Import any `wg-quick` config. There is no vendor-specific code.
- **No toolchain on the target.**
  - A single static binary with AmneziaWG embedded in userspace, plus WireGuard via the kernel.
  - Runs on any systemd Linux on amd64 or arm64. No DKMS and no kernel headers.
- **Clean ownership.** vwitch only touches its own nftables tables (`inet vwitch`, `ip vwitch_nat` and `inet vwitch_block`) and never flushes the ruleset.

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

The admin UI listens on port **443**, HTTPS only, on `lo` and on the VPN
ingress `awg0`. Connect a client (`vwitch client add laptop --qr`) and open
**https://v.witch**. Before your first client exists, use an SSH tunnel:

```sh
ssh -L 8443:127.0.0.1:443 root@<server>
# then open https://127.0.0.1:8443
```

| | |
| --- | --- |
| **Username** | `admin` (or `--admin-user` / `VWITCH_ADMIN_USER`) |
| **Password** | your own, if you chose one at setup (see below); otherwise printed by `vwitch setup` at install time, or written to the `--password-file` you passed (cloud-init examples: `/root/vwitch-admin-password`). In Docker it is in `config/admin-password`. |
| **Forgot it?** | `vwitch admin passwd` on the server sets a new one. |

To choose the password yourself at install time:

```sh
# on the server
printf '%s' 'my long password' | sudo vwitch setup --admin-password-stdin
# for a new VPS: asks for the password on your machine
vwitch cloud-init --endpoint vpn.example.org --ask-admin-password > user-data.yaml
```

vwitch always stores only a bcrypt hash of the password. With cloud-init the
hashing already happens on your machine: user data is kept in plain text by
the cloud provider, so it carries only the hash, never the password.

Until you install your own certificate, the browser warns about a
self-signed certificate. Compare its SHA-256 fingerprint with the one vwitch
logs (`journalctl -u vwitch | grep sha256`, or `docker logs vwitch`) before you
accept it. With NetBird, set `vwitch set admin_interfaces lo,awg0,wt0` and open
the server's NetBird address as well.

Installed with an older version? Explicit values in `vwitch.yaml` are kept, so
switch over once with `vwitch set admin_listen :443` and
`vwitch set admin_interfaces lo,awg0` (plus `wt0` if you use NetBird).

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
| Domains via a fixed egress | `vwitch route set streaming --via home netflix.com youtube.com` |
| Add or remove route domains | `vwitch route add streaming disneyplus.com` / `vwitch route rm streaming youtube.com` |
| Kill switch | `vwitch killswitch on` / `off` |
| Change settings | `vwitch set <key> <value>` |
| Admin password | `vwitch admin passwd` |
| Own certificate for the admin UI | `vwitch tls set cert.pem key.pem` |
| Health check of the host | `vwitch doctor` |

## Domain routes

A route sends a list of domains through one egress, no matter which exit the
client normally uses (including direct mode). Manage routes under **Routes**
in the admin UI or with `vwitch route`.

```sh
vwitch route set streaming --via home netflix.com youtube.com
vwitch route list
```

- A domain includes all its subdomains (`google.de` covers `www.google.de`).
  The most specific domain wins, so `mail.google.com` can go elsewhere than
  `google.com`. Input is cleaned up: `https://www.Google.de/x` becomes
  `www.google.de`. Each domain may be in one route only.
- vwitch learns the addresses from the clients' DNS queries, which it answers
  anyway. The query itself leaves through the route's egress, so CDNs return
  addresses that fit that path. The address is routed **before** the client
  gets the answer, so the first connection already takes the route. Learned
  addresses are kept for at least an hour so long connections stay on their
  path.
- The kill switch and blocked clients always win. If the route's egress is
  down, clients use their normal exit until it is back.
- Limits: browsers with their own encrypted DNS (Secure DNS / DoH) and
  hard-coded IP addresses bypass DNS and therefore the route. Addresses a
  client cached before the route existed apply once their DNS entry expires.

## Blocking

Under **Blocking** in the admin UI, or with `vwitch block` and `vwitch set`:

```sh
vwitch block add ads.example.com tracker.example   # answered with 0.0.0.0
vwitch block log                                     # recent hits
vwitch set regions.countries RU,CN
vwitch set regions.mode block          # or: allow (only these countries)
vwitch set regions.direction both      # or: outgoing, incoming
vwitch set regions.enabled true
```

- **Domains** are answered by vwitch's DNS with `0.0.0.0` (A) or an empty
  answer, including all subdomains. Like domain routes, this only sees DNS:
  browsers with their own encrypted DNS bypass it.
- **Countries** are matched by the address ranges the five regional internet
  registries publish. vwitch downloads them (about 46 MB) once region blocking
  is on, keeps a compact copy in `/var/lib/vwitch` and refreshes it weekly.
  *Outgoing* covers connections clients start. *Incoming* covers new
  connections from outside to the server, including the VPN port, so a client
  travelling in a blocked country cannot connect. Connections that already
  exist keep working. Private and special-purpose ranges are never filtered.
- **Allow mode for incoming connections** locks out SSH and the VPN from every
  other country, you included when you travel. The UI warns about it.
- Every blocked lookup or connection appears in the block log (in memory,
  the last 1000 entries) with time, client, target, country and direction.
  Rules live in their own nftables table `inet vwitch_block`.

## Activity

Under **Activity** in the admin UI:

- **Traffic graph** for the last hour, day, week or month, for all clients
  together or for one client. The overview and every client page show it too.
  The history is sampled every 10 seconds and kept in
  `/var/lib/vwitch/traffic.json`.
- **Per client** download, upload and share for the chosen range.
- **Domains** clients looked up during the last 24 hours, grouped by site
  (`www.youtube.com` and `i.ytimg.com` count for their own site), with the
  clients that asked. Each entry can be blocked or routed through an egress in
  one step. The list is kept in memory only and can be switched off in the
  settings (`vwitch set activity false`).

## Ingresses

An ingress is an AmneziaWG interface that clients connect to. Every install
starts with the ingress `default` on `awg0` and UDP 51845. Add more on the
**Ingresses** page or with the CLI:

```sh
vwitch ingress add secure --strict --isolated   # awg1, next free port (51846)
vwitch client add laptop --ingress secure --qr
vwitch ingress list
```

All ingresses share the client network, the server address `10.8.0.1` and
the server key, so a client can move to another ingress
(`vwitch client set laptop --ingress default`, then `vwitch client renew laptop`).
Each ingress has its own port and camouflage parameters:

- **Strict** accepts only apps with AmneziaWG 3.1 (header protection, see below).
  A strict ingress next to a compatible one lets new and old apps connect at
  the same time.
- **Isolated** clients reach their egress, DNS and the portal, but no other
  client, and no other client reaches them. Without isolation, clients reach
  each other, also across ingresses.
- **Admin UI reachable** (`--admin`) decides per ingress whether its clients
  can open the admin UI. On for new ingresses, off for new isolated ones,
  switchable at any time, also for `default`.

An ingress with clients cannot be removed; move or remove its clients first.
Allow every ingress port in your provider's firewall. Configs written before
ingresses existed (`server.interface`, `server.listen_port`, `server.awg`) are
moved to the ingress `default` automatically.

## AmneziaWG 3.1

New ingresses use AmneziaWG 3.1 features that every client understands:
encrypted content padding (inside the encryption, invisible to the receiver)
and no cookie replies under load. Junk packet sizes S1 to S4 are at least 12.

- **AWG 3.1 client configs** add `ContentPaddingAddition` to the client's
  config. New clients get them by default (per ingress: "AmneziaWG 3.1 for new
  clients", `vwitch ingress set <name> --new-clients-awg3`). Turn them off for
  apps without AmneziaWG 3.1 support, which reject unknown keys: when adding
  the client (`vwitch client add tv --awg3=false`, or the switch in the form)
  or later on the client page.
- **Strict mode** (Ingresses page, or `vwitch ingress set <name> --strict`)
  adds header protection and random trailers for every client of that
  ingress. It changes its parameters, so **each of its clients needs a new
  config** afterwards (`vwitch client renew <name>`), and they must support
  AmneziaWG 3.1. Turning it off again also needs new configs. To keep older
  apps working, put strict mode on a second ingress instead.

## Configuration

`/etc/vwitch/vwitch.yaml` is the single source of truth. The UI and the CLI
write it atomically, and runtime switches live separately in `/var/lib/vwitch`.
A reconcile loop converges interfaces, routes and firewall to the desired state.
It is idempotent and survives reboots without manual steps.

Defaults:

| Setting | Default |
| --- | --- |
| Client network | `10.8.0.1/24` |
| AmneziaWG ingress | `default` on `awg0`, `51845/udp` |
| MTU | `1340` |
| Client DNS | `10.8.0.1` (vwitch), upstream `9.9.9.9` |
| Admin UI | `https://v.witch` (port 443) on `lo` and `awg0`, user `admin` |
| Client portal | port `80` inside the tunnel |

All of these are configurable.

## Security

- **Admin UI.**
  - HTTPS only. By default every VPN client can open it at https://v.witch (through any ingress that is not isolated), and so can the server itself (`lo`). Nothing else reaches it unless you add an interface, e.g. NetBird `wt0`. Each ingress has its own switch "Admin UI reachable"; the list behind it is the setting `admin_interfaces`.
  - Without your own certificate, vwitch generates a self-signed one, renews it automatically and logs its SHA-256 fingerprint. Upload your own in the UI or with `vwitch tls set`; it applies without a restart.
  - Sign-in uses a username plus a bcrypt-hashed password, with login rate limiting and cross-origin protection. Changing the sign-in requires the current password.
  - Server-side sessions use random tokens (not JWT). They expire after 7 days without use or 30 days at most, and end on logout or a password change. They survive restarts: the state directory keeps only SHA-256 hashes of the tokens.
- **Client keys.** A client's private key exists only in the config shown once at creation. vwitch stores only the public key. A lost or outdated config is replaced with `renew`, which revokes the old one. The UI flags clients whose config is outdated after server changes.
- **Client portal.** Shows each client only its own status, identified by its tunnel address, which WireGuard makes unspoofable. It is protected against cross-site requests and DNS rebinding: it only answers for vwitch's own names and the server address, and vwitch's DNS drops upstream answers that point into the client network. The portal and DNS on the server address are reachable only through the tunnel.
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
   (and the ports of further ingresses). Use your provider's firewall (Hetzner Cloud
   Firewall, AWS security groups, …) or nftables/ufw to drop everything else.
   vwitch never touches tables it does not own, so your own rules stay intact.
2. **Keep admin access off the internet.** The admin UI is only reachable
   through the VPN (`awg0`) and `lo`. For SSH, join the server to an overlay
   VPN such as [NetBird](https://netbird.io), then:
   ```sh
   vwitch set admin_interfaces lo,awg0,wt0
   vwitch set lockdown_ssh true      # SSH only via lo/wt0 once wt0 is up
   ```
   SSH is never opened on `awg0`, and `awg0` alone never triggers the lockdown.
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
