# Docker

## Who this is for

The image is a different way to ship vwitch, not a sandbox. vwitch is a router,
so the container runs with host networking and `NET_ADMIN`, and it changes the
host's interfaces, routes and nftables directly.

Use it when the host is managed through containers anyway:

- **Container-first or immutable OS** without apt or dnf, for example Flatcar
  Container Linux. Its kernel ships WireGuard, nftables and `/dev/net/tun`, and
  Docker is preinstalled.
  - Run the container from a systemd unit or a Butane/Ignition config.
  - Cloud-init does not apply there.
  - Compose may not be preinstalled. Use the equivalent `docker run` flags from
    `compose.yaml` instead.
  - Flatcar should work but has not been tested yet.
- **Existing Docker hosts:** homelab servers, NAS systems or a VPS that already
  runs other services with Compose or Portainer.
- **Image-based updates**, by pinning and bumping a tag.

For a dedicated VPS on Debian, Ubuntu, Fedora or similar, use the
[installer](../../README.md#install) instead. The systemd unit is sandboxed
more tightly than a container can be, and it needs no container runtime.

Host requirements:

- A Linux kernel with WireGuard (5.6+) and nftables.
- `/dev/net/tun`.
- amd64 or arm64.

## Usage

```sh
docker compose up -d
cat config/admin-password
docker compose exec vwitch vwitch status
docker compose exec vwitch vwitch client add phone --qr
```

The container uses host networking because vwitch is a router: it creates
`awg0` and the egress interfaces on the host and owns the nftables tables
`inet vwitch` / `ip vwitch_nat`. Nothing else on the host is touched.

On first start `serve --init` creates `config/vwitch.yaml` from the
`VWITCH_*` variables (`ENDPOINT`, `LISTEN_PORT`, `ADDRESS`, `RESOLVER`,
`ALLOW_DIRECT`, `ADMIN_INTERFACES`, `LANGUAGE`, `ADMIN_USER`, `ADMIN_PASSWORD`). Later
changes go through the CLI, the admin UI or by editing the file plus
`vwitch reload`.

Admin UI: https://v.witch from any VPN client, or https://127.0.0.1 on the host (or via SSH tunnel). It is HTTPS only; until you upload a certificate it uses a self-signed one, so compare the SHA-256 fingerprint from `docker logs vwitch`.
