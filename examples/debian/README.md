# Debian / Ubuntu host (no cloud-init)

```sh
curl -fsSL https://github.com/sseewald/vwitch/releases/latest/download/install.sh \
  | sudo sh -s -- --allow-direct --language de
```

Installer options are listed at the top of
[`deploy/install.sh`](../../deploy/install.sh). Without `curl`, use
`wget -qO- … | sudo sh -s -- …`.

Pin a version for reproducible rollouts:

```sh
curl -fsSL https://github.com/sseewald/vwitch/releases/download/v1.0.0/install.sh | sudo sh -s -- --version 1.0.0
```
