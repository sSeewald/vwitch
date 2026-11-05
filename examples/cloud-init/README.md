# Generic cloud-init

[`user-data.yaml`](user-data.yaml) installs the latest vwitch on a fresh
Debian 12+/Ubuntu 22.04+ machine with default settings and auto-detected
endpoint. It was produced by:

```sh
vwitch cloud-init > user-data.yaml
```

After boot:

```sh
cat /root/vwitch-admin-password      # admin UI password
vwitch egress add home ./home.conf   # a WireGuard client config from your router/server
vwitch client add phone --qr         # scan with the AmneziaWG app
vwitch status
```
