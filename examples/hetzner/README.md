# Hetzner Cloud

Creates a small Debian 13 server running vwitch, joins NetBird for admin
access and closes public SSH once NetBird is connected.

```sh
export NETBIRD_SETUP_KEY=...            # from your NetBird dashboard
envsubst '$NETBIRD_SETUP_KEY' < user-data.yaml > /tmp/user-data.yaml

hcloud server create \
  --name vwitch --type cx22 --image debian-13 --location nbg1 \
  --ssh-key my-key --user-data-from-file /tmp/user-data.yaml

# allow the AmneziaWG port in the Hetzner firewall (default UDP 51845)
hcloud firewall create --name vwitch
hcloud firewall add-rule vwitch --direction in --protocol udp --port 51845 --source-ips 0.0.0.0/0 --source-ips ::/0
hcloud firewall apply-to-resource vwitch --type server --server vwitch
```

Without NetBird, drop `--netbird-setup-key` and `--lockdown-ssh` when
regenerating the file:

```sh
vwitch cloud-init --allow-direct > user-data.yaml
```

The admin UI is then reachable via an SSH tunnel:
`ssh -L 8443:127.0.0.1:443 root@<server>` → https://127.0.0.1:8443, or add a client and open https://v.witch
