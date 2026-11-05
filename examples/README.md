# Rollout examples

Every example installs the released vwitch from GitHub
(`install.sh` → `.deb` → `vwitch setup`) or runs the container image. Pick
the one matching your platform; all of them end with the same running
service and the same CLI.

| Example | Platform | How |
|---|---|---|
| [`cloud-init/`](cloud-init/) | any cloud with cloud-init | generic user data |
| [`hetzner/`](hetzner/) | Hetzner Cloud | `hcloud server create --user-data-from-file` |
| [`digitalocean/`](digitalocean/) | DigitalOcean | `doctl compute droplet create --user-data-file` |
| [`aws-ec2/`](aws-ec2/) | AWS EC2 | `aws ec2 run-instances --user-data` |
| [`debian/`](debian/) | any Debian/Ubuntu host | one-line installer |
| [`docker/`](docker/) | container-managed hosts (Flatcar, NAS, existing Docker hosts) | `docker compose up -d` |

Generate user data with your own values instead of editing YAML by hand:

```sh
vwitch cloud-init --endpoint vpn.example.org --allow-direct \
  --netbird-setup-key "$NB_KEY" --lockdown-ssh \
  --egress home=./home.conf:ipv6 > user-data.yaml
```

`vwitch cloud-init` runs on any OS (macOS, Windows, Linux).
