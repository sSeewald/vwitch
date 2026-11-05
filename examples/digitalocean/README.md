# DigitalOcean

```sh
doctl compute droplet create vwitch \
  --image debian-13-x64 --size s-1vcpu-1gb --region fra1 \
  --ssh-keys <fingerprint> --user-data-file user-data.yaml
```

Open UDP 51845 in a cloud firewall if you use one. Admin UI via SSH tunnel:
`ssh -L 8090:127.0.0.1:8090 root@<droplet>` → https://127.0.0.1:8090
