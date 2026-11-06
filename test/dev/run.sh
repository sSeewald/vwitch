#!/bin/sh
# Start a disposable vwitch dev instance in Docker with demo data.
# The container has its own network namespace: the host is not changed.
set -eu

NAME=${DEV_NAME:-vwitch-dev}
PORT=${DEV_PORT:-8090}
PASSWORD=${DEV_PASSWORD:-vwitch-dev-123}
IMAGE=${DEV_IMAGE:-vwitch:dev}

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv4.conf.all.rp_filter=2 --sysctl net.ipv4.conf.default.rp_filter=2 \
  -e VWITCH_ENDPOINT=demo.example.org -e VWITCH_ADMIN_INTERFACES=lo,eth0 \
  -e VWITCH_ALLOW_DIRECT=true -e VWITCH_ADMIN_PASSWORD="$PASSWORD" \
  -e VWITCH_LANGUAGE="${DEV_LANGUAGE:-de}" \
  -p "127.0.0.1:$PORT:443" "$IMAGE" serve --init --debug >/dev/null

# wait for the API socket
i=0
until docker exec "$NAME" vwitch status >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 30 ] || { docker logs "$NAME"; exit 1; }
  sleep 0.5
done

# demo exits: unreachable endpoints, so they show as down
key() { head -c 32 /dev/urandom | base64; }
egress() {
  printf '[Interface]\nPrivateKey = %s\nAddress = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = 0.0.0.0/0\n' \
    "$(key)" "$2" "$(key)" "$3" | docker exec -i "$NAME" vwitch egress add "$1" - >/dev/null
}
egress home 192.168.1.201/24 home.example.org:51820
egress office 10.20.0.2/32 office.example.org:51820
docker exec "$NAME" vwitch ingress add secure --strict --isolated >/dev/null
for c in phone laptop; do docker exec "$NAME" vwitch client add "$c" >/dev/null; done
docker exec "$NAME" vwitch client add tablet --ingress secure >/dev/null
docker exec "$NAME" vwitch route set streaming --via home netflix.com youtube.com googlevideo.com >/dev/null
docker exec "$NAME" vwitch route set work --via office corp.example.com >/dev/null

docker exec "$NAME" vwitch block add ads.example doubleclick.net >/dev/null

# demo traffic history: stop (it saves its own on shutdown), add, start
docker stop "$NAME" >/dev/null
awk -v now="$(date +%s)" 'BEGIN {
  srand(7); split("1h:10:3600 24h:300:86400 7d:3600:604800 30d:21600:2592000", rs, " ")
  split("phone laptop tablet", cs, " "); w["phone"] = 3; w["laptop"] = 8; w["tablet"] = 1
  printf "{\"series\":{"
  for (r = 1; r <= 4; r++) {
    split(rs[r], f, ":"); step = f[2]; n = f[3] / step; end = now - now % step
    printf "%s\"%s\":{", (r > 1 ? "," : ""), f[1]
    delete td; delete tu; delete tb
    for (c = 1; c <= 3; c++) {
      printf "%s\"%s\":{", (c > 1 ? "," : ""), cs[c]
      for (i = 0; i < n; i++) {
        t = end - i * step; h = (t % 86400) / 3600
        base = w[cs[c]] * 20000 * step * (1.2 + sin((h - 14) / 24 * 6.283)) * (0.4 + rand())
        d = int(base); u = int(base * (0.08 + rand() * 0.1)); td[t] += d; tu[t] += u
        b = (rand() < 0.06) ? 1 + int(rand() * 6) : 0; tb[t] += b # blocked events, now and then
        printf "%s\"%d\":{\"d\":%d,\"u\":%d,\"b\":%d}", (i ? "," : ""), t, d, u, b
      }
      printf "}"
    }
    printf ",\"\":{"; k = 0
    for (t in td) printf "%s\"%s\":{\"d\":%d,\"u\":%d,\"b\":%d}", (k++ ? "," : ""), t, td[t], tu[t], tb[t]
    printf "}}"
  }
  printf "}}\n"
}' > "${TMPDIR:-/tmp}/vwitch-dev-traffic.json"
docker cp "${TMPDIR:-/tmp}/vwitch-dev-traffic.json" "$NAME:/var/lib/vwitch/traffic.json" >/dev/null
rm -f "${TMPDIR:-/tmp}/vwitch-dev-traffic.json"
docker start "$NAME" >/dev/null
i=0
until docker exec "$NAME" vwitch status >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 30 ] || { docker logs "$NAME"; exit 1; }
  sleep 0.5
done

# demo lookups from the client addresses, in a helper sharing the network
# namespace; untracked, so the client masquerade does not rewrite them on lo
# (the answers do not come back then, the lookups are recorded anyway)
docker run --rm --network "container:$NAME" --cap-add NET_ADMIN \
  alpine:3.24@sha256:3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a sh -c '
  apk add -q --no-cache bind-tools nftables >/dev/null
  nft add table ip dev_seed
  nft add chain ip dev_seed out "{ type filter hook output priority raw; }"
  nft add rule ip dev_seed out ip daddr 10.8.0.1 udp dport 53 notrack
  q() { ip addr add "$1/32" dev lo 2>/dev/null; shift_ip=$1; shift
    for n in "$@"; do dig +short +tries=1 +retry=0 +time=1 -b "$shift_ip" @10.8.0.1 "$n" A >/dev/null; done; }
  q 10.8.0.2 www.youtube.com i.ytimg.com rr3.googlevideo.com ads.example tracker.ads.example api.github.com
  q 10.8.0.3 github.com api.github.com stats.doubleclick.net news.ycombinator.com www.wikipedia.org
  q 10.8.0.4 www.netflix.com assets.nflxext.com www.wikipedia.org ads.example
  nft delete table ip dev_seed' >/dev/null 2>&1 || true

echo "vwitch dev: https://127.0.0.1:$PORT  user: admin  password: $PASSWORD"
echo "CLI: docker exec $NAME vwitch status   logs: make dev-logs   stop: make dev-stop"
