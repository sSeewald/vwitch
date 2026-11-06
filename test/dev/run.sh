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
for c in phone laptop tablet; do docker exec "$NAME" vwitch client add "$c" >/dev/null; done
docker exec "$NAME" vwitch route set streaming --via home netflix.com youtube.com googlevideo.com >/dev/null
docker exec "$NAME" vwitch route set work --via office corp.example.com >/dev/null

echo "vwitch dev: https://127.0.0.1:$PORT  user: admin  password: $PASSWORD"
echo "CLI: docker exec $NAME vwitch status   logs: make dev-logs   stop: make dev-stop"
