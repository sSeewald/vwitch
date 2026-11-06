#!/bin/sh
# End-to-end test. Topology (all on one kernel):
#
#   ns client  --veth-- root ns (vwitch: awg0, vwe1, nftables, rules) --veth-- ns home
#   AWG client 10.8.0.2                                                     WG server 10.99.0.1
#   ns client2 --veth-- (second ingress awg1)                               "internet" 198.51.100.1
set -eu
pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  ✓ $*"; }
bad()  { fail=$((fail+1)); echo "  ✗ $*"; }
check() { desc=$1; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi; }
wait_for() { i=0; while ! "$@" >/dev/null 2>&1; do i=$((i+1)); [ $i -gt 60 ] && return 1; sleep 1; done; }

echo "== topology"
ip netns add home; ip netns add client
ip link add vh type veth peer name vh-home; ip link set vh-home netns home
ip link add vc type veth peer name vc-client; ip link set vc-client netns client
ip addr add 192.0.2.1/24 dev vh; ip link set vh up
ip addr add 203.0.113.1/24 dev vc; ip link set vc up
ip -n home addr add 192.0.2.2/24 dev vh-home; ip -n home link set vh-home up; ip -n home link set lo up
ip -n client addr add 203.0.113.2/24 dev vc-client; ip -n client link set vc-client up; ip -n client link set lo up
ip -n client route add default via 203.0.113.1
ip netns add client2
ip link add vc2 type veth peer name vc2-client; ip link set vc2-client netns client2
ip addr add 198.18.0.1/24 dev vc2; ip link set vc2 up
ip -n client2 addr add 198.18.0.2/24 dev vc2-client; ip -n client2 link set vc2-client up; ip -n client2 link set lo up
ip -n client2 route add default via 198.18.0.1
# the VPS "uplink" default route (direct exit) points nowhere useful in the test
ip route replace default via 192.0.2.254 dev vh 2>/dev/null || true

echo "== home exit (plain WireGuard server)"
HOME_KEY=$(wg genkey); HOME_PUB=$(echo "$HOME_KEY" | wg pubkey)
VPS_KEY=$(wg genkey); VPS_PUB=$(echo "$VPS_KEY" | wg pubkey)
ip -n home link add wg0 type wireguard
ip netns exec home sh -c "echo $HOME_KEY > /tmp/k && wg set wg0 private-key /tmp/k listen-port 51820 peer $VPS_PUB allowed-ips 10.99.0.2/32,10.8.0.0/24"
ip -n home addr add 10.99.0.1/24 dev wg0; ip -n home link set wg0 up
ip -n home addr add 198.51.100.1/32 dev lo
ip -n home addr add 198.51.100.7/32 dev lo   # target of the domain route test
ip -n home addr add 9.9.9.9/32 dev lo        # the public resolver, only reachable through home
ip -n home addr add 198.51.100.66/32 dev lo  # in the blocked test country
ip -n home addr add 198.51.100.67/32 dev lo  # source of incoming connections from that country
ip -n home route add 10.8.0.0/24 dev wg0
# a tiny "internet" web server that shows the source address it sees
ip netns exec home python3 -c '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b=self.client_address[0].encode(); self.send_response(200); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
http.server.ThreadingHTTPServer(("",80),H).serve_forever()' &
# a minimal resolver: names under ru.test get 198.51.100.66 (the "RU"
# range), every other A query 198.51.100.7
ip netns exec home python3 -c '
import socket,struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("9.9.9.9",53))
while True:
    q,a=s.recvfrom(512); i=12
    while q[i]: i+=q[i]+1
    end=i+5
    ip="198.51.100.66" if q[12:i].endswith(b"\x02ru\x04test") else "198.51.100.7"
    ans=b"\xc0\x0c\x00\x01\x00\x01"+struct.pack(">I",30)+b"\x00\x04"+socket.inet_aton(ip)
    s.sendto(q[:2]+b"\x81\x80"+q[4:6]+b"\x00\x01\x00\x00\x00\x00"+q[12:end]+ans,a)' &

echo "== vwitch"
mkdir -p /etc/vwitch /run/vwitch
vwitch setup --endpoint 203.0.113.1 --allow-direct --password-file /root/pw >/dev/null
cat >> /etc/vwitch/vwitch.yaml <<YAML
YAML
python3 - <<'PY'
import re
p='/etc/vwitch/vwitch.yaml'; s=open(p).read()
s=re.sub(r'targets:\n(\s+- .*\n)+', 'targets:\n    - ping: 10.99.0.1\n', s, count=1)
s=s.replace('interval: 10s','interval: 2s').replace('timeout: 3s','timeout: 1s')
open(p,'w').write(s)
PY
vwitch config validate
# a cached country database (no download): "RU" = 198.51.100.64/26
mkdir -p /var/lib/vwitch
python3 -c '
import gzip,time
open("/var/lib/vwitch/geo.db.gz","wb").write(gzip.compress(("#updated|%d\nx|RU|ipv4|198.51.100.64|64|0|allocated\n" % time.time()).encode()))'
vwitch serve >/tmp/vwitch.log 2>&1 &
wait_for vwitch status || { cat /tmp/vwitch.log; exit 1; }
ok "daemon running"

check "nft table inet vwitch exists" nft list table inet vwitch
check "nft table ip vwitch_nat exists" nft list table ip vwitch_nat
check "fail-safe unreachable rule" sh -c 'ip rule | grep -q "99:.*10.8.0.0/24.*unreachable"'

cat > /tmp/home.conf <<CONF
[Interface]
PrivateKey = $VPS_KEY
Address = 10.99.0.2/24
DNS = 10.99.0.1
[Peer]
PublicKey = $HOME_PUB
AllowedIPs = 0.0.0.0/0
Endpoint = 192.0.2.2:51820
PersistentKeepalive = 5
CONF
vwitch egress add home /tmp/home.conf
check "egress interface vwe1 up" ip link show vwe1
wait_for sh -c 'vwitch status --json | grep -q "\"healthy\": true"' && ok "egress home healthy" || { bad "egress home healthy"; vwitch status; }

echo "== client"
vwitch client add phone > /tmp/phone.conf
check "client config has AWG params" grep -q '^H1 = ' /tmp/phone.conf
check "client config has no IPv6" sh -c '! grep -q "::" /tmp/phone.conf'
check "client config uses vwitch as DNS" grep -qx "DNS = 10.8.0.1" /tmp/phone.conf
CPRIV=$(awk -F' = ' '/^PrivateKey/{print $2}' /tmp/phone.conf | head -1)
SPUB=$(awk -F' = ' '/^PublicKey/{print $2}' /tmp/phone.conf)
PSK=$(awk -F' = ' '/^PresharedKey/{print $2}' /tmp/phone.conf)
hex() { echo "$1" | base64 -d | od -An -tx1 | tr -d ' \n'; }
ip netns exec client amneziawg-go awg-c >/dev/null 2>&1
{
  echo "set=1"
  echo "private_key=$(hex "$CPRIV")"
  for k in Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4; do
    v=$(awk -F' = ' -v k="$k" '$1==k{print $2}' /tmp/phone.conf)
    echo "$(echo "$k" | tr 'A-Z' 'a-z')=$v"
  done
  echo "public_key=$(hex "$SPUB")"
  echo "preshared_key=$(hex "$PSK")"
  echo "endpoint=203.0.113.1:51845"
  echo "persistent_keepalive_interval=5"
  echo "allowed_ip=0.0.0.0/0"
  echo
} | ip netns exec client nc -U -q1 /var/run/amneziawg/awg-c.sock >/tmp/uapi.out 2>&1 || true
check "client UAPI accepted config" grep -q 'errno=0' /tmp/uapi.out
ip -n client addr add 10.8.0.2/32 dev awg-c; ip -n client link set awg-c up
ip -n client route add 198.51.100.0/24 dev awg-c
ip -n client route add 10.8.0.0/24 dev awg-c
ip -n client route add 8.8.8.8/32 dev awg-c
wait_for ip netns exec client ping -c1 -W1 10.8.0.1 && ok "client reaches server through AWG" || bad "client reaches server through AWG"

wait_for sh -c 'vwitch status | grep -q "phone.*home"' && ok "client assigned to exit home" || { bad "client assigned to home"; vwitch status; }
SRC=$(ip netns exec client curl -s --max-time 5 http://198.51.100.1/ || true)
[ "$SRC" = "10.99.0.2" ] && ok "client traffic leaves via home (seen as $SRC)" || bad "traffic via home, got '$SRC'"
check "portal answers on server address" sh -c 'ip netns exec client curl -s --max-time 5 http://10.8.0.1/ | grep -q vwitch'
check "dns: v.witch resolves to server" sh -c 'ip netns exec client dig +short +time=2 @10.8.0.1 v.witch | grep -qx 10.8.0.1'
check "dns: any resolver is redirected to vwitch" sh -c 'ip netns exec client dig +short +time=2 @8.8.8.8 v.witch | grep -qx 10.8.0.1'
check "admin UI reachable from VPN client at https://v.witch" sh -c 'ip netns exec client curl -sk --max-time 5 --resolve v.witch:443:10.8.0.1 https://v.witch/login | grep -q current-password'

echo "== domain routes"
vwitch fast on    # normal exit: the server uplink, which leads nowhere in this test
wait_for sh -c 'vwitch status | grep -q "phone.*direct"' && ok "client in direct mode" || bad "client in direct mode"
SRC=$(ip netns exec client curl -s --max-time 3 http://198.51.100.7/ || true)
[ -z "$SRC" ] && ok "without route: no path to 198.51.100.7" || bad "unexpected path: '$SRC'"
vwitch route set lab --via home routed.test
check "route listed" sh -c 'vwitch route list | grep -q "lab.*home.*active.*routed.test"'
check "dns for routed name goes through the route's egress" sh -c 'ip netns exec client dig +short +time=2 @10.8.0.1 www.routed.test | grep -qx 198.51.100.7'
check "learned address gets a route rule" sh -c 'ip rule | grep -q "75:.*to 198.51.100.7 lookup 51821"'
SRC=$(ip netns exec client curl -s --max-time 5 http://198.51.100.7/ || true)
[ "$SRC" = "10.99.0.2" ] && ok "routed domain leaves via home (seen as $SRC)" || bad "routed domain via home, got '$SRC'"
check "other names keep the normal exit" sh -c '! ip netns exec client dig +short +time=2 @10.8.0.1 other.test | grep -q 198'
vwitch killswitch on
sleep 1
SRC=$(ip netns exec client curl -s --max-time 3 http://198.51.100.7/ || true)
[ -z "$SRC" ] && ok "kill switch beats the domain route" || bad "kill switch leaked via route: '$SRC'"
vwitch killswitch off
vwitch route rm lab
wait_for sh -c '! ip rule | grep -q "^75:"' && ok "route rule removed" || bad "route rule removed"
vwitch fast off
wait_for sh -c 'vwitch status | grep -q "phone.*home"' || bad "back to home"

echo "== domain blocking"
vwitch block add blocked.test
check "blocked domain answered with 0.0.0.0" sh -c 'ip netns exec client dig +short +time=2 @10.8.0.1 www.blocked.test | grep -qx 0.0.0.0'
check "other domains still resolve" sh -c 'ip netns exec client dig +short +time=2 @10.8.0.1 fine.test | grep -qx 198.51.100.7'
check "block log names domain and client" sh -c 'vwitch block log | grep -q "phone.*www.blocked.test.*custom"'
vwitch block rm blocked.test
check "unblocked domain resolves again" sh -c 'ip netns exec client dig +short +time=2 @10.8.0.1 www.blocked.test | grep -qx 198.51.100.7'

echo "== region blocking"
SRC=$(ip netns exec client curl -s --max-time 5 http://198.51.100.66/ || true)
[ "$SRC" = "10.99.0.2" ] && ok "country target reachable before blocking" || bad "country target before blocking: '$SRC'"
vwitch set regions.countries RU
vwitch set regions.enabled true
wait_for nft list table inet vwitch_block && ok "nft table inet vwitch_block exists" || bad "nft table inet vwitch_block exists"
check "block table holds the country range" sh -c 'nft list table inet vwitch_block | grep -q "198.51.100.64/26"'
SRC=$(ip netns exec client curl -s --max-time 5 http://198.51.100.66/ || true)
[ -z "$SRC" ] && ok "outgoing connection to the country blocked" || bad "outgoing to country leaked: '$SRC'"
# looked up by name: the TCP reset ends the attempt at once (curl 7, not a timeout)
ip netns exec client dig +short +time=2 @10.8.0.1 www.ru.test >/dev/null
rc=0; ip netns exec client curl -s --max-time 5 http://198.51.100.66/ >/dev/null 2>&1 || rc=$?
[ "$rc" = 7 ] && ok "blocked TCP connection is reset at once" || bad "blocked TCP connection: curl exit $rc"
wait_for sh -c 'vwitch block log | grep -q "198.51.100.66.*(RU) www.ru.test"' && ok "block log names the looked-up domain" || { bad "block log domain"; vwitch block log; }
SRC=$(ip netns exec client curl -s --max-time 5 http://198.51.100.1/ || true)
[ "$SRC" = "10.99.0.2" ] && ok "other countries unaffected" || bad "other target: '$SRC'"
ip netns exec home curl -s --max-time 2 --interface 198.51.100.67 http://192.0.2.1:9/ >/dev/null 2>&1 || true
wait_for sh -c 'vwitch block log | grep -q "phone.*198.51.100.66.*(RU).*region"' && ok "block log: outgoing with client and country" || { bad "block log outgoing"; vwitch block log; }
wait_for sh -c 'vwitch block log | grep -q "198.51.100.67.*(RU).*region"' && ok "block log: incoming from the country" || { bad "block log incoming"; vwitch block log; }
vwitch set regions.mode allow
SRC=$(ip netns exec client curl -s --max-time 5 http://198.51.100.66/ || true)
[ "$SRC" = "10.99.0.2" ] && ok "allow mode: listed country reachable" || bad "allow mode listed: '$SRC'"
SRC=$(ip netns exec client curl -s --max-time 3 http://198.51.100.1/ || true)
[ -z "$SRC" ] && ok "allow mode: other countries blocked" || bad "allow mode leaked: '$SRC'"
check "allow mode: VPN and DNS keep working" sh -c 'ip netns exec client dig +short +time=2 @10.8.0.1 v.witch | grep -qx 10.8.0.1'
vwitch set regions.enabled false
wait_for sh -c '! nft list table inet vwitch_block | grep -q "198.51.100.64"' && ok "block table emptied when off" || bad "block table emptied when off"
SRC=$(ip netns exec client curl -s --max-time 5 http://198.51.100.1/ || true)
[ "$SRC" = "10.99.0.2" ] && ok "traffic flows again" || bad "after region off: '$SRC'"

echo "== kill switch"
vwitch killswitch on
sleep 1
SRC=$(ip netns exec client curl -s --max-time 3 http://198.51.100.1/ || true)
[ -z "$SRC" ] && ok "kill switch blocks traffic" || bad "kill switch leaked: '$SRC'"
check "kill switch: dns refused" sh -c 'ip netns exec client dig +time=2 @10.8.0.1 example.org | grep -q REFUSED'
check "admin UI stays reachable (kill switch)" sh -c 'ip netns exec client curl -sk --max-time 5 --resolve v.witch:443:10.8.0.1 https://v.witch/login | grep -q current-password'
vwitch killswitch off

echo "== exit failure -> offline policy ask (captive portal)"
ip -n home link set wg0 down
wait_for sh -c 'vwitch status | grep -q "phone.*portal"' && ok "client asked after exit failure" || { bad "portal after failure"; vwitch status; }
SRC=$(ip netns exec client curl -sL --resolve v.witch:80:10.8.0.1 --max-time 3 http://198.51.100.1/ || true)
case "$SRC" in *vwitch*) ok "HTTP lands on the captive page, nothing leaks" ;; *) bad "offline: got '$SRC'" ;; esac
check "portal refuses actions for foreign names (DNS rebinding)" sh -c 'ip netns exec client curl -s -o /dev/null -w "%{http_code}" --max-time 3 -H "Host: attacker.example" -d action=direct -d on=true http://10.8.0.1/action | grep -qx 403'
check "dns still answered while asking" sh -c 'ip netns exec client dig +short +time=2 @10.8.0.1 v.witch | grep -qx 10.8.0.1'

echo "== offline policy block"
vwitch set offline block
wait_for sh -c 'vwitch status | grep -q "phone.*block"' && ok "client blocked" || bad "client blocked"
SRC=$(ip netns exec client curl -s --max-time 3 http://198.51.100.1/ || true)
[ -z "$SRC" ] && ok "no leak while blocked" || bad "leak while blocked: '$SRC'"
check "admin UI stays reachable (no egress works)" sh -c 'ip netns exec client curl -sk --max-time 5 --resolve v.witch:443:10.8.0.1 https://v.witch/login | grep -q current-password'
vwitch set offline ask
ip -n home link set wg0 up
wait_for sh -c 'vwitch status | grep -q "phone.*home"' && ok "client returns to home" || bad "client returns to home"

echo "== AmneziaWG 3.1"
# awg_up <conf> <address> [netns]: (re)creates the AWG client interface from a config
awg_up() {
  ns=${3:-client}; dev=awg-c; [ "$ns" = client ] || dev=awg-c2 # UAPI sockets are shared by all netns
  ip -n "$ns" link del "$dev" 2>/dev/null || true; sleep 1
  ip netns exec "$ns" amneziawg-go "$dev" >/dev/null 2>&1
  {
    echo "set=1"
    echo "private_key=$(hex "$(awk -F' = ' '/^PrivateKey/{print $2}' "$1")")"
    for k in Jc Jmin Jmax S1 S2 S3 S4 H1 H2 H3 H4; do
      echo "$(echo "$k" | tr 'A-Z' 'a-z')=$(awk -F' = ' -v k="$k" '$1==k{print $2}' "$1")"
    done
    v=$(awk -F' = ' '$1=="HeaderProtectionKey"{print $2}' "$1"); [ -z "$v" ] || echo "header_protection_key=$(hex "$v")"
    v=$(awk -F' = ' '$1=="ContentPaddingAddition"{print $2}' "$1"); [ -z "$v" ] || echo "content_padding_addition=$v"
    v=$(awk -F' = ' '$1=="RandomTrailers"{print $2}' "$1"); [ -z "$v" ] || echo "random_trailers=$v"
    echo "public_key=$(hex "$(awk -F' = ' '/^PublicKey/{print $2}' "$1")")"
    echo "preshared_key=$(hex "$(awk -F' = ' '/^PresharedKey/{print $2}' "$1")")"
    echo "endpoint=$(awk -F' = ' '/^Endpoint/{print $2}' "$1")"
    echo "persistent_keepalive_interval=5"
    echo "allowed_ip=0.0.0.0/0"
    echo
  } | ip netns exec "$ns" nc -U -q1 "/var/run/amneziawg/$dev.sock" >/tmp/uapi.out 2>&1 || true
  ip -n "$ns" addr add "$2/32" dev "$dev"; ip -n "$ns" link set "$dev" up
  ip -n "$ns" route add 198.51.100.0/24 dev "$dev"
  ip -n "$ns" route add 10.8.0.0/24 dev "$dev"
  grep -q 'errno=0' /tmp/uapi.out
}
vwitch client add tab --awg3 > /tmp/tab.conf
check "AWG 3.1 client gets content padding" grep -q '^ContentPaddingAddition = ' /tmp/tab.conf
check "new clients get AWG 3.1 by default" grep -q '^ContentPaddingAddition = ' /tmp/phone.conf
vwitch client add old --awg3=false > /tmp/old.conf
check "opted-out client config has no AWG 3.1 keys" sh -c '! grep -q "ContentPaddingAddition\|HeaderProtectionKey" /tmp/old.conf'
vwitch client rm old
check "AWG 3.1 client accepted by amneziawg-go" awg_up /tmp/tab.conf 10.8.0.3
wait_for ip netns exec client ping -c1 -W1 10.8.0.1 && ok "AWG 3.1 client: handshake and data" || bad "AWG 3.1 client: handshake and data"
SRC=$(ip netns exec client curl -s --max-time 5 http://198.51.100.1/ || true)
[ "$SRC" = "10.99.0.2" ] && ok "AWG 3.1 client traffic leaves via home" || bad "AWG 3.1 via home: '$SRC'"

vwitch ingress set default --strict
check "strict: S1-S4 at least 12" sh -c 'for k in s1 s2 s3 s4; do v=$(sed -n "s/^ *$k: //p" /etc/vwitch/vwitch.yaml | head -1); [ "$v" -ge 12 ] || exit 1; done'
awg_up /tmp/tab.conf 10.8.0.3 >/dev/null 2>&1 || true
sleep 3
if ip netns exec client ping -c1 -W2 10.8.0.1 >/dev/null 2>&1; then bad "old config rejected in strict mode"; else ok "old config rejected in strict mode"; fi
vwitch client renew tab > /tmp/tab2.conf
check "strict config has header protection" sh -c 'grep -q "^HeaderProtectionKey = " /tmp/tab2.conf && grep -qx "RandomTrailers = 1" /tmp/tab2.conf && grep -qx "H1 = 1" /tmp/tab2.conf'
check "strict config accepted by amneziawg-go" awg_up /tmp/tab2.conf 10.8.0.3
wait_for ip netns exec client ping -c1 -W1 10.8.0.1 && ok "strict: handshake and data" || bad "strict: handshake and data"
SRC=$(ip netns exec client curl -s --max-time 5 http://198.51.100.1/ || true)
[ "$SRC" = "10.99.0.2" ] && ok "strict: traffic leaves via home" || bad "strict via home: '$SRC'"
vwitch ingress set default --strict=false
check "strict off: header protection key removed" sh -c '! grep -q "header_protection_key" /etc/vwitch/vwitch.yaml'

echo "== AmneziaWG port"
vwitch set listen_port 51900
wait_for sh -c 'ss -uln | grep -q ":51900 "' && ok "ingress listens on the new port without restart" || { bad "new port"; ss -uln; }
check "old port closed" sh -c '! ss -uln | grep -q ":51845 "'
check "client marked outdated after port change" sh -c 'vwitch status --json | grep -q "\"outdated\": true"'
vwitch client renew tab > /tmp/tab3.conf
check "new config points at the new port" grep -qx 'Endpoint = 203.0.113.1:51900' /tmp/tab3.conf
awg_up /tmp/tab3.conf 10.8.0.3 >/dev/null 2>&1 || true
wait_for ip netns exec client ping -c1 -W1 10.8.0.1 && ok "client connects on the new port" || bad "client connects on the new port"
vwitch set listen_port 51845
vwitch client renew tab > /tmp/tab4.conf
awg_up /tmp/tab4.conf 10.8.0.3 >/dev/null 2>&1 || true

echo "== ingresses"
vwitch ingress add secure --strict --isolated
wait_for sh -c 'ss -uln | grep -q ":51846 "' && ok "second ingress listens on the next port" || { bad "second ingress port"; ss -uln; }
check "second ingress has its own interface" ip link show awg1
check "isolated ingress gets no admin access" sh -c 'vwitch ingress list --json | grep -q "\"name\":\"secure\",\"iface\":\"awg1\",\"port\":51846,\"strict\":true,\"isolated\":true,\"admin\":false"'
# client2 has no tunnel yet: its default route reaches the server over vc2
check "dns on the server address is closed outside the tunnel" sh -c '! ip netns exec client2 dig +short +time=2 +tries=1 @10.8.0.1 v.witch | grep -qx 10.8.0.1'
check "portal on the server address is closed outside the tunnel" sh -c '! ip netns exec client2 curl -s --max-time 3 http://10.8.0.1/ | grep -q vwitch'
vwitch client add lap --ingress secure > /tmp/lap.conf
check "client config points at its ingress" sh -c 'grep -qx "Endpoint = 203.0.113.1:51846" /tmp/lap.conf && grep -q "^HeaderProtectionKey = " /tmp/lap.conf'
check "client on strict ingress accepted by amneziawg-go" awg_up /tmp/lap.conf 10.8.0.4 client2
wait_for ip netns exec client2 ping -c1 -W1 10.8.0.1 && ok "second ingress: handshake and data" || bad "second ingress: handshake and data"
SRC=$(ip netns exec client2 curl -s --max-time 5 http://198.51.100.1/ || true)
[ "$SRC" = "10.99.0.2" ] && ok "second ingress: traffic leaves via home" || bad "second ingress via home: '$SRC'"
check "first ingress still works at the same time" ip netns exec client ping -c1 -W2 10.8.0.1
check "dns works on the second ingress" sh -c 'ip netns exec client2 dig +short +time=2 @10.8.0.1 v.witch | grep -qx 10.8.0.1'
check "isolated: no traffic from other clients" sh -c '! ip netns exec client ping -c1 -W2 10.8.0.4'
check "isolated: no traffic to other clients" sh -c '! ip netns exec client2 ping -c1 -W2 10.8.0.3'
check "isolated ingress cannot open the admin UI" sh -c '! ip netns exec client2 curl -sk --max-time 3 https://10.8.0.1/login | grep -q current-password'
vwitch ingress set secure --isolated=false
sleep 2
check "not isolated: clients reach each other across ingresses" ip netns exec client ping -c1 -W2 10.8.0.4
check "ingress with clients cannot be removed" sh -c '! vwitch ingress rm secure'
vwitch client rm lap
vwitch ingress rm secure
wait_for sh -c '! ip link show awg1' && ok "removed ingress is gone" || bad "removed ingress is gone"
wait_for sh -c '! ss -uln | grep -q ":51846 "' && ok "its port is closed" || bad "its port is closed"
vwitch client rm tab

echo "== offboarding"
vwitch client rm phone
sleep 1
check "client removed from status" sh -c '! vwitch status | grep -q phone'

echo "== admin UI"
check "admin login page" sh -c 'curl -sk https://127.0.0.1/login | grep -q current-password'
check "admin is HTTPS only" sh -c '! curl -s --max-time 3 http://127.0.0.1:443/login | grep -q current-password'
check "admin requires login" sh -c 'curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1/ | grep -q 303'

echo
echo "passed: $pass  failed: $fail"
[ $fail -eq 0 ] || { echo "--- vwitch log"; tail -50 /tmp/vwitch.log; exit 1; }
