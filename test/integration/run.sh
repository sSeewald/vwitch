#!/bin/sh
# End-to-end test. Topology (all on one kernel):
#
#   ns client  --veth-- root ns (vwitch: awg0, vwe1, nftables, rules) --veth-- ns home
#   AWG client 10.8.0.2                                                     WG server 10.99.0.1
#                                                                           "internet" 198.51.100.1
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
ip -n home route add 10.8.0.0/24 dev wg0
# a tiny "internet" web server that shows the source address it sees
ip netns exec home python3 -c '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b=self.client_address[0].encode(); self.send_response(200); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
http.server.ThreadingHTTPServer(("",80),H).serve_forever()' &
# a minimal resolver: every A query is answered with 198.51.100.7
ip netns exec home python3 -c '
import socket,struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("9.9.9.9",53))
while True:
    q,a=s.recvfrom(512); i=12
    while q[i]: i+=q[i]+1
    end=i+5
    ans=b"\xc0\x0c\x00\x01\x00\x01"+struct.pack(">I",30)+b"\x00\x04"+socket.inet_aton("198.51.100.7")
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

echo "== kill switch"
vwitch killswitch on
sleep 1
SRC=$(ip netns exec client curl -s --max-time 3 http://198.51.100.1/ || true)
[ -z "$SRC" ] && ok "kill switch blocks traffic" || bad "kill switch leaked: '$SRC'"
check "kill switch: dns refused" sh -c 'ip netns exec client dig +time=2 @10.8.0.1 example.org | grep -q REFUSED'
vwitch killswitch off

echo "== exit failure -> offline policy ask (captive portal)"
ip -n home link set wg0 down
wait_for sh -c 'vwitch status | grep -q "phone.*portal"' && ok "client asked after exit failure" || { bad "portal after failure"; vwitch status; }
SRC=$(ip netns exec client curl -s --max-time 3 http://198.51.100.1/ || true)
case "$SRC" in *vwitch*) ok "HTTP lands on the captive page, nothing leaks" ;; *) bad "offline: got '$SRC'" ;; esac
check "dns still answered while asking" sh -c 'ip netns exec client dig +short +time=2 @10.8.0.1 v.witch | grep -qx 10.8.0.1'

echo "== offline policy block"
vwitch set offline block
wait_for sh -c 'vwitch status | grep -q "phone.*block"' && ok "client blocked" || bad "client blocked"
SRC=$(ip netns exec client curl -s --max-time 3 http://198.51.100.1/ || true)
[ -z "$SRC" ] && ok "no leak while blocked" || bad "leak while blocked: '$SRC'"
vwitch set offline ask
ip -n home link set wg0 up
wait_for sh -c 'vwitch status | grep -q "phone.*home"' && ok "client returns to home" || bad "client returns to home"

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
