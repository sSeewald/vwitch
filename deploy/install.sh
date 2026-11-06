#!/bin/sh
# vwitch installer for systemd Linux (amd64, arm64): .deb, .rpm or tarball.
#
#   curl -fsSL https://github.com/sseewald/vwitch/releases/latest/download/install.sh | sudo sh -s -- [options]
#
# Options (all optional, passed to "vwitch setup"):
#   --version X.Y.Z          install this release instead of the latest
#   --endpoint HOST          public address clients connect to (default: auto-detect)
#   --listen-port N          AmneziaWG UDP port (default 51845)
#   --address CIDR           server address + client network (default 10.8.0.1/24)
#   --resolver IP            public DNS resolver for clients (default 9.9.9.9)
#   --allow-direct           allow the server's own uplink as exit
#   --admin-interfaces LIST  interfaces for the admin UI, e.g. lo,awg0,wt0 (default lo,awg0)
#   --lockdown-ssh           allow SSH only on admin interfaces once they are up
#   --language de|en         default UI language
#   --password-file PATH     where to store the generated admin password
#   --no-start               install and configure, but do not start
set -eu

REPO="sseewald/vwitch"
VERSION="latest"
START=1
SETUP_ARGS=""

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2#v}"; shift 2 ;;
    --no-start) START=0; shift ;;
    --allow-direct|--lockdown-ssh) SETUP_ARGS="$SETUP_ARGS $1"; shift ;;
    --endpoint|--listen-port|--address|--resolver|--admin-interfaces|--language|--password-file)
      [ $# -ge 2 ] || die "$1 needs a value"
      SETUP_ARGS="$SETUP_ARGS $1 $2"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

# The binary is static and runs on any Linux; only the package format differs.
if command -v apt-get >/dev/null 2>&1; then FMT=deb
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1 || command -v zypper >/dev/null 2>&1; then FMT=rpm
else FMT=tar.gz
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
  final_url() { curl -fsSLI -o /dev/null -w '%{url_effective}' "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
  final_url() { wget -q --max-redirect=5 -S --spider "$1" 2>&1 | awk '/^  Location: /{u=$2} END{print u}'; }
else
  die "curl or wget is required"
fi

if [ "$VERSION" = "latest" ]; then
  url=$(final_url "https://github.com/$REPO/releases/latest")
  VERSION="${url##*/v}"
  [ -n "$VERSION" ] || die "cannot determine the latest release"
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
BASE="https://github.com/$REPO/releases/download/v$VERSION"
PKG="vwitch_${VERSION}_linux_${ARCH}.${FMT}"

log "Downloading vwitch $VERSION ($ARCH, $FMT)"
fetch "$BASE/$PKG" "$TMP/$PKG"
fetch "$BASE/checksums.txt" "$TMP/checksums.txt"
(cd "$TMP" && grep " $PKG\$" checksums.txt | sha256sum -c -) >/dev/null || die "checksum mismatch for $PKG"

log "Installing"
case "$FMT" in
  deb) DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$TMP/$PKG" >/dev/null ;;
  rpm)
    if command -v dnf >/dev/null 2>&1; then dnf install -y -q "$TMP/$PKG"
    elif command -v zypper >/dev/null 2>&1; then zypper --non-interactive install --allow-unsigned-rpm "$TMP/$PKG"
    else yum install -y -q "$TMP/$PKG"; fi ;;
  tar.gz)
    tar -xzf "$TMP/$PKG" -C "$TMP"
    install -m 0755 "$TMP/vwitch" /usr/local/bin/vwitch
    sed 's|/usr/bin/vwitch|/usr/local/bin/vwitch|' "$TMP/deploy/vwitch.service" > /etc/systemd/system/vwitch.service
    install -d -m 0700 /etc/vwitch ;;
esac

if [ ! -f /etc/vwitch/vwitch.yaml ]; then
  log "Creating configuration"
  # shellcheck disable=SC2086 # word splitting of SETUP_ARGS is intended
  vwitch setup $SETUP_ARGS
else
  log "Keeping existing /etc/vwitch/vwitch.yaml"
fi

if [ "$START" -eq 1 ]; then
  systemctl daemon-reload
  systemctl enable vwitch
  systemctl restart vwitch # also picks up the new binary on upgrades
  log "vwitch is running. Check with: vwitch doctor && vwitch status"
fi
