#!/bin/sh
# Build all OpenWrt .ipk files and bundle them into one release asset:
#
#   VERSION=1.7.20+38 openwrt/build-bundle.sh
#   VERSION=1.7.20+38 openwrt/build-bundle.sh --no-build
#
# Output: dist/dtm_relay-<version>-ipk.tar.gz containing one .ipk per
# architecture, SHA256SUMS and README.txt. build_apps.sh copies it to
# build-artifacts/ for the GitHub release.
set -eu

VERSION="${VERSION:-0.1.0}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/dist}"
NO_BUILD=0
[ "${1:-}" = "--no-build" ] && NO_BUILD=1

arches() {
	awk 'NF && $1 !~ /^#/ { print $1 }' "$ROOT/openwrt/arches.txt"
}

if [ "$NO_BUILD" -eq 0 ]; then
	VERSION="$VERSION" "$ROOT/openwrt/build-ipk.sh" all
fi

bundle="dtm_relay-${VERSION}-ipk.tar.gz"
stage="$OUT/bundle"
rm -rf "$stage"
mkdir -p "$stage"

count=0
for arch in $(arches); do
	ipk="$OUT/dtm_relay_${VERSION}-1_${arch}.ipk"
	if [ ! -f "$ipk" ]; then
		echo "missing package: $ipk" >&2
		exit 1
	fi
	cp "$ipk" "$stage/"
	count=$((count + 1))
done
if [ "$count" -ne 5 ]; then
	echo "expected 5 architectures, bundled $count" >&2
	exit 1
fi

(
	cd "$stage"
	sha256sum dtm_relay_*.ipk > SHA256SUMS
)

cat > "$stage/README.txt" <<EOF
Soty router relay (dtm_relay) $VERSION
======================================

OpenWrt 24.10+ package set (opkg 2024, gzip-tar .ipk).
Architectures: $(arches | tr '\n' ' ')

Back up the router before installing anything:
  sysupgrade -b /tmp/router-backup.tar.gz
Keep an overlay copy as well if you have custom packages.

Unpack and verify:
  tar -xzf dtm_relay-$VERSION-ipk.tar.gz
  sha256sum -c SHA256SUMS

Install the package for your architecture, for example:
  opkg install dtm_relay_${VERSION}-1_aarch64_cortex-a53.ipk

Enable and start:
  uci set dtm_relay.relay.enabled='1'
  uci commit dtm_relay
  /etc/init.d/dtm_relay enable
  /etc/init.d/dtm_relay start

The invite is printed to the log:
  logread | grep 'soty://host'

Never delete /etc/dtm-relay/identity: it is the relay Ed25519 key and
clients pin it. Federation is off by default; enable it only with
explicit seed URLs.

Русский: сначала сделайте бекап роутера (sysupgrade -b), распакуйте
архив, сверьте SHA-256 и установите .ipk своей архитектуры. Ключ
/etc/dtm-relay/identity не удалять — клиенты пиннят его.
EOF

rm -f "$OUT/$bundle"
tar -C "$stage" --owner=0 --group=0 --numeric-owner --mtime='@0' \
	-czf "$OUT/$bundle" .
rm -rf "$stage"

check="$(mktemp -d)"
trap 'rm -rf "$check"' EXIT
tar -xzf "$OUT/$bundle" -C "$check"
(
	cd "$check"
	sha256sum -c SHA256SUMS >/dev/null
)
files="$(find "$check" -maxdepth 1 -name 'dtm_relay_*.ipk' | wc -l)"
[ "$files" -eq 5 ] || {
	echo "bundle has $files packages, expected 5" >&2
	exit 1
}

echo "bundle $OUT/$bundle"
( cd "$OUT" && sha256sum "$bundle" )
