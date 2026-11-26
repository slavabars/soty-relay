#!/bin/sh
# Build the noarch LuCI package for dtm_relay from the local source tree.
#
#   VERSION=1.7.21+39 openwrt/build-luci-ipk.sh
#
# Output: dist/luci-app-dtm-relay_<version>-1_all.ipk (OpenWrt 24.10 gzip-tar
# format, the same as the relay packages).
set -eu

VERSION="${VERSION:-0.1.0}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PKG="$ROOT/luci-app-dtm-relay"
OUT="${OUT:-$ROOT/dist}"

stage="$OUT/luci-ipk"
rm -rf "$stage"
mkdir -p "$stage/control" "$stage/data"

mkdir -p "$stage/data/www"
cp -R "$PKG/htdocs/." "$stage/data/www/"
cp -R "$PKG/root/." "$stage/data/"
chmod 0755 "$stage/data/usr/libexec/dtm-relay-status"

# LuCI loads every /usr/lib/lua/luci/i18n/*.<lang>.lmo into the active
# catalog. Compile the PO files here: the local build does not have the
# OpenWrt po2lmo tool, and shipping only the .po silently leaves the UI in
# English.
i18n="$stage/data/usr/lib/lua/luci/i18n"
mkdir -p "$i18n"
for po in "$PKG"/po/*/*.po; do
	[ -f "$po" ] || continue
	lang="$(basename "$(dirname "$po")")"
	python3 "$ROOT/openwrt/po2lmo.py" "$po" \
		"$i18n/luci-app-dtm-relay.$lang.lmo"
done

cat > "$stage/control/control" <<EOF
Package: luci-app-dtm-relay
Version: ${VERSION}-1
Depends: luci-base, rpcd, uclient-fetch, dtm_relay
Source: https://github.com/slavabars/soty-relay
SourceName: luci-app-dtm-relay
License: AGPL-3.0-or-later
Section: luci
Priority: optional
Maintainer: Soty <soty@dcns.ru>
Architecture: all
Installed-Size: $(du -sk "$stage/data" | awk '{print $1}')
Description: LuCI control panel for the Soty router relay
 Service state, metrics and launch settings for dtm_relay.
EOF

cat > "$stage/control/postinst" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
rm -f /tmp/luci-indexcache* 2>/dev/null
rm -rf /tmp/luci-modulecache/* 2>/dev/null
/etc/init.d/rpcd reload 2>/dev/null || true
exit 0
EOF
chmod 0755 "$stage/control/postinst"

cat > "$stage/control/prerm" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
rm -f /tmp/luci-indexcache* 2>/dev/null
rm -rf /tmp/luci-modulecache/* 2>/dev/null
/etc/init.d/rpcd reload 2>/dev/null || true
exit 0
EOF
chmod 0755 "$stage/control/prerm"

tar -C "$stage/control" --owner=0 --group=0 --numeric-owner \
	--mtime='@0' -czf "$stage/control.tar.gz" .
tar -C "$stage/data" --owner=0 --group=0 --numeric-owner \
	--mtime='@0' -czf "$stage/data.tar.gz" .
printf '2.0\n' > "$stage/debian-binary"

ipk="$OUT/luci-app-dtm-relay_${VERSION}-1_all.ipk"
rm -f "$ipk"
tar -C "$stage" --owner=0 --group=0 --numeric-owner --mtime='@0' \
	-czf "$ipk" ./debian-binary ./control.tar.gz ./data.tar.gz
rm -rf "$stage"

echo "luci   $ipk"
( cd "$OUT" && sha256sum "$(basename "$ipk")" )
