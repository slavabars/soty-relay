#!/bin/sh
# Build OpenWrt .ipk packages for dtm_relay from the local source tree.
#
#   openwrt/build-ipk.sh                 # all router architectures
#   openwrt/build-ipk.sh mipsel_24kc     # one architecture
#
# The binary is static (CGO_ENABLED=0), so the package has no shared-library
# dependency and runs on musl routers. Output goes to dist/.
set -eu

VERSION="${VERSION:-0.1.0}"
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/dist}"
GO="${GO:-go}"

# OpenWrt architecture -> Go target. GOMIPS=softfloat is mandatory for the
# FPU-less MT7621 class SoCs used by most supported routers.
build_one() {
	owrt_arch="$1" goarch="$2" goarm="$3" gomips="$4"
	bin="$OUT/$owrt_arch/dtm_relay"

	echo "build  $owrt_arch (GOARCH=$goarch GOARM=$goarm GOMIPS=$gomips)"
	mkdir -p "$OUT/$owrt_arch"
	(
		cd "$ROOT"
		CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOARM="$goarm" \
			GOMIPS="$gomips" "$GO" build -mod=vendor -trimpath \
			-ldflags="-s -w" -o "$bin" ./cmd/dtm_relay
	)
	package_one "$owrt_arch" "$bin"
}

package_one() {
	owrt_arch="$1" bin="$2"
	stage="$OUT/$owrt_arch/ipk"
	rm -rf "$stage"
	mkdir -p "$stage/control" "$stage/data/usr/bin" "$stage/data/etc/init.d" \
		"$stage/data/etc/config"

	cp "$bin" "$stage/data/usr/bin/dtm_relay"
	chmod 0755 "$stage/data/usr/bin/dtm_relay"
	cp "$ROOT/openwrt/files/dtm_relay.init" "$stage/data/etc/init.d/dtm_relay"
	chmod 0755 "$stage/data/etc/init.d/dtm_relay"
	cp "$ROOT/openwrt/files/dtm_relay.config" "$stage/data/etc/config/dtm_relay"
	chmod 0644 "$stage/data/etc/config/dtm_relay"

	cat > "$stage/control/control" <<EOF
Package: dtm_relay
Version: $VERSION-1
Depends:
Source: https://github.com/slavabars/soty-relay
SourceName: dtm_relay
License: AGPL-3.0-or-later
Section: net
Priority: optional
Maintainer: Soty <soty@dcns.ru>
Architecture: $owrt_arch
Installed-Size: $(du -sk "$stage/data" | awk '{print $1}')
Description: Soty LAN relay and tracker (static Go build)
 Stores only opaque end-to-end encrypted envelopes for offline delivery.
EOF
	printf '%s\n' /etc/config/dtm_relay > "$stage/control/conffiles"

	cat > "$stage/control/postinst" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/dtm_relay enable
/etc/init.d/dtm_relay start
exit 0
EOF
	chmod 0755 "$stage/control/postinst"

	cat > "$stage/control/prerm" <<'EOF'
#!/bin/sh
[ -n "${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/dtm_relay stop
/etc/init.d/dtm_relay disable
exit 0
EOF
	chmod 0755 "$stage/control/prerm"

	# Reproducible-ish: fixed ownership and mtimes inside the archives.
	tar -C "$stage/control" --owner=0 --group=0 --numeric-owner \
		--mtime='@0' -czf "$stage/control.tar.gz" .
	tar -C "$stage/data" --owner=0 --group=0 --numeric-owner \
		--mtime='@0' -czf "$stage/data.tar.gz" .
	printf '2.0\n' > "$stage/debian-binary"

	ipk="$OUT/dtm_relay_${VERSION}-1_${owrt_arch}.ipk"
	rm -f "$ipk"
	(cd "$stage" && ar r "$ipk" debian-binary control.tar.gz data.tar.gz \
		>/dev/null)
	echo "ipk    $ipk"
	rm -rf "$stage"
}

case "${1:-all}" in
all)
	build_one mipsel_24kc mipsle "" softfloat
	build_one mips_24kc mips "" softfloat
	build_one aarch64_cortex-a53 arm64 "" ""
	build_one arm_cortex-a7_neon-vfpv4 arm 7 ""
	build_one x86_64 amd64 "" ""
	;;
mipsel_24kc) build_one mipsel_24kc mipsle "" softfloat ;;
mips_24kc) build_one mips_24kc mips "" softfloat ;;
aarch64_cortex-a53) build_one aarch64_cortex-a53 arm64 "" "" ;;
arm_cortex-a7_neon-vfpv4) build_one arm_cortex-a7_neon-vfpv4 arm 7 "" ;;
x86_64) build_one x86_64 amd64 "" "" ;;
*)
	echo "unknown architecture: $1" >&2
	echo "known: mipsel_24kc mips_24kc aarch64_cortex-a53 arm_cortex-a7_neon-vfpv4 x86_64" >&2
	exit 64
	;;
esac

echo "done: $OUT"
