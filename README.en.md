# Soty — relay host (dtm_host)

[Русский](README.md) · **English**

[![CI](https://github.com/slavabars/soty-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/slavabars/soty-relay/actions/workflows/ci.yml) [![Nightly](https://github.com/slavabars/soty-relay/actions/workflows/nightly.yml/badge.svg)](https://github.com/slavabars/soty-relay/actions/workflows/nightly.yml) [![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

An operator-run Soty node: it accepts encrypted envelopes for offline delivery, hands them to recipients when they reconnect and acts as a peer tracker. Plaintext and device keys never appear on the host.

Install, update and operations are described in the main repository: https://github.com/slavabars/soty#quick-install-on-a-relay-machine

The installers download a ready `dtm_host.bin` from [Releases](https://github.com/slavabars/soty/releases) and **never** overwrite `host.db`.

> **Do not delete `host.db`.** It holds `host_state.ed_seed` — the host's Ed25519 identity — and the client pins. Losing it means `IDENTITY CHANGED` for every pinned client.

## Building from source

`dtm_host` imports the `dtm_app` package (shared envelope and crypto code), so the two repositories must sit side by side:

```text
workspace/
  app-src/   # github.com/slavabars/soty-app
  host/      # this repository
```

```bash
export PATH="$HOME/development/flutter/bin:$PATH"

cd host
flutter pub get
dart analyze
flutter test --no-pub
dart compile exe bin/dtm_host.dart -o build/dtm_host
```

## Router relay for OpenWrt

`relay-owrt/` contains `dtm_relay`, a static Go implementation of the same protocol for musl routers (mipsel, mips, armv7, aarch64, x86_64). It does not replace `dtm_host`: the server-side host stays on Dart/SQLite, while a router serves its LAN and opens no outbound connections by default.

```bash
cd relay-owrt
go test ./...
VERSION=1.7.20+38 ./openwrt/build-bundle.sh
VERSION=1.7.20+38 ./openwrt/build-luci-ipk.sh   # LuCI panel only
```

`dist/dtm_relay-<version>-ipk.tar.gz` contains five architecture packages, the noarch `luci-app-dtm-relay` package, `SHA256SUMS` and `README.txt`. Install, UCI and limits are in [`relay-owrt/README.en.md`](relay-owrt/README.en.md); Soty releases publish this bundle as `dtm_relay-X.Y.Z+N-ipk.tar.gz`.

## Security

- Threat model: [`docs/threat_model.md`](docs/threat_model.md).
- How to report a vulnerability: [`SECURITY.md`](SECURITY.md) — **not** through a public issue.
- Limits on connections, subscriptions, frame size and the gossip window are enforced before any allocation.

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md), [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

AGPL-3.0, see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
