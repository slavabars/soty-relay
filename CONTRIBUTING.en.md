# Contributing to the Soty relay

[Русский](CONTRIBUTING.md) · **English**

`dtm_host` is the operator-run relay and peer tracker. Changes here affect every relay in the federation, so they are reviewed carefully.

## Before you start

- Read `docs/threat_model.md` before touching the protocol or storage.
- Open an issue before a non-trivial change.
- Security problems go to `SECURITY.md`, **never** to a public issue.

## Development

`dtm_host` imports the `dtm_app` package for the shared envelope and crypto code, so the two repositories must sit side by side:

```text
workspace/
  app-src/     # https://github.com/slavabars/soty-app
  host/        # this repository
```

```bash
export PATH="$HOME/development/flutter/bin:$PATH"

cd host
flutter pub get
dart analyze
flutter test --no-pub
```

## Router relay (Go)

`relay-owrt/` is the second protocol implementation in Go. It must match `dtm_host` on the wire, so protocol changes are checked in both implementations.

```bash
cd relay-owrt
go test ./...
go vet ./...
VERSION=X.Y.Z+N ./openwrt/build-bundle.sh
cd ../.. && scripts/verify_owrt_bundle.sh build-artifacts/dtm_relay-X.Y.Z+N-ipk.tar.gz
```

- The golden vector `internal/wire/testdata/vector.json` is produced by `host/tool/gen_wire_vector.dart`; never bend it to the Go code.
- Every architecture in `openwrt/arches.txt` must build; `GOMIPS=softfloat` is mandatory for mips.
- An `.ipk` for OpenWrt 24.10+ is a gzip-tar, not an `ar` archive.
- A live-router test starts with a verified backup (`sysupgrade -b`, overlay, `/etc`, packages) and ends with a rollback to the original `uci export`/`opkg list-installed`.

## Rules

- **Test first**, including hostile paths: oversize frames, bad signatures, replayed envelopes, impersonated federation peers, subscription floods.
- **Limits are enforced before allocation.** Do not add an unbounded list, buffer or cache.
- **Never delete `host.db`** in code, scripts or docs; it holds `host_state.ed_seed` and every client pin.
- **Never log** envelope contents, keys or seeds.
- Keep the wire types UPPERCASE and the handshake backward compatible; relays are updated one at a time.
- One logical change per pull request.
- Do not hard-wrap prose in docs, templates or commit messages: one paragraph or list item is one source line.

## Pull requests

- Describe the protocol impact and the rollout order.
- State what you verified (`dart analyze`, `flutter test`, `host_probe.py`).
- CI fetches `soty-app` next to this repository and must be green.
- By contributing you agree your work is licensed under AGPL-3.0.
