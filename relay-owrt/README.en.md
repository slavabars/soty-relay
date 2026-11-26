[Русский](README.md) · **English**

# dtm_relay — Soty relay for OpenWrt

`dtm_relay` is a LAN relay and tracker for Soty on an OpenWrt router. It accepts only opaque encrypted envelopes, keeps them for offline delivery, serves subscribers and answers tracker requests. Its WebSocket protocol is byte-compatible with `dtm_host`, so the app joins the router with the same `soty://host?...` invite it uses for an internet relay.

The router is what makes the messenger work when there is no internet: devices on one LAN exchange messages through it without losing history when the sender goes offline.

## Why a separate Go implementation

`dart compile exe` produces a glibc binary and does not support musl, while a typical router runs musl/mipsel (MT7621) or musl/aarch64. `dtm_host` therefore does not run on a router. `dtm_relay` is built statically (`CGO_ENABLED=0`) and has no dependency on the router's shared libraries.

mips/mipsle requires `GOMIPS=softfloat` because most of those SoCs have no FPU; `openwrt/build-ipk.sh` passes the right flags.

## Build

```sh
cd host/relay-owrt
make test          # go test ./...
make               # vet + test + local binary in dist/
make ipk           # .ipk for mipsel_24kc, mips_24kc, aarch64, armv7, x86_64

# release bundle: 5 architectures + LuCI + SHA256SUMS + README.txt
VERSION=X.Y.Z+N ./openwrt/build-bundle.sh

# LuCI panel only
VERSION=X.Y.Z+N ./openwrt/build-luci-ipk.sh
```

One package: `openwrt/build-ipk.sh mipsel_24kc` → `dist/dtm_relay_<version>-1_<arch>.ipk`. The package has no dependencies: the binary is static. The `.ipk` is a gzip-compressed tar (`debian-binary`, `control.tar.gz`, `data.tar.gz`), the format opkg reads on OpenWrt 24.10+; older releases should use the buildroot package, which lets OpenWrt produce its own format.

`openwrt/Makefile` is the canonical OpenWrt buildroot package (feed layout). The tested path on a plain Linux host is `build-ipk.sh`; the buildroot variant requires the SDK and a layout where the sources sit next to the `openwrt/` directory.

## Install

```sh
tar -xzf dtm_relay-X.Y.Z+N-ipk.tar.gz
sha256sum -c SHA256SUMS
opkg install dtm_relay_X.Y.Z+N-1_mipsel_24kc.ipk
opkg install luci-app-dtm-relay_X.Y.Z+N-1_all.ipk
uci set dtm_relay.relay.enabled='1'
uci set dtm_relay.relay.port='3100'
uci commit dtm_relay
/etc/init.d/dtm_relay enable
/etc/init.d/dtm_relay start
```

The log and stdout print an invite:

```text
soty://host?addr=ws%3A%2F%2F192.168.1.1%3A3100%2Fws&pk=<ed25519>
```

Send it to a contact or open it on a device. The app adds the relay from the deep link and subscribes to it. When `announce` is empty the init script substitutes the `br-lan` address (falling back to the UCI LAN address); the binary itself defaults to `ws://127.0.0.1:<port>/ws` when run by hand, so pass `--announce` for a LAN.

The port listens on `0.0.0.0` but is meant for the local network; the OpenWrt `lan` zone accepts input by default, so a firewall rule is only needed after you tighten it. Do not forward `ws://` to the internet: a public relay must sit behind `wss://` (nginx), otherwise the path can be read and rewritten, even though envelope contents stay encrypted.

## UCI options

| Option | Default | Meaning |
| --- | --- | --- |
| `enabled` | `1` | Start the relay |
| `port` | `3100` | WebSocket `/ws` port |
| `announce` | auto | Public `ws://`/`wss://` URL; when empty the init script uses the router LAN address (`ws://<lan-ip>:<port>/ws`) |
| `identity` | `/etc/dtm-relay/identity` | Ed25519 seed file, mode `0600` |
| `retention_days` | `30` | How long envelopes for subscribed recipients are kept |
| `max_connections` | `128` | Simultaneous socket ceiling (hard maximum 512) |
| `storage` | `memory` | `memory` (RAM) or `disk` (journal on USB) |
| `path` | `/tmp/dtm-relay` | Journal directory for `storage=disk` |
| `federation` | `0` | Upstream bridge to seed relays, off by default |
| `seeds` | empty | Space-separated seed addresses, each `url` or `url\|pk` |

## Storage and identity

The queue lives in RAM by default. That is deliberate: router flash wears out, and 30-day retention is impossible in 128 MiB anyway. A reboot loses the queue, but subscriptions and devices reconnect on their own.

`storage=disk` enables an append-only `envelopes.ndjson` journal under `path` (for example on a USB drive). The journal is rewritten on prune and shutdown, so it does not grow forever. It is not `fsync`ed per write: a sudden power loss can lose the newest envelopes, which is the accepted price for flash lifetime.

The identity always lives in `/etc` (default `/etc/dtm-relay/identity`) and is **never deleted**: clients pin the Ed25519 key, and losing it means `IDENTITY CHANGED` for everyone who added this relay. The file is created with mode `0600` and its directory with `0700`. A corrupt file is a startup error, never a reason to generate a new key.

In-memory storage is hard-capped at 20 000 envelopes and 32 MiB; the oldest are evicted first. That is a cache bound, not a retention promise: signed Merkle roots cover age- and window-based pruning only.

## Federation

By default the relay serves only its LAN and **opens no outbound connections**. A router must not become an open relay without its owner's knowledge.

Federation is explicit:

```sh
uci set dtm_relay.relay.federation='1'
uci set dtm_relay.relay.seeds='wss://soty.su/soty-ws|fad55cc7...'
uci commit dtm_relay
/etc/init.d/dtm_relay restart
```

A router behind NAT cannot be accepted by an internet host as a federated relay: `dtm_host` verifies that `announce` resolves to the socket address, while the router announces a LAN address. `dtm_relay` therefore works as an **upstream client** of the seed host:

- it subscribes the seed to the X25519 keys of its LAN devices (up to 16 keys) with `SUBSCRIBE`;
- it receives envelopes and live slices for those keys from the seed and delivers them to local subscribers;
- it publishes LAN-originated messages upstream with `PUBLISH`/`PUBLISH_LIVE`, so they reach internet devices.

With `federation=0` the router opens no outbound connections and serves only its LAN. With `federation=1` and a seed, the bridge is active; the router needs no public address or port. Pin the seed: `wss://soty.su/soty-ws|<ed25519>`. Limit: 16 LAN keys per seed; more devices need a second seed or a future protocol extension.

## Endpoints

| Path | Purpose |
| --- | --- |
| `/ws` | Relay and tracker protocol (WebSocket) |
| `/status` | Aggregate counters and process health, no keys or addresses |
| `/healthz` | `{"ok":true}` |
| `/directory` | Public relay entry: own address and Ed25519, plus internet-reachable federated members |

## Security and limits

- Envelopes are opaque: the relay verifies the signature and id but never decrypts or logs ciphertext or plaintext.
- The verification order is fixed: rate limit → clock skew → Ed25519 → id → dedup.
- Every number is copied from `app-src/lib/core/security_limits.dart` into `internal/limits`; a divergence shows up in the diff. Frame 256 KiB, 16 subscription keys per connection, 256 gossip items, hop ceiling 3, 64 presence keys, 8192 known peers.
- Duplicate ids are dropped, the `since` window is clamped to 30 days, and subscriptions and peers have TTLs.
- `/status` contains no identity, client addresses or envelope metadata.

## LuCI

The `luci-app-dtm-relay` package adds **Services → Soty relay** to LuCI: service state, metrics, `Start`/`Stop`/`Restart` and a UCI form. Metrics come from the local `/status` through `/usr/libexec/dtm-relay-status`; the seed is never read. The package is noarch, installs next to the relay and does not change the protocol. See [`luci-app-dtm-relay/README.en.md`](luci-app-dtm-relay/README.en.md).

## Verification

```sh
go test ./...
python3 ../../scripts/host_probe.py ws://192.168.1.1:3100/ws <pinned-ed25519>
```

`host_probe.py` performs the same handshake and key check the app does when adding a relay. For an end-to-end check with the app's real code (not just a Go client), use `../tool/interop_relay.dart`: it connects to a running relay, subscribes, publishes and receives an envelope built by `createEnvelopeForPubKey`, and checks presence, `PEER_LIST` and live delivery.

## Back up before a router test

Any test on a working router starts with a verified backup: `sysupgrade -b`, a copy of the overlay upper, `/etc`, the package list and SHA-256. Install only after the backup is downloaded and checked; a rollback must restore the same `uci export` and `opkg list-installed`. The finished bundle is published in Soty releases as `dtm_relay-X.Y.Z+N-ipk.tar.gz`; individual `.ipk` files are not attached to a release.

## Not in this version

- Media over radio and all LoRa features are separate tasks (`T-108`…`T-118`); the `dtm_lora_gw` gateway lives separately.
- TLS termination on the router itself: `wss://` is an nginx concern, the relay stays on loopback.
- A full replacement for a server-side `dtm_host`: the server host has SQLite, a Merkle audit trail and a larger connection ceiling; a router serves one LAN.
