[Русский](README.md) · **English**

# dtm_relay — Soty relay for OpenWrt

`dtm_relay` is a LAN relay and tracker for Soty on an OpenWrt router. It accepts only opaque encrypted envelopes, keeps them for offline delivery, serves subscribers and answers tracker requests. Its WebSocket protocol is byte-compatible with `dtm_host`, so the app joins the router with the same `soty://host?...` invite it uses for an internet relay.

The router is what makes the messenger work when there is no internet: devices on one LAN exchange messages through it without losing history when the sender goes offline.

## Why a separate Go implementation

`dart compile exe` produces a glibc binary and does not support musl, while a typical router runs musl/mipsel (MT7621) or musl/aarch64. `dtm_host` therefore does not run on a router. `dtm_relay` is built statically (`CGO_ENABLED=0`) and has no dependency on the router's shared libraries.

mips/mipsle requires `GOMIPS=softfloat` because most of those SoCs have no FPU; `openwrt/build-ipk.sh` passes the right flags.

## Build

```sh
cd relay-owrt
make test          # go test ./...
make               # vet + test + local binary in dist/
make ipk           # .ipk for mipsel_24kc, mips_24kc, aarch64, armv7, x86_64
```

One archive: `openwrt/build-ipk.sh mipsel_24kc`. The result is `dist/dtm_relay_0.1.0-1_<arch>.ipk`. The package has no dependencies: the binary is static.

`openwrt/Makefile` is the canonical OpenWrt buildroot package (feed layout). The tested path on a plain Linux host is `build-ipk.sh`; the buildroot variant requires the SDK and a layout where the sources sit next to the `openwrt/` directory.

## Install

```sh
opkg install dtm_relay_0.1.0-1_mipsel_24kc.ipk
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

Send it to a contact or open it on a device. The app adds the relay from the deep link and subscribes to it.

The port listens on `0.0.0.0` but is meant for the local network. Do not forward `ws://` to the internet: a public relay must sit behind `wss://` (nginx), otherwise the path can be read and rewritten, even though envelope contents stay encrypted.

## UCI options

| Option | Default | Meaning |
| --- | --- | --- |
| `enabled` | `1` | Start the relay |
| `port` | `3100` | WebSocket `/ws` port |
| `announce` | empty | Public `ws://`/`wss://` URL; defaults to `ws://<listen>:<port>/ws` |
| `identity` | `/etc/dtm-relay/identity` | Ed25519 seed file, mode `0600` |
| `retention_days` | `30` | How long envelopes for subscribed recipients are kept |
| `max_connections` | `128` | Simultaneous socket ceiling (hard maximum 512) |
| `storage` | `memory` | `memory` (RAM) or `disk` (journal on USB) |
| `path` | `/tmp/dtm-relay` | Journal directory for `storage=disk` |
| `federation` | `0` | Federation with internet relays, off by default |
| `seeds` | empty | Space-separated seed addresses, each `url` or `url|pk` |

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

With `federation=0` any `dtm-host` claim in HELLO stays an ordinary client: other devices' envelopes are never forwarded to it. With `federation=1` the same rules as `dtm_host` apply: the relay role is granted, not claimed, a seeded key is pinned, and anti-entropy runs over `WANT`/`HAVE`/`GET`/`ENVELOPES` and `NETWORK`.

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

## Verification

```sh
go test ./...
python3 ../scripts/host_probe.py ws://192.168.1.1:3100/ws <pinned-ed25519>
```

`host_probe.py` performs the same handshake and key check the app does when adding a relay. For an end-to-end check with the app's real code (not just a Go client), use `../host/tool/interop_relay.dart`: it connects to a running relay, subscribes, publishes and receives an envelope built by `createEnvelopeForPubKey`, and checks presence, `PEER_LIST` and live delivery.

## Not in this version

- Media over radio and all LoRa features are separate tasks (`T-108`…`T-118`); the `dtm_lora_gw` gateway lives separately.
- TLS termination on the router itself: `wss://` is an nginx concern, the relay stays on loopback.
- A full replacement for a server-side `dtm_host`: the server host has SQLite, a Merkle audit trail and a larger connection ceiling; a router serves one LAN.
