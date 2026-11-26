[Русский](README.md) · **English**

# luci-app-dtm-relay

LuCI web panel for the `dtm_relay` router relay: service state, metrics and launch settings. It does not replace `dtm_relay` and does not change its protocol.

## What it shows

- **Overview**: running state, autostart, version, uptime; current and total connections, federation links, envelopes, peers, subscriptions, RSS, load1 and counters (received, relayed, rejected, duplicates, backfill, live).
- **Actions**: `Start`, `Stop`, `Restart`, a link to settings. Metrics refresh every 5 seconds.
- **Settings**: `enabled`, `port`, `announce`, `retention_days`, `max_connections`, `storage`, `path`, `federation`, `seeds`. The identity file is shown as a path only and is not editable.

## Install

Install it next to the relay:

```sh
opkg install dtm_relay_<version>-1_<arch>.ipk
opkg install luci-app-dtm-relay_<version>-1_all.ipk
```

Both packages are inside the release bundle `dtm_relay-X.Y.Z+N-ipk.tar.gz`. Open LuCI → **Services → Soty relay**.

## Metrics

The page calls the fixed helper `/usr/libexec/dtm-relay-status`, which reads the port from UCI and requests the local `http://127.0.0.1:<port>/status`. The browser never talks to the relay port directly, and the helper takes no arguments and never reads the seed.

## Security

- The ACL grants only `uci dtm_relay`, `luci.getInitList`/`setInitAction` and execution of the helper.
- `/etc/dtm-relay/identity` is never read or displayed.
- Federation is off by default; enabling it shows an outbound-connection warning.
- Back up the router before changing settings; never delete the identity key.

## Locales

The `po/<lang>` catalogs are compiled to `.lmo` at package build time and installed under `/usr/lib/lua/luci/i18n`. Currently `ru`, `de`, `zh-cn`, `es` and `fr` are shipped; other LuCI languages fall back to the English source. The Russian catalog covers every panel and menu string.

## Build

```sh
cd host/relay-owrt
VERSION=X.Y.Z+N ./openwrt/build-luci-ipk.sh
```

The result is `dist/luci-app-dtm-relay_<version>-1_all.ipk`. For OpenWrt buildroot, use this directory's `Makefile` in the LuCI feed.
