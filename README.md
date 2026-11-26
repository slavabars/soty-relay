# Soty — релей-хост (dtm_host)

**Русский** · [English](README.en.md)

[![CI](https://github.com/slavabars/soty-relay/actions/workflows/ci.yml/badge.svg)](https://github.com/slavabars/soty-relay/actions/workflows/ci.yml) [![Nightly](https://github.com/slavabars/soty-relay/actions/workflows/nightly.yml/badge.svg)](https://github.com/slavabars/soty-relay/actions/workflows/nightly.yml) [![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

Операторский узел Soty: принимает зашифрованные конверты для офлайн-доставки, отдаёт их адресатам при подключении и работает трекером пиров. Плейнтекст и ключи устройства на хосте не появляются.

Установка, обновление и эксплуатация описаны в основном репозитории: https://github.com/slavabars/soty#quick-install-on-a-relay-machine

Установщики скачивают готовый `dtm_host.bin` из [Releases](https://github.com/slavabars/soty/releases) и **никогда** не перезаписывают `host.db`.

> **Не удаляйте `host.db`.** В нём `host_state.ed_seed` — Ed25519-идентичность хоста — и пины клиентов. Потеря означает `IDENTITY CHANGED` у всех.

## Сборка из исходников

`dtm_host` импортирует пакет `dtm_app` (общий код конвертов и криптографии), поэтому репозитории должны лежать рядом:

```text
workspace/
  app-src/   # github.com/slavabars/soty-app
  host/      # этот репозиторий
```

```bash
export PATH="$HOME/development/flutter/bin:$PATH"

cd host
flutter pub get
dart analyze
flutter test --no-pub
dart compile exe bin/dtm_host.dart -o build/dtm_host
```

## Релей для OpenWrt

В `relay-owrt/` лежит `dtm_relay` — статическая Go-реализация того же протокола для роутеров на musl (mipsel, mips, armv7, aarch64, x86_64). Она не заменяет `dtm_host`: серверный хост остаётся на Dart/SQLite, а роутер обслуживает свою LAN и по умолчанию не открывает исходящих соединений.

```bash
cd relay-owrt
go test ./...
VERSION=1.7.20+38 ./openwrt/build-bundle.sh
```

`dist/dtm_relay-<version>-ipk.tar.gz` содержит пять `.ipk`, `SHA256SUMS` и `README.txt`. Установка, UCI и ограничения — в [`relay-owrt/README.md`](relay-owrt/README.md); в релизах Soty этот bundle публикуется как `dtm_relay-X.Y.Z+N-ipk.tar.gz`.

## Безопасность

- Модель угроз: [`docs/threat_model.md`](docs/threat_model.md).
- Как сообщить об уязвимости: [`SECURITY.md`](SECURITY.md) — **не** через публичный issue.
- Лимиты на соединения, подписки, размер кадра и gossip window применяются до выделения памяти.

## Участие

[`CONTRIBUTING.md`](CONTRIBUTING.md), [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Лицензия

AGPL-3.0, см. [`LICENSE`](LICENSE) и [`NOTICE`](NOTICE).
