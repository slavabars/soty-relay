VERSION ?= 0.1.0
GO ?= go
DIST ?= dist

.PHONY: all build test vet ipk luci bundle clean

all: vet test build

build:
	CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath -ldflags="-s -w" \
		-o $(DIST)/dtm_relay ./cmd/dtm_relay

test:
	$(GO) test -mod=vendor ./...

vet:
	$(GO) vet -mod=vendor ./...

ipk:
	VERSION=$(VERSION) ./openwrt/build-ipk.sh all

luci:
	VERSION=$(VERSION) ./openwrt/build-luci-ipk.sh

bundle:
	VERSION=$(VERSION) ./openwrt/build-bundle.sh

clean:
	rm -rf $(DIST)
