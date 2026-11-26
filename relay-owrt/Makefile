VERSION ?= 0.1.0
GO ?= go
DIST ?= dist

.PHONY: all build test vet ipk clean

all: vet test build

build:
	CGO_ENABLED=0 $(GO) build -mod=vendor -trimpath -ldflags="-s -w" \
		-o $(DIST)/dtm_relay ./cmd/dtm_relay

test:
	$(GO) test -mod=vendor ./...

vet:
	$(GO) vet -mod=vendor ./...

ipk:
	./openwrt/build-ipk.sh all

clean:
	rm -rf $(DIST)
