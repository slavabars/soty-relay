# OpenWrt package for dtm_relay.
#
# This is the canonical OpenWrt buildroot package (feed layout). The tested
# path on a plain Linux host is openwrt/build-ipk.sh, which cross-builds the
# static binary and assembles an installable .ipk without an OpenWrt SDK.
#
# To use this feed package, put this directory under package/dtm_relay of an
# OpenWrt buildroot checkout with the relay-owrt source one level above
# `openwrt/` (the repository layout used here); golang.mk then compiles it
# with the target toolchain.

include $(TOPDIR)/rules.mk

PKG_NAME:=dtm_relay
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=AGPL-3.0-or-later
PKG_MAINTAINER:=Soty <soty@dcns.ru>

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_USE_MIPS16:=0

GO_PKG:=github.com/slavabars/soty-relay/relay-owrt
GO_PKG_BUILD_PKG:=github.com/slavabars/soty-relay/relay-owrt/cmd/dtm_relay
GO_PKG_INSTALL_ALL:=0
GO_PKG_LDFLAGS:=-s -w
GO_PKG_LDFLAGS_X:=main.version=$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/golang.mk

RELAY_SRC:=$(realpath $(CURDIR)/../..)

define Package/dtm_relay
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Soty LAN relay and tracker
  URL:=https://github.com/slavabars/soty-relay
endef

define Package/dtm_relay/description
 Opaque end-to-end encrypted envelope relay and peer tracker for Soty.
 Wire-compatible with dtm_host; federation is off by default.
endef

define Package/dtm_relay/conffiles
/etc/config/dtm_relay
endef

define Build/Prepare
	rm -rf $(PKG_BUILD_DIR)
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) $(RELAY_SRC)/go.mod $(RELAY_SRC)/go.sum $(RELAY_SRC)/vendor $(PKG_BUILD_DIR)/
	$(CP) $(RELAY_SRC)/cmd $(RELAY_SRC)/internal $(PKG_BUILD_DIR)/
endef

define Package/dtm_relay/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/dtm_relay $(1)/usr/bin/dtm_relay
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/dtm_relay.init $(1)/etc/init.d/dtm_relay
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/dtm_relay.config $(1)/etc/config/dtm_relay
endef

$(eval $(call BuildPackage,dtm_relay))
