# LuCI application for the Soty router relay.
#
# This file is the canonical OpenWrt feed package. In a LuCI feed checkout it
# lives under applications/ and uses ../../luci.mk; a standalone feed can use
# $(TOPDIR)/feeds/luci/luci.mk. The tested local path is
# ../openwrt/build-luci-ipk.sh, which does not need an SDK.

include $(TOPDIR)/rules.mk

LUCI_TITLE:=Soty relay
LUCI_DESCRIPTION:=LuCI control panel for the Soty router relay (dtm_relay)
LUCI_DEPENDS:=+dtm_relay +uclient-fetch
LUCI_PKGARCH:=all
PKG_LICENSE:=AGPL-3.0-or-later

include $(TOPDIR)/feeds/luci/luci.mk

# See /LICENSE for more information.
