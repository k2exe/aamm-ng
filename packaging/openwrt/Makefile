include $(TOPDIR)/rules.mk

PKG_NAME:=aamm-ng
PKG_VERSION:=0.1.3
PKG_RELEASE:=1

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/k2exe/aamm-ng.git
PKG_SOURCE_VERSION:=2aad96ef5f484a13583b09887187fa3353676d43
PKG_MIRROR_HASH:=skip

PKG_LICENSE:=Apache-2.0
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=K2EXE
PKG_BUILD_DEPENDS:=golang/host
PKG_BUILD_PARALLEL:=1
PKG_BUILD_FLAGS:=no-mips16

GO_PKG:=github.com/k2exe/aamm-ng
GO_PKG_BUILD_PKG:= \
	$(GO_PKG)/cmd/aamm-ng \
	$(GO_PKG)/cmd/aamm-ng-web

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/golang/golang-package.mk

define Package/aamm-ng
  SECTION:=net
  CATEGORY:=Network
  TITLE:=AREDN Alert Message Manager NG
  URL:=https://github.com/k2exe/aamm-ng
  DEPENDS:=$(GO_ARCH_DEPENDS)
  USERID:=aamm-ng:aamm-ng aamm-ng-web:aamm-ng-control
endef

define Package/aamm-ng/description
 AAMM-NG gives AREDN operators a web interface to discover mesh nodes
 and create, edit, and remove targeted alert messages with authenticated
 audit tracking.
endef

define Package/aamm-ng/install
	$(INSTALL_DIR) $(1)/usr/sbin

	$(INSTALL_BIN) \
		$(GO_PKG_BUILD_BIN_DIR)/aamm-ng \
		$(1)/usr/sbin/aamm-ng

	$(INSTALL_BIN) \
		$(GO_PKG_BUILD_BIN_DIR)/aamm-ng-web \
		$(1)/usr/sbin/aamm-ng-web

	$(INSTALL_DIR) $(1)/etc/init.d

	$(INSTALL_BIN) \
		./files/aamm-ng.init \
		$(1)/etc/init.d/aamm-ng

	$(INSTALL_BIN) \
		./files/aamm-ng-web.init \
		$(1)/etc/init.d/aamm-ng-web

	$(INSTALL_DIR) $(1)/etc/local/mesh-firewall

	$(INSTALL_BIN) \
		./files/aamm-ng-portal.firewall \
		$(1)/etc/local/mesh-firewall/60-aamm-ng-portal

	$(INSTALL_DIR) $(1)/www/cgi-bin/apps/AAMM-NG

	$(INSTALL_BIN) \
		./files/aamm-ng-app-admin \
		$(1)/www/cgi-bin/apps/AAMM-NG/admin

	$(INSTALL_DIR) $(1)/www/apps/AAMM-NG

	$(INSTALL_DATA) \
		./files/aamm-ng-icon.svg \
		$(1)/www/apps/AAMM-NG/icon.svg

	$(INSTALL_DATA) \
		./files/aamm-ng.css \
		$(1)/www/apps/AAMM-NG/aamm-ng.css

	$(INSTALL_DATA) \
		./files/aamm-ng.js \
		$(1)/www/apps/AAMM-NG/aamm-ng.js
endef

# Reload the firewall so that the portal rule is added now, and removed when
# the package is removed. A failed reload must not fail the install.
define Package/aamm-ng/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || /etc/init.d/firewall reload >/dev/null 2>&1 || true
exit 0
endef

define Package/aamm-ng/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || /etc/init.d/firewall reload >/dev/null 2>&1 || true
exit 0
endef

$(eval $(call BuildPackage,aamm-ng))
