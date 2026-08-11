include $(TOPDIR)/rules.mk

PKG_NAME:=aamm-ng
PKG_VERSION:=0.1.0
PKG_RELEASE:=12

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/k2exe/aamm-ng.git
PKG_SOURCE_VERSION:=878b2cd8619fd0b39d2adf1c0b95a2557317bc35
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
 AAMM-NG provides authenticated management of AREDN alert messages
 using a privileged local daemon and separate unprivileged web service.
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

$(eval $(call BuildPackage,aamm-ng))
