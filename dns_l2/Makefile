#
# Copyright (C) 2018
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# Auth:lyj051031448@163.com
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=sdns_l2
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/$(PKG_NAME)
  SUBMENU:=Other modules
  TITLE:=L2 smart dns
  DEPENDS:=
  FILES:=$(PKG_BUILD_DIR)/$(PKG_NAME).ko
  KCONFIG:=
endef

define KernelPackage/$(PKG_NAME)/description
 Kernel module for L2 smart dns
endef

# EXTRA_KCONFIG:= \
	CONFIG_UP_DATA=y

EXTRA_CFLAGS:= \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=m,%,$(filter %=m,$(EXTRA_KCONFIG)))) \
	$(patsubst CONFIG_%, -DCONFIG_%=1, $(patsubst %=y,%,$(filter %=y,$(EXTRA_KCONFIG)))) \

MAKE_OPTS:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	SUBDIRS="$(PKG_BUILD_DIR)" \
	EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
	$(EXTRA_KCONFIG)

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		modules
endef

$(eval $(call KernelPackage,$(PKG_NAME)))
