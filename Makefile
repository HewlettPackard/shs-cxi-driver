# SPDX-License-Identifier: GPL-2.0
# Copyright 2020 Hewlett Packard Enterprise Development LP

export TOPDIR := $(if $(TOPDIR),$(TOPDIR),$(shell readlink -e .))

SUBDIRS = drivers/net/ethernet/hpe/ss1 ucxi tests/pkt_test

all clean: $(SUBDIRS)
	rm -rf WORKSPACE
	rm -rf RPMS
	rm -f vars.sh

$(SUBDIRS)::
	$(MAKE) -C $@ $(MAKECMDGOALS)

# Run the testsuite
check:
	make -C tests prove

atu-test:
	make -C tests t0400-atu.t

PACKAGE = cray-cxi-driver
VERSION = 0.9

DIST_FILES = \
	drivers/net/ethernet/hpe/ss1/*.c \
	drivers/net/ethernet/hpe/ss1/*.h \
	drivers/net/ethernet/hpe/ss1/Makefile \
	drivers/net/ethernet/hpe/ss1/Kbuild \
	ucxi/*.c \
	ucxi/*.h \
	ucxi/Makefile \
	include/ \
	cray-cxi-driver.spec \
	dkms.conf.in \
	50-cxi-driver.rules \
	Makefile \
	README \
	README.eth

.PHONY: dist

dist: $(DIST_FILES)
	tar czf $(PACKAGE)-$(VERSION).tar.gz --transform 's/^/$(PACKAGE)-$(VERSION)\//' $(DIST_FILES)

$(PACKAGE)-$(VERSION).tar.gz: dist

rpm: $(PACKAGE)-$(VERSION).tar.gz
	BUILD_METADATA='0' rpmbuild -ta $<
