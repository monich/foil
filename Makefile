# -*- Mode: makefile-gmake -*-

.PHONY: clean install test

# This one could be substituted with arch specific dir
LIBDIR ?= /usr/lib
REL_LIBDIR := $(shell echo /$(LIBDIR) | sed -r 's|^/+||g')
GEN_INSTALL_FILES := debian/libfoil.install debian/libfoil-dev.install

all:
%:
	@$(MAKE) -C libfoil $*
	@$(MAKE) -C libfoilmsg $*
	@$(MAKE) -C tools $*

clean:
	@make -C libfoil clean
	@make -C libfoilmsg clean
	@make -C tools clean
	@make -C test clean
	rm -fr test/coverage/results test/coverage/*.gcov
	rm -f *~
	rm -fr $(BUILD_DIR) RPMS installroot
	rm -fr debian/tmp debian/libfoil debian/libfoil-dev
	rm -f documentation.list debian/files debian/*.substvars
	rm -f debian/*.debhelper.log debian/*.debhelper debian/*~
	rm -f $(GEN_INSTALL_FILES)

pkgconfig:
	make LIBDIR="$(LIBDIR)" -C libfoil pkgconfig

install: $(GEN_INSTALL_FILES)
	make DESTDIR="$(DESTDIR)" LIBDIR="$(LIBDIR)" -C libfoil install-dev
	make DESTDIR="$(DESTDIR)" LIBDIR="$(LIBDIR)" -C tools install

debian/%.install: debian/%.install.in
	sed 's|@LIBDIR@|$(REL_LIBDIR)|g' $< > $@

check:
	make -C test test
