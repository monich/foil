# -*- Mode: makefile-gmake -*-

.PHONY: clean install test

# This one could be substituted with arch specific dir
LIBDIR ?= /usr/lib
REL_LIBDIR := $(shell echo /$(LIBDIR) | sed -r 's|^/+||g')
GEN_INSTALL_FILES := \
  debian/libfoil.install \
  debian/libfoil-dev.install \
  debian/libfoilmsg-dev.install

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
	rm -fr $(BUILD_DIR) RPMS installroot documentation.list
	rm -fr debian/tmp debian/.debhelper
	rm -fr debian/foil-tools debian/libfoil
	rm -fr debian/libfoil-dev debian/libfoilmsg-dev
	rm -f debian/files debian/*.substvars debian/*~
	rm -f debian/*.debhelper.log debian/*.debhelper
	rm -f $(GEN_INSTALL_FILES)

pkgconfig:
	make LIBDIR="$(LIBDIR)" -C libfoil pkgconfig
	make LIBDIR="$(LIBDIR)" -C libfoilmsg pkgconfig

install: $(GEN_INSTALL_FILES)
	make DESTDIR="$(DESTDIR)" LIBDIR="$(LIBDIR)" -C libfoil install-dev
	make DESTDIR="$(DESTDIR)" LIBDIR="$(LIBDIR)" -C libfoilmsg install-dev
	make DESTDIR="$(DESTDIR)" LIBDIR="$(LIBDIR)" -C tools install

debian/%.install: debian/%.install.in
	sed 's|@LIBDIR@|$(REL_LIBDIR)|g' $< > $@

check:
	make -C test test
