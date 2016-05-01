# -*- Mode: makefile-gmake -*-

.PHONY: clean install test

all:
%:
	@$(MAKE) -C libfoil $*
	@$(MAKE) -C libfoilmsg $*
	@$(MAKE) -C foilmsg $*

clean:
	@make -C libfoil clean
	@make -C libfoilmsg clean
	@make -C foilmsg clean
	@make -C test clean
	rm -fr test/coverage/results test/coverage/*.gcov
	rm -f *~
	rm -fr $(BUILD_DIR) RPMS installroot
	rm -fr debian/tmp debian/libfoil debian/libfoil-dev
	rm -f documentation.list debian/files debian/*.substvars
	rm -f debian/*.debhelper.log debian/*.debhelper debian/*~

install:
	make DESTDIR="$(DESTDIR)" -C libfoil release pkgconfig install-dev
	make DESTDIR="$(DESTDIR)" -C foilmsg release install

check:
	make -C test test
