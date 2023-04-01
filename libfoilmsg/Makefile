# -*- Mode: makefile-gmake -*-

.PHONY: clean distclean all debug release coverage pkgconfig
.PHONY: print_debug_lib print_release_lib print_coverage_lib

#
# Required packages
#

PKGS = libglibutil glib-2.0 gobject-2.0

#
# Default target
#

all: debug release 

#
# Library name
#

NAME = foilmsg
LIB_NAME = lib$(NAME)
LIB = $(LIB_NAME).a

#
# Sources
#

SRC = \
  foilmsg_encrypt.c \
  foilmsg_decrypt.c

#
# Directories
#

SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
DEBUG_BUILD_DIR = $(BUILD_DIR)/debug
RELEASE_BUILD_DIR = $(BUILD_DIR)/release
COVERAGE_BUILD_DIR = $(BUILD_DIR)/coverage
LIBFOIL_DIR = ../libfoil
LIBFOIL_INCLUDE_DIR = $(LIBFOIL_DIR)/include

#
# Library version
#

VERSION_FILE = $(LIBFOIL_INCLUDE_DIR)/foil_version.h
get_version = $(shell grep -E '^ *\#define +FOIL_VERSION_$1 +[0-9]+$$' $(VERSION_FILE) | sed 's/  */ /g' | cut -d ' ' -f 3)

VERSION_MAJOR = $(call get_version,MAJOR)
VERSION_MINOR = $(call get_version,MINOR)
VERSION_RELEASE = $(call get_version,RELEASE)

# Full version
PCVERSION = $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_RELEASE)

#
# Tools and flags
#

CC = $(CROSS_COMPILE)gcc
ARFLAGS = rc
WARNINGS = -Wall -Wstrict-aliasing -Wunused-result
INCLUDES = -I$(INCLUDE_DIR) -I$(SRC_DIR) -I$(LIBFOIL_INCLUDE_DIR)
BASE_FLAGS = -fPIC
FULL_CFLAGS = $(BASE_FLAGS) $(CFLAGS) $(DEFINES) $(WARNINGS) $(INCLUDES) \
  -DGLIB_VERSION_MAX_ALLOWED=GLIB_VERSION_2_32 \
  -DGLIB_VERSION_MIN_REQUIRED=GLIB_VERSION_MAX_ALLOWED \
  -MMD -MP $(shell pkg-config --cflags $(PKGS))
DEBUG_FLAGS = -g
RELEASE_FLAGS =
COVERAGE_FLAGS = -g

KEEP_SYMBOLS ?= 0
ifneq ($(KEEP_SYMBOLS),0)
RELEASE_FLAGS += -g
endif

DEBUG_CFLAGS = $(FULL_CFLAGS) $(DEBUG_FLAGS) -DDEBUG
RELEASE_CFLAGS = $(FULL_CFLAGS) $(RELEASE_FLAGS) -O2
COVERAGE_CFLAGS = $(FULL_CFLAGS) $(COVERAGE_FLAGS) --coverage

#
# Files
#

PKGCONFIG = $(BUILD_DIR)/$(LIB_NAME).pc
DEBUG_OBJS = $(SRC:%.c=$(DEBUG_BUILD_DIR)/%.o)
RELEASE_OBJS = $(SRC:%.c=$(RELEASE_BUILD_DIR)/%.o)
COVERAGE_OBJS = $(SRC:%.c=$(COVERAGE_BUILD_DIR)/%.o)

DEBUG_LIB = $(DEBUG_BUILD_DIR)/$(LIB)
RELEASE_LIB = $(RELEASE_BUILD_DIR)/$(LIB)
COVERAGE_LIB = $(COVERAGE_BUILD_DIR)/$(LIB)

#
# Dependencies
#

DEPS = $(DEBUG_OBJS:%.o=%.d) $(RELEASE_OBJS:%.o=%.d) $(COVERAGE_OBJS:%.o=%.d)
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(DEPS)),)
-include $(DEPS)
endif
endif

$(PKGCONFIG): | $(BUILD_DIR)
$(DEBUG_OBJS) $(DEBUG_LIB): | $(DEBUG_BUILD_DIR)
$(RELEASE_OBJS) $(RELEASE_LIB): | $(RELEASE_BUILD_DIR)
$(COVERAGE_OBJS) $(COVERAGE_LIB): | $(COVERAGE_BUILD_DIR)

#
# Rules
#

debug: $(DEBUG_LIB)

release: $(RELEASE_LIB)

coverage: $(COVERAGE_LIB)

pkgconfig: $(PKGCONFIG)

print_debug_lib:
	@echo $(DEBUG_LIB)

print_release_lib:
	@echo $(RELEASE_LIB)

print_coverage_lib:
	@echo $(COVERAGE_LIB)

distclean: clean

clean:
	rm -f *~ $(SRC_DIR)/*~ $(INCLUDE_DIR)/*~
	rm -fr $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $@

$(DEBUG_BUILD_DIR):
	mkdir -p $@

$(RELEASE_BUILD_DIR):
	mkdir -p $@

$(COVERAGE_BUILD_DIR):
	mkdir -p $@

$(DEBUG_BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -c $(DEBUG_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(RELEASE_BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -c $(RELEASE_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(COVERAGE_BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -c $(COVERAGE_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(DEBUG_LIB): $(DEBUG_BUILD_DIR) $(DEBUG_OBJS)
	$(AR) $(ARFLAGS) $@ $(DEBUG_OBJS)
	ranlib $@

$(RELEASE_LIB): $(RELEASE_BUILD_DIR) $(RELEASE_OBJS)
	$(AR) $(ARFLAGS) $@ $(RELEASE_OBJS)
	ranlib $@

$(COVERAGE_LIB): $(COVERAGE_BUILD_DIR) $(COVERAGE_OBJS)
	$(AR) $(ARFLAGS) $@ $(COVERAGE_OBJS)
	ranlib $@

#
# LIBDIR usually gets substituted with arch specific dir.
# It's relative in deb build and can be whatever in rpm build.
#

LIBDIR ?= usr/lib
ABS_LIBDIR := $(shell echo /$(LIBDIR) | sed -r 's|/+|/|g')

$(PKGCONFIG): $(LIB_NAME).pc.in Makefile
	sed -e 's|@version@|$(PCVERSION)|g' -e 's|@libdir@|$(ABS_LIBDIR)|g' $< > $@

#
# Install
#

INSTALL = install
INSTALL_DIRS = $(INSTALL) -d
INSTALL_FILES = $(INSTALL) -m 644

INSTALL_LIB_DIR = $(DESTDIR)$(ABS_LIBDIR)
INSTALL_INCLUDE_DIR = $(DESTDIR)/usr/include/$(NAME)
INSTALL_PKGCONFIG_DIR = $(DESTDIR)$(ABS_LIBDIR)/pkgconfig

install-dev: $(INSTALL_LIB_DIR) $(INSTALL_INCLUDE_DIR) $(INSTALL_PKGCONFIG_DIR)
	$(INSTALL_FILES) $(RELEASE_LIB) $(INSTALL_LIB_DIR)
	$(INSTALL_FILES) $(INCLUDE_DIR)/*.h $(INSTALL_INCLUDE_DIR)
	$(INSTALL_FILES) $(PKGCONFIG) $(INSTALL_PKGCONFIG_DIR)

$(INSTALL_LIB_DIR):
	$(INSTALL_DIRS) $@

$(INSTALL_INCLUDE_DIR):
	$(INSTALL_DIRS) $@

$(INSTALL_PKGCONFIG_DIR):
	$(INSTALL_DIRS) $@
