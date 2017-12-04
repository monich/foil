# -*- Mode: makefile-gmake -*-

.PHONY: clean distclean all debug release
.PHONY: libfoil-debug libfoil-release
.PHONY: libfoilmsg-debug libfoilmsg-release

#
# Executable and source
#

EXE = foilmsg
SRC = $(EXE).c

#
# Required packages
#

PKGS += libglibutil glib-2.0 gobject-2.0

#
# Default target
#

all: debug release

#
# Directories
#

SRC_DIR = .
LIBFOIL_DIR = ../../libfoil
LIBFOILMSG_DIR = ../../libfoilmsg
BUILD_DIR = build
DEBUG_BUILD_DIR = $(BUILD_DIR)/debug
RELEASE_BUILD_DIR = $(BUILD_DIR)/release

#
# Application version
#

VERSION_FILE = ../../VERSION
VERSION_MAJOR = $(shell head -1 $(VERSION_FILE) | cut -f1 -d.)
VERSION_MINOR = $(shell head -1 $(VERSION_FILE) | cut -f2 -d.)
VERSION_RELEASE = $(shell head -1 $(VERSION_FILE) | cut -f3 -d.)
VERSION = $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_RELEASE)

#
# Tools and flags
#

CC = $(CROSS_COMPILE)gcc
LD = $(CC)
WARNINGS = -Wall
DEFINES += -DVERSION=$(VERSION)
INCLUDES = -I$(LIBFOIL_DIR)/include -I$(LIBFOILMSG_DIR)/include
BASE_FLAGS = -fPIC
BASE_LDFLAGS = $(BASE_FLAGS) $(LDFLAGS)
BASE_CFLAGS = $(BASE_FLAGS) $(CFLAGS)
FULL_CFLAGS = $(BASE_CFLAGS) $(DEFINES) $(WARNINGS) $(INCLUDES) -MMD -MP \
  $(shell pkg-config --cflags $(PKGS))
FULL_LDFLAGS = $(BASE_LDFLAGS)
LIBS = $(shell pkg-config --libs $(PKGS))
QUIET_MAKE = make --no-print-directory
DEBUG_FLAGS = -g
RELEASE_FLAGS =

ifndef KEEP_SYMBOLS
KEEP_SYMBOLS = 0
endif

ifneq ($(KEEP_SYMBOLS),0)
RELEASE_FLAGS += -g
SUBMAKE_OPTS += KEEP_SYMBOLS=1
endif

DEBUG_LDFLAGS = $(FULL_LDFLAGS) $(DEBUG_FLAGS)
RELEASE_LDFLAGS = $(FULL_LDFLAGS) $(RELEASE_FLAGS)
DEBUG_CFLAGS = $(FULL_CFLAGS) $(DEBUG_FLAGS) -DDEBUG
RELEASE_CFLAGS = $(FULL_CFLAGS) $(RELEASE_FLAGS) -O2

#
# Files
#

DEBUG_OBJS = $(SRC:%.c=$(DEBUG_BUILD_DIR)/%.o)
RELEASE_OBJS = $(SRC:%.c=$(RELEASE_BUILD_DIR)/%.o)

LIBFOIL_DEBUG = $(LIBFOIL_DIR)/$(shell $(QUIET_MAKE) -C $(LIBFOIL_DIR) print_debug_lib)
LIBFOIL_RELEASE = $(LIBFOIL_DIR)/$(shell $(QUIET_MAKE) -C $(LIBFOIL_DIR) print_release_lib)
LIBFOILMSG_DEBUG = $(LIBFOILMSG_DIR)/$(shell $(QUIET_MAKE) -C $(LIBFOILMSG_DIR) print_debug_lib)
LIBFOILMSG_RELEASE = $(LIBFOILMSG_DIR)/$(shell $(QUIET_MAKE) -C $(LIBFOILMSG_DIR) print_release_lib)

DEBUG_LIBS = $(LIBFOILMSG_DEBUG) $(LIBFOIL_DEBUG) $(LIBS)
RELEASE_LIBS = $(LIBFOILMSG_RELEASE) $(LIBFOIL_RELEASE) $(LIBS)

DEBUG_EXE = $(DEBUG_BUILD_DIR)/$(EXE)
RELEASE_EXE = $(RELEASE_BUILD_DIR)/$(EXE)

#
# Dependencies
#

DEPS = $(DEBUG_OBJS:%.o=%.d) $(RELEASE_OBJS:%.o=%.d)
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(DEPS)),)
-include $(DEPS)
endif
endif

$(DEBUG_OBJS): | $(DEBUG_BUILD_DIR)
$(RELEASE_OBJS): | $(RELEASE_BUILD_DIR)

$(DEBUG_EXE): | $(LIBFOILMSG_DEBUG) $(LIBFOIL_DEBUG)
$(RELEASE_EXE): | $(LIBFOILMSG_RELEASE) $(LIBFOIL_RELEASE)

$(LIBFOIL_DEBUG): | libfoil-debug
$(LIBFOIL_RELEASE): | libfoil-release

$(LIBFOILMSG_DEBUG): | libfoilmsg-debug
$(LIBFOILMSG_RELEASE): | libfoilmsg-release

#
# Rules
#

debug: $(DEBUG_EXE)

release: $(RELEASE_EXE)

distclean: clean

clean:
	rm -f *~
	rm -fr $(BUILD_DIR)

$(DEBUG_BUILD_DIR):
	mkdir -p $@

$(RELEASE_BUILD_DIR):
	mkdir -p $@

$(DEBUG_BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -c $(DEBUG_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(RELEASE_BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -c $(RELEASE_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(DEBUG_EXE): $(LIBFOILMSG_DEBUG) $(DEBUG_OBJS)
	$(LD) $(DEBUG_LDFLAGS) $(DEBUG_OBJS) $(DEBUG_LIBS) -o $@

$(RELEASE_EXE): $(LIBFOILMSG_RELEASE) $(RELEASE_OBJS)
	$(LD) $(RELEASE_LDFLAGS) $(RELEASE_OBJS) $(RELEASE_LIBS) -o $@
ifeq ($(KEEP_SYMBOLS),0)
	strip $@
endif

libfoil-debug:
	@make $(SUBMAKE_OPTS) -C $(LIBFOIL_DIR) debug

libfoil-release:
	@make $(SUBMAKE_OPTS) -C $(LIBFOIL_DIR) release

libfoilmsg-debug:
	@make $(SUBMAKE_OPTS) -C $(LIBFOILMSG_DIR) debug

libfoilmsg-release:
	@make $(SUBMAKE_OPTS) -C $(LIBFOILMSG_DIR) release

#
# Install
#

INSTALL = install
INSTALL_DIRS = $(INSTALL) -d
INSTALL_FILES = $(INSTALL) -m 755
INSTALL_BIN_DIR = $(DESTDIR)/usr/bin

install: $(INSTALL_BIN_DIR)
	$(INSTALL_FILES) $(RELEASE_EXE) $(INSTALL_BIN_DIR)

$(INSTALL_BIN_DIR):
	$(INSTALL_DIRS) $@
