# -*- Mode: makefile-gmake -*-

.PHONY: clean distclean all debug release
.PHONY: libfoil-debug libfoil-release
.PHONY: libfoilmsg-debug libfoilmsg-release

#
# Executable and source
#

EXE = foilpng
SRC = $(EXE).c

#
# Required packages
#

PKGS += libpng libglibutil glib-2.0 gobject-2.0

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
# Tools and flags
#

CC = $(CROSS_COMPILE)gcc
LD = $(CC)
WARNINGS = -Wall
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

ifndef HAVE_MAGIC
HAVE_MAGIC = 1
endif

ifneq ($(HAVE_MAGIC),0)
DEFINES += -DHAVE_MAGIC
LIBS += -lmagic
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

#
# Rules
#

DEBUG_EXE = $(DEBUG_BUILD_DIR)/$(EXE)
RELEASE_EXE = $(RELEASE_BUILD_DIR)/$(EXE)

DEBUG_DEPS += libfoil-debug libfoilmsg-debug $(DEBUG_EXE)
RELEASE_DEPS += libfoil-release libfoilmsg-release $(RELEASE_EXE)

debug: $(DEBUG_DEPS)

release: $(RELEASE_DEPS)

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

$(DEBUG_EXE): $(DEBUG_OBJS)
	$(LD) $(DEBUG_LDFLAGS) $(DEBUG_OBJS) $(DEBUG_LIBS) -o $@

$(RELEASE_EXE): $(RELEASE_OBJS)
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
