# -*- Mode: makefile-gmake -*-

.PHONY: clean all debug release libfoil-release libfoil-debug

#
# Real test makefile defines EXE (and possibly SRC) and includes this one.
#

ifndef EXE
${error EXE not defined}
endif

ifndef SRC
SRC = $(EXE).c
endif

#
# Required packages
#

PKGS += libglibutil glib-2.0 gobject-2.0 openssl

#
# Default target
#

all: debug release

#
# Directories
#

SRC_DIR ?= .
LIB_DIR ?= ../../../libfoil
COMMON_DIR ?= ../../common
BUILD_DIR = build
DEBUG_BUILD_DIR = $(BUILD_DIR)/debug
RELEASE_BUILD_DIR = $(BUILD_DIR)/release

#
# Code coverage
#

ifndef GCOV
GCOV = 0
endif

ifneq ($(GCOV),0)
CFLAGS += --coverage
LDFLAGS += --coverage
SUBMAKE_OPTS += GCOV=1
endif

#
# Tools and flags
#

CC = $(CROSS_COMPILE)gcc
LD = $(CC)
WARNINGS = -Wall
INCLUDES += -I$(LIB_DIR)/include -I$(LIB_DIR)/src -I$(COMMON_DIR)
BASE_FLAGS = -fPIC
BASE_LDFLAGS = $(BASE_FLAGS) $(LDFLAGS)
BASE_CFLAGS = $(BASE_FLAGS) $(CFLAGS)
FULL_CFLAGS = $(BASE_CFLAGS) $(DEFINES) $(WARNINGS) $(INCLUDES) -MMD -MP \
  $(shell pkg-config --cflags $(PKGS))
FULL_LDFLAGS = $(BASE_LDFLAGS)
LIBS += $(shell pkg-config --libs $(PKGS))
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

DEBUG_OBJS = \
  $(COMMON_SRC:%.c=$(DEBUG_BUILD_DIR)/%.o) \
  $(SRC:%.c=$(DEBUG_BUILD_DIR)/%.o)
RELEASE_OBJS = \
  $(COMMON_SRC:%.c=$(RELEASE_BUILD_DIR)/%.o) \
  $(SRC:%.c=$(RELEASE_BUILD_DIR)/%.o)

ifdef SRC1
DEBUG_OBJS += $(SRC1:%.c=$(DEBUG_BUILD_DIR)/%.o)
RELEASE_OBJS += $(SRC1:%.c=$(RELEASE_BUILD_DIR)/%.o)
endif

ifdef SRC2
DEBUG_OBJS += $(SRC2:%.c=$(DEBUG_BUILD_DIR)/%.o)
RELEASE_OBJS += $(SRC2:%.c=$(RELEASE_BUILD_DIR)/%.o)
endif

DEBUG_LIB_FILE := $(shell $(QUIET_MAKE) -C $(LIB_DIR) print_debug_lib)
RELEASE_LIB_FILE := $(shell $(QUIET_MAKE) -C $(LIB_DIR) print_release_lib)
DEBUG_LIB_PATH := $(shell $(QUIET_MAKE) -C $(LIB_DIR) print_debug_path)
DEBUG_LIB := $(LIB_DIR)/$(DEBUG_LIB_FILE)
RELEASE_LIB := $(LIB_DIR)/$(RELEASE_LIB_FILE)
DEBUG_LIBS += $(DEBUG_LIB)
RELEASE_LIBS += $(RELEASE_LIB)

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

DEBUG_DEPS += libfoil-debug $(DEBUG_EXE)
RELEASE_DEPS += libfoil-release $(RELEASE_EXE)

debug: $(DEBUG_DEPS)

release: $(RELEASE_DEPS)

clean:
	rm -f *~
	rm -fr $(BUILD_DIR)

cleaner: clean
	@make -C $(LIB_DIR) clean

test_banner:
	@echo "===========" $(EXE) "=========== "

test: test_banner debug
	@LD_LIBRARY_PATH="$(LIB_DIR)/$(DEBUG_LIB_PATH)" $(DEBUG_EXE)

valgrind: test_banner debug
	@LD_LIBRARY_PATH="$(LIB_DIR)/$(DEBUG_LIB_PATH)" G_DEBUG=gc-friendly G_SLICE=always-malloc valgrind --tool=memcheck --leak-check=full --show-possibly-lost=no $(DEBUG_EXE)

$(DEBUG_BUILD_DIR):
	mkdir -p $@

$(RELEASE_BUILD_DIR):
	mkdir -p $@

$(DEBUG_BUILD_DIR)/%.o : $(COMMON_DIR)/%.c
	$(CC) -c $(DEBUG_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(RELEASE_BUILD_DIR)/%.o : $(COMMON_DIR)/%.c
	$(CC) -c $(RELEASE_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(DEBUG_BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -c $(DEBUG_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(RELEASE_BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -c $(RELEASE_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

ifdef SRC1
$(DEBUG_BUILD_DIR)/%.o : $(SRC1_DIR)/%.c
	$(CC) -c $(DEBUG_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(RELEASE_BUILD_DIR)/%.o : $(SRC1_DIR)/%.c
	$(CC) -c $(RELEASE_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@
endif

ifdef SRC2
$(DEBUG_BUILD_DIR)/%.o : $(SRC2_DIR)/%.c
	$(CC) -c $(DEBUG_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(RELEASE_BUILD_DIR)/%.o : $(SRC2_DIR)/%.c
	$(CC) -c $(RELEASE_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@
endif

$(DEBUG_EXE): $(DEBUG_LIBS) $(DEBUG_BUILD_DIR) $(DEBUG_OBJS)
	$(LD) $(DEBUG_LDFLAGS) $(DEBUG_OBJS) $(DEBUG_LIBS) $(LIBS) -o $@

$(RELEASE_EXE): $(RELEASE_LIBS) $(RELEASE_BUILD_DIR) $(RELEASE_OBJS)
	$(LD) $(RELEASE_LDFLAGS) $(RELEASE_OBJS) $(RELEASE_LIBS) $(LIBS) -o $@
ifeq ($(KEEP_SYMBOLS),0)
	strip $@
endif

libfoil-debug:
	@make $(SUBMAKE_OPTS) -C $(LIB_DIR) debug

libfoil-release:
	@make $(SUBMAKE_OPTS) -C $(LIB_DIR) release
