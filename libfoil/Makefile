# -*- Mode: makefile-gmake -*-

.PHONY: clean distclean all debug release

#
# Required packages
#

IMPL = openssl
IMPL_PKG = libcrypto
PKGS = $(IMPL_PKG) libglibutil glib-2.0 gobject-2.0

#
# Default target
#

all: debug release pkgconfig

#
# Library version
#

VERSION_FILE = ../VERSION
VERSION_MAJOR = $(shell head -1 $(VERSION_FILE) | cut -f1 -d.)
VERSION_MINOR = $(shell head -1 $(VERSION_FILE) | cut -f2 -d.)
VERSION_RELEASE = $(shell head -1 $(VERSION_FILE) | cut -f3 -d.)

# Version for pkg-config
PCVERSION = $(VERSION_MAJOR).$(VERSION_MINOR).$(VERSION_RELEASE)

#
# Library name
#

NAME = foil
LIB_NAME = lib$(NAME)
LIB_DEV_SYMLINK = $(LIB_NAME).so
LIB_SYMLINK1 = $(LIB_DEV_SYMLINK).$(VERSION_MAJOR)
LIB_SYMLINK2 = $(LIB_SYMLINK1).$(VERSION_MINOR)
LIB_SONAME = $(LIB_SYMLINK1)
LIB = $(LIB_SONAME).$(VERSION_MINOR).$(VERSION_RELEASE)

#
# Sources
#

SRC = \
  foil_asn1.c \
  foil_cipher.c \
  foil_cipher_aes.c \
  foil_cipher_sync.c \
  foil_digest.c \
  foil_digest_md5.c \
  foil_digest_sha1.c \
  foil_digest_sha256.c \
  foil_input.c \
  foil_input_base64.c \
  foil_input_cipher.c \
  foil_input_digest.c \
  foil_input_file.c \
  foil_input_mem.c \
  foil_input_range.c \
  foil_key.c \
  foil_key_aes.c \
  foil_key_rsa_private.c \
  foil_key_rsa_public.c \
  foil_output.c \
  foil_output_base64.c \
  foil_output_digest.c \
  foil_output_file.c \
  foil_output_mem.c \
  foil_private_key.c \
  foil_random.c \
  foil_sign.c \
  foil_util.c

IMPL_SRC = \
  foil_openssl_cipher_aes_cbc_decrypt.c \
  foil_openssl_cipher_aes_cbc_encrypt.c \
  foil_openssl_cipher_rsa_decrypt.c \
  foil_openssl_cipher_rsa_encrypt.c \
  foil_openssl_digest_md5.c \
  foil_openssl_digest_sha1.c \
  foil_openssl_digest_sha256.c \
  foil_openssl_key_rsa_private.c \
  foil_openssl_key_rsa_public.c \
  foil_openssl_random.c

#
# Directories
#

SRC_DIR = src
IMPL_SRC_DIR = src/$(IMPL)
INCLUDE_DIR = include
BUILD_DIR = build
DEBUG_BUILD_DIR = $(BUILD_DIR)/debug
RELEASE_BUILD_DIR = $(BUILD_DIR)/release
IMPL_DEBUG_BUILD_DIR = $(DEBUG_BUILD_DIR)/$(IMPL)
IMPL_RELEASE_BUILD_DIR = $(RELEASE_BUILD_DIR)/$(IMPL)

#
# Code coverage
#

ifndef GCOV
GCOV = 0
endif

ifneq ($(GCOV),0)
CFLAGS += --coverage
LDFLAGS += --coverage
endif

#
# Tools and flags
#

CC = $(CROSS_COMPILE)gcc
LD = $(CC)
WARNINGS = -Wall
INCLUDES = -I$(INCLUDE_DIR) -I$(SRC_DIR)
BASE_FLAGS = -fPIC
FULL_CFLAGS = $(BASE_FLAGS) $(CFLAGS) $(DEFINES) $(WARNINGS) $(INCLUDES) \
  -MMD -MP $(shell pkg-config --cflags $(PKGS))
FULL_LDFLAGS = $(BASE_FLAGS) $(LDFLAGS) -shared -Wl,-soname,$(LIB_SONAME) \
  $(shell pkg-config --libs $(PKGS))
DEBUG_FLAGS = -g
RELEASE_FLAGS =

ifndef KEEP_SYMBOLS
KEEP_SYMBOLS = 0
endif

ifneq ($(KEEP_SYMBOLS),0)
RELEASE_FLAGS += -g
endif

DEBUG_LDFLAGS = $(FULL_LDFLAGS) $(DEBUG_FLAGS)
RELEASE_LDFLAGS = $(FULL_LDFLAGS) $(RELEASE_FLAGS)
DEBUG_CFLAGS = $(FULL_CFLAGS) $(DEBUG_FLAGS) -DDEBUG
RELEASE_CFLAGS = $(FULL_CFLAGS) $(RELEASE_FLAGS) -O2

#
# Files
#

PKGCONFIG = $(BUILD_DIR)/$(LIB_NAME).pc
BASE_DEBUG_OBJS = $(SRC:%.c=$(DEBUG_BUILD_DIR)/%.o)
BASE_RELEASE_OBJS = $(SRC:%.c=$(RELEASE_BUILD_DIR)/%.o)
IMPL_DEBUG_OBJS = $(IMPL_SRC:%.c=$(IMPL_DEBUG_BUILD_DIR)/%.o)
IMPL_RELEASE_OBJS = $(IMPL_SRC:%.c=$(IMPL_RELEASE_BUILD_DIR)/%.o)

DEBUG_OBJS = $(BASE_DEBUG_OBJS) $(IMPL_DEBUG_OBJS)
RELEASE_OBJS = $(BASE_RELEASE_OBJS) $(IMPL_RELEASE_OBJS)

#
# Dependencies
#

DEPS = $(DEBUG_OBJS:%.o=%.d) $(RELEASE_OBJS:%.o=%.d)
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(DEPS)),)
-include $(DEPS)
endif
endif

$(DEBUG_OBJS) $(DEBUG_LIB): | $(DEBUG_BUILD_DIR)
$(RELEASE_OBJS) $(RELEASE_LIB): | $(RELEASE_BUILD_DIR)
$(IMPL_DEBUG_OBJS): | $(IMPL_DEBUG_BUILD_DIR)
$(IMPL_RELEASE_OBJS): | $(IMPL_RELEASE_BUILD_DIR)

#
# Rules
#

DEBUG_LIB = $(DEBUG_BUILD_DIR)/$(LIB)
RELEASE_LIB = $(RELEASE_BUILD_DIR)/$(LIB)
DEBUG_LINK = $(DEBUG_BUILD_DIR)/$(LIB_SYMLINK1)
RELEASE_LINK = $(RELEASE_BUILD_DIR)/$(LIB_SYMLINK1)

debug: $(DEBUG_LIB) $(DEBUG_LINK)

release: $(RELEASE_LIB) $(RELEASE_LINK)

pkgconfig: $(PKGCONFIG)

print_debug_lib:
	@echo $(DEBUG_LIB)

print_release_lib:
	@echo $(RELEASE_LIB)

print_debug_link:
	@echo $(DEBUG_LINK)

print_release_link:
	@echo $(RELEASE_LINK)

print_debug_path:
	@echo $(DEBUG_BUILD_DIR)

print_release_path:
	@echo $(RELEASE_BUILD_DIR)

distclean: clean

clean:
	rm -f *~ $(SRC_DIR)/*~ $(IMPL_SRC_DIR)/*~ $(INCLUDE_DIR)/*~
	rm -fr $(BUILD_DIR)

$(DEBUG_BUILD_DIR):
	mkdir -p $@

$(RELEASE_BUILD_DIR):
	mkdir -p $@

$(IMPL_DEBUG_BUILD_DIR):
	mkdir -p $@

$(IMPL_RELEASE_BUILD_DIR):
	mkdir -p $@

$(DEBUG_BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -c $(DEBUG_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(RELEASE_BUILD_DIR)/%.o : $(SRC_DIR)/%.c
	$(CC) -c $(RELEASE_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(IMPL_DEBUG_BUILD_DIR)/%.o : $(IMPL_SRC_DIR)/%.c
	$(CC) -c $(DEBUG_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(IMPL_RELEASE_BUILD_DIR)/%.o : $(IMPL_SRC_DIR)/%.c
	$(CC) -c $(RELEASE_CFLAGS) -MT"$@" -MF"$(@:%.o=%.d)" $< -o $@

$(DEBUG_LIB): $(DEBUG_OBJS)
	$(LD) $(DEBUG_OBJS) $(DEBUG_LDFLAGS) -o $@

$(RELEASE_LIB): $(RELEASE_OBJS)
	$(LD) $(RELEASE_OBJS) $(RELEASE_LDFLAGS) -o $@
ifeq ($(KEEP_SYMBOLS),0)
	strip $@
endif

$(DEBUG_LINK):
	ln -sf $(LIB) $@

$(RELEASE_LINK):
	ln -sf $(LIB) $@

$(PKGCONFIG): $(LIB_NAME).pc.in
	sed -e 's/\[version\]/'$(PCVERSION)/g $< > $@

#
# Install
#

INSTALL = install
INSTALL_DIRS = $(INSTALL) -d
INSTALL_FILES = $(INSTALL) -m 644

INSTALL_LIB_DIR = $(DESTDIR)/usr/lib
INSTALL_INCLUDE_DIR = $(DESTDIR)/usr/include/$(NAME)
INSTALL_PKGCONFIG_DIR = $(DESTDIR)/usr/lib/pkgconfig

install: $(INSTALL_LIB_DIR)
	$(INSTALL_FILES) $(RELEASE_LIB) $(INSTALL_LIB_DIR)
	ln -sf $(LIB) $(INSTALL_LIB_DIR)/$(LIB_SYMLINK2)
	ln -sf $(LIB_SYMLINK2) $(INSTALL_LIB_DIR)/$(LIB_SYMLINK1)

install-dev: install $(INSTALL_INCLUDE_DIR) $(INSTALL_PKGCONFIG_DIR)
	$(INSTALL_FILES) $(INCLUDE_DIR)/*.h $(INSTALL_INCLUDE_DIR)
	$(INSTALL_FILES) $(PKGCONFIG) $(INSTALL_PKGCONFIG_DIR)
	ln -sf $(LIB_SYMLINK1) $(INSTALL_LIB_DIR)/$(LIB_DEV_SYMLINK)

$(INSTALL_LIB_DIR):
	$(INSTALL_DIRS) $@

$(INSTALL_INCLUDE_DIR):
	$(INSTALL_DIRS) $@

$(INSTALL_PKGCONFIG_DIR):
	$(INSTALL_DIRS) $@
