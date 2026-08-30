# openaic build configuration

# OpenSSL 3.5 LTS baseline
OPENSSL_VERSION   := 3.5.7
OPENSSL_TARBALL   := openssl-$(OPENSSL_VERSION).tar.gz
OPENSSL_URL_BASE  := https://github.com/openssl/openssl/releases/download/openssl-$(OPENSSL_VERSION)

# Optional SOCKS5 proxy (e.g. Tor) used by `make fetch` when HTTPS direct fails.
# Empty = direct download. Overridable from the environment (e.g. CI sets
# CONNECTION_PROXY= to force a direct download).
CONNECTION_PROXY  ?= 127.0.0.1:9050

# Source layout
OPENSSL_SRC      := openssl-src
PATCH_FILE       := patch/openssl-3.5.7-aic.patch
PATCH_DIR        := patch-dir
INSTALL_PREFIX   := $(CURDIR)/build/install

# Configure is invoked against pristine sources in $(OPENSSL_SRC); the patch is
# applied in a copy at $(PATCH_DIR) so `make gen-patch` can regenerate the
# unified diff at any time.
# no-asm: this host's binutils predates AVX-512 (aes-gcm-avx512.s fails to
# assemble). Kept out of the patch; it is a build option only.
OPENSSL_CONFIGURE_ARGS := --prefix=$(INSTALL_PREFIX) enable-unit-test -fPIC shared no-asm

.PHONY: help fetch build test cross gen-patch clean check-json