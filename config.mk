# openaic build configuration

# OpenSSL 3.5 LTS baseline
OPENSSL_VERSION   := 3.5.7
OPENSSL_TARBALL   := openssl-$(OPENSSL_VERSION).tar.gz
OPENSSL_URL_BASE  := https://github.com/openssl/openssl/releases/download/openssl-$(OPENSSL_VERSION)

# Optional SOCKS5 proxy (e.g. Tor) used by `make fetch` when HTTPS direct fails.
# Empty (default) = direct download. Override from the environment when your
# network requires a proxy, e.g.:
#   CONNECTION_PROXY=127.0.0.1:9050 make fetch
CONNECTION_PROXY  ?=

# Source layout
OPENSSL_SRC      := openssl-src
PATCH_FILE       := patch/openssl-3.5.7-aic.patch
PATCH_DIR        := patch-dir
INSTALL_PREFIX   := $(CURDIR)/build/install

# Configure is invoked against pristine sources in $(OPENSSL_SRC); the patch is
# applied in a copy at $(PATCH_DIR) so `make gen-patch` can regenerate the
# unified diff at any time.
# no-asm: kept out of the patch (build option only) because
# aes-gcm-avx512.s can fail to assemble on toolchains without AVX-512.
# Override via environment when building on newer toolchains.
OPENSSL_CONFIGURE_ARGS ?= --prefix=$(INSTALL_PREFIX) enable-unit-test -fPIC shared no-asm

.PHONY: help fetch build test cross gen-patch clean check-json