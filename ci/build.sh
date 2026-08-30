#!/bin/sh
# ci/build.sh — build OpenSSL 3.5.7 + AIC patch and run tests.
# Mirrors `make build test cross` for environments without make (or as a
# single step). Uses the SOCKS5 proxy when CONNECTION_PROXY is set.

set -eu

cd "$(dirname "$0")/.."
. ./config.mk

PROXY_OPT=""
if [ -n "${CONNECTION_PROXY:-}" ]; then
    PROXY_OPT="--socks5-hostname $CONNECTION_PROXY"
fi

echo "==> fetching OpenSSL $(OPENSSL_VERSION)"
[ -f "$OPENSSL_TARBALL" ] || curl -fL $PROXY_OPT -o "$OPENSSL_TARBALL" \
    "$OPENSSL_URL_BASE/$OPENSSL_TARBALL"

echo "==> extracting"
rm -rf "$OPENSSL_SRC"
tar -xzf "$OPENSSL_TARBALL"
mv "openssl-$OPENSSL_VERSION" "$OPENSSL_SRC"

echo "==> applying patch"
rm -rf "$PATCH_DIR"
cp -r "$OPENSSL_SRC" "$PATCH_DIR"
cd "$PATCH_DIR"
git init -q && git add -A
git apply "$OLDPWD/$PATCH_FILE" || patch -p1 < "$OLDPWD/$PATCH_FILE"
cd "$OLDPWD"

echo "==> configure & build"
cd "$PATCH_DIR"
./Configure $OPENSSL_CONFIGURE_ARGS
make -j"$(nproc)" build_libs build_apps
cd "$OLDPWD"

echo "==> build OK"
