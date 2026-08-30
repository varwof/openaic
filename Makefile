include config.mk

# ── downloads ─────────────────────────────────────────────────────────────
.PHONY: fetch
fetch:
	@test -f $(OPENSSL_TARBALL) || { \
		echo ">> downloading $(OPENSSL_TARBALL)"; \
		if [ -n "$(CONNECTION_PROXY)" ]; then \
			curl -fL --socks5-hostname $(CONNECTION_PROXY) -o $(OPENSSL_TARBALL) \
				$(OPENSSL_URL_BASE)/$(OPENSSL_TARBALL); \
		else \
			curl -fL -o $(OPENSSL_TARBALL) $(OPENSSL_URL_BASE)/$(OPENSSL_TARBALL); \
		fi; \
		curl -fL -o $(OPENSSL_TARBALL).sha256 $(OPENSSL_URL_BASE)/$(OPENSSL_TARBALL).sha256; \
	}
	@echo ">> verifying sha256"
	@cd $(CURDIR) && sha256sum -c $(OPENSSL_TARBALL).sha256

.PHONY: extract
extract: fetch
	@if [ ! -d $(OPENSSL_SRC) ]; then \
		tar -xzf $(OPENSSL_TARBALL) && mv openssl-$(OPENSSL_VERSION) $(OPENSSL_SRC); \
	fi
	@echo ">> sources ready at $(OPENSSL_SRC)"

# ── patch application ─────────────────────────────────────────────────────
# $(OPENSSL_SRC) is the *surgery tree*: a git repo with baseline + aic-patch
# commits (see `make gen-patch` / docs). It is the single source of truth and
# is NEVER deleted by build targets. $(PATCH_DIR) is a copy of the surgery
# tree (already patched), ready to configure/build.
.PHONY: apply-patch
apply-patch: extract
	@if [ ! -d $(OPENSSL_SRC)/.git ]; then \
		echo ">> $(OPENSSL_SRC) is not a surgery tree; run 'make gen-patch' first"; \
		exit 1; \
	fi
	@rm -rf $(PATCH_DIR)
	@cp -r $(OPENSSL_SRC) $(PATCH_DIR)
	@echo ">> patch applied in $(PATCH_DIR) (copied from surgery tree $(OPENSSL_SRC))"

# ── build ────────────────────────────────────────────────────────────────
# OpenSSL 3.5's -MMD deps race under parallel make: the same .c is compiled
# for both libcrypto-lib-* and libcrypto-shlib-* (same .d.tmp), so -j often
# fails with "mv: cannot stat *.d.tmp". Build serial to stay deterministic.
.PHONY: build
build: apply-patch
	@cd $(PATCH_DIR) && ./Configure $(OPENSSL_CONFIGURE_ARGS) >/dev/null
	@$(MAKE) -C $(PATCH_DIR) -j1 build_libs build_apps
	@echo ">> OpenSSL $(OPENSSL_VERSION)+AIC built at $(PATCH_DIR)"

# ── tests ─────────────────────────────────────────────────────────────────
.PHONY: test
test: build
	@$(MAKE) -C $(PATCH_DIR) -j"$(shell nproc 2>/dev/null || echo 2)" test >/tmp/openaic-ossl-test.log 2>&1 || { \
		echo ">> OpenSSL test failure, tail:"; tail -40 /tmp/openaic-ossl-test.log; exit 1; }
	@echo ">> OpenSSL test suite OK"
	$(MAKE) test-helper

.PHONY: test-helper
test-helper: build
	@mkdir -p build
	@$(CC) -o build/openaic_json_test test/openaic_json_test.c lib/openaic.c lib/cjson/cJSON.c \
		-Ilib -Ilib/cjson -Wall -Wextra -O2
	@./build/openaic_json_test
	@echo ">> openaic helper tests OK"

# ── cross consistency (Go vectors ↔ C parse) ─────────────────────────────
.PHONY: cross
cross: build test-helper
	@mkdir -p test/vectors/out
	@cd test/vectors && go mod tidy && go run . -out out/
	@echo ">> Go vectors emitted in test/vectors/out"
	@echo "(C-side round-trip asserted by test/aic_ext_test.c during test)"

# ── AIC extension tests against the patched build ─────────────────────────
.PHONY: test-aic
test-aic: build test-helper
	@mkdir -p test/vectors/out
	@cd test/vectors && go mod tidy && go run . -out out/
	@echo ">> Go vectors emitted in test/vectors/out"
	@mkdir -p build
	@$(CC) -o build/aic_ext_test test/aic_ext_test.c lib/openaic.c lib/cjson/cJSON.c \
		-Ilib -Ilib/cjson -Isrc -I$(PATCH_DIR)/include \
		-L$(PATCH_DIR) -Wl,-rpath,$(abspath $(PATCH_DIR)) \
		-lcrypto -lssl -Wall -Wextra -O2
	@./build/aic_ext_test test/vectors/out
	@echo ">> AIC extension tests OK"

# ── patch regeneration ────────────────────────────────────────────────────
# The surgery tree ($(OPENSSL_SRC)) is a git repo: first commit = pristine
# baseline (v3.5.7 tarball), subsequent commits = the AIC surgery. The unified
# diff against the baseline commit IS the distributable patch.
.PHONY: gen-patch
gen-patch:
	@cd $(OPENSSL_SRC) && test -d .git || { echo ">> no surgery tree; run: extract+init"; exit 1; }
	@cd $(OPENSSL_SRC) && git diff --binary HEAD~1..HEAD > $(CURDIR)/$(PATCH_FILE)
	@echo ">> wrote $(PATCH_FILE)"
	@echo "   verify: git apply --check $(CURDIR)/$(PATCH_FILE)  # against pristine v3.5.7"

.PHONY: clean
clean:
	@rm -rf $(PATCH_DIR) build
	@echo ">> cleaned build dirs (kept $(OPENSSL_TARBALL) and $(OPENSSL_SRC))"

.PHONY: distclean
distclean: clean
	@rm -rf $(OPENSSL_SRC) $(OPENSSL_TARBALL) $(OPENSSL_TARBALL).sha256

.PHONY: check-json
check-json:
	@echo "cJSON vendored: $$(wc -l < lib/cjson/cJSON.c) lines, $$(wc -l < lib/cjson/cJSON.h) header lines"