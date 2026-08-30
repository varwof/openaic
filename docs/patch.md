# OpenSSL 3.5 LTS AIC patch (patch/)

## The single patch file

`patch/openssl-3.5.7-aic.patch` is the only distributable artifact. Against
the **OpenSSL 3.5.7 release tarball** source tree it makes these changes:

| File | Change |
|------|--------|
| `crypto/objects/objects.txt` | adds `1 3 6 1 4 1 66257 1 1 : aic : AIC` |
| `crypto/objects/obj_mac.num` | regenerated: `AIC` → `NID 1487` (`objects.pl -n`) |
| `include/openssl/obj_mac.h` | regenerated: `SN_AIC`/`LN_AIC`/`NID_AIC 1487`/`OBJ_AIC` |
| `crypto/objects/obj_dat.h` | regenerated: OID serialized bytes + `nid_objs`/`sn_objs`/`ln_objs`/`obj_objs` |
| `crypto/objects/obj_xref.h` | regenerated (copyright year only) |
| `crypto/x509/ext_dat.h` | appends `extern const X509V3_EXT_METHOD ossl_v3_aic;` |
| `crypto/x509/standard_exts.h` | appends `&ossl_v3_aic` at the end of `standard_exts[]` (highest NID, keeps ascending order) |
| `crypto/x509/v3_aic.c` (new) | extension method: ASN.1 templates, d2i/i2d, printing, config v2i/i2v (see `../src/v3_aic.c`, maintained in sync) |
| `crypto/x509/aic_verify.c` (new) | verification hooks: DA verify, SPKI cross-check, replay cache (see `../src/aic_verify.c`) |
| `crypto/x509/v3_aic.h` (new) | see `../src/v3_aic.h` |
| `crypto/x509/aic_verify.h` (new) | see `../src/aic_verify.h` |
| `crypto/x509/build.info` | adds `v3_aic.c aic_verify.c` |
| `util/libcrypto.num` | exports 51 AIC symbols (ordinals 6055–6105) |

## Why a patch and not a provider

- For a custom X.509 extension to be printed by `openssl x509 -text` and
  generated from config `v2i`, it must be registered in `standard_exts[]`
  (compiled into libcrypto);
- a provider cannot hook into the `X509V3_EXT_METHOD` table, nor touch
  verification-layer semantics hooks.

## Version strategy

- Only **3.5 LTS** is targeted (baseline 3.5.7, supported until 2030-04-08).
  The patch corresponds strictly to the tag; on an OpenSSL patch release,
  regenerate the `git diff` and rerun the full test suite.
- If 3.0 LTS is ever needed: x509 differs very little between 3.0/3.5, so a
  separate `openssl-3.0-*.patch` can be produced by `git cherry-pick`.

## Surgery tree and `make gen-patch`

`openssl-src/` is a separate git repository and is the **single source of
truth**:

- first commit = pristine baseline (3.5.7 tarball extracted, `git add -A`);
- subsequent commits = the AIC surgery (synced from this repo's `src/`);
- `make gen-patch` runs `git diff --binary HEAD~1..HEAD` to produce the unified
  patch.

Build targets **never delete** the surgery tree: `make build` copies it to
`patch-dir/` and configures there. Maintainers keep a local backup of the
surgery tree.

```sh
make gen-patch            # regenerate patch/openssl-3.5.7-aic.patch
git apply --check patch/openssl-3.5.7-aic.patch   # verify against pristine 3.5.7
make build test           # full validation
```

## Maintenance notes (lessons learned)

### Serial build (-j1)

OpenSSL's parallel make compiles the same `.c` as both `libcrypto-lib-*` and
`libcrypto-shlib-*`, which race on the same `.d.tmp` and often fail with
`mv: cannot stat '*.d.tmp'`. **Build with `-j1`**; the test phase of `make
test` may run in parallel.

### OID regeneration

Equivalent to `make update`'s `generate_crypto_objects`, but `obj_mac.num`
must be written to a temp file first and then `mv`-ed — a direct `>` redirect
truncates the input and renumbers every NID:

```sh
perl crypto/objects/objects.pl -n crypto/objects/objects.txt crypto/objects/obj_mac.num > /tmp/num && mv /tmp/num crypto/objects/obj_mac.num
perl crypto/objects/objects.pl   crypto/objects/objects.txt crypto/objects/obj_mac.num > /tmp/h
perl crypto/objects/obj_dat.pl   /tmp/h > crypto/objects/obj_dat.h
perl crypto/objects/objxref.pl   crypto/objects/obj_mac.num crypto/objects/obj_xref.txt > crypto/objects/obj_xref.h
sed -e '1,8d' crypto/objects/obj_compat.h >> /tmp/h && mv /tmp/h include/openssl/obj_mac.h
```

Missing the `obj_compat.h` append loses the `DEPRECATED_3_0` section.

### Symbol export and ordinals

The `libcrypto.ld` version script's `local: *` hides new symbols, so the 51 AIC
symbols must be appended to `util/libcrypto.num` (format
`NAME<pad>N\t3_5_0\tEXIST::FUNCTION:`), then `make libcrypto.ld`
(mkdef.pl regenerates it).

- New lines must keep ordinals strictly increasing and version `3_5_0`;
- **Do not leave blank lines**: `test/recipes/02-test_ordinals.t` treats a
  blank line as invalid and fails the whole suite (a full run once failed on
  exactly this).

## Validation

- `make fetch` verifies the tarball SHA-256;
- `make build` builds from a copy;
- CI (`ci/build.sh`) verifies `git apply --check` on a pristine 3.5.7 tree
  before building;
- full `make test` runs OpenSSL's 344 files / 4499 tests plus the openaic
  tests.
