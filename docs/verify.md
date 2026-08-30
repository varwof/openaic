# AIC verification semantics (verification hooks)

## Layered design

openaic deliberately separates "extension representation" from "JSON
semantics" so that the libcrypto patch stays small and free of runtime
dependencies:

| Layer | Location | Responsibility | Dependencies |
|-------|----------|----------------|--------------|
| Extension method | libcrypto patch (`src/v3_aic.c`) | ASN.1 templates, d2i/i2d, printing, config v2i/i2v; `parameters` opaque bytes | none |
| Verification hooks | libcrypto patch (`src/aic_verify.c`) | DA verification, SPKI keyHash cross-check, nonce anti-replay (off by default) | none |
| Helper layer | `lib/openaic.c` | JSON parse/validate/pretty-print of `parameters`; base64url; `max-concurrent` constraint | cJSON (vendored) |
| CLI | `cmd/openaic-tool` | integrates both layers | patched OpenSSL + libopenaic + cJSON |

## Verification flow (`AIC_verify_cert`)

1. Read the AIC extension from the end-entity certificate
   (`X509_get_ext_d2i(cert, NID_aic, ...)`).
   - No AIC: with `AIC_VERIFY_REQUIRE` unset → return -1 (skip, treated as
     pass); set → return 0.
2. `AIC_validate()`: field-level constraints (lengths / 32-byte nonce /
   lifetime range / capability count / DA required / constraint schemeId
   allow-list). Failure → 0.
3. `AIC_VERIFY_REPLAY` (optional, off by default): anti-replay check on
   `da.nonce`, requires an external `AIC_REPLAY_CTX`. Replay → 0.
4. `AIC_VERIFY_CHECK_SPKI` (on by default): look up the **principal** (user)
   certificate among `untrusted` (and the verify chain/untrusted) where
   `principalUid.keyHash == SHA-256(SPKI)`. Not found → 0.
5. `AIC_VERIFY_VERIFY_DA` (on by default): rebuild `DelegationAuthTBS`
   (field order/tags strictly matching `types`), verify the DA signature with
   the principal certificate's public key according to the
   `signatureAlgorithm` OID. Failure → 0.

## Signature algorithm dispatch

| OID | Verification |
|-----|--------------|
| rsaEncryption + SHA-256/384/512 | `EVP_DigestVerify`, RSA-PKCS1 |
| rsassaPss + SHA-256 | `EVP_PKEY_CTX` with `RSA_PKCS1_PSS_PADDING`, saltlen = digest |
| ecdsa-with-SHA256/384/512 | `EVP_DigestVerify`, ECDSA (ASN.1 signature) |
| Ed25519 | `EVP_DigestVerify`, no digest (digest NULL) |
| others | rejected |

The keyHash cross-check currently supports SHA-256 lengths; SHA-384/512/SM3
length dispatch and `hashAlgo` parsing live in the libopenaic layer (later
milestone).

## Off by default, explicitly enabled

Stock OpenSSL 3.5 verification behaviour is **not changed**. To enable:

```c
#include <openssl/x509_vfy.h>
#include "aic_verify.h"

/* Method A: verify callback (recommended, composes with existing X509_STORE_CTX) */
X509_VERIFY_PARAM_set_aic_flags(ctx->param, AIC_VERIFY_REQUIRE
                                              | AIC_VERIFY_CHECK_SPKI
                                              | AIC_VERIFY_VERIFY_DA);
X509_STORE_CTX_set_verify_cb(ctx, aic_verify_cb);

/* Method B: direct call (independent of X509_STORE_CTX) */
AIC_VERIFY_OPTS opts = { .flags = AIC_VERIFY_CHECK_SPKI | AIC_VERIFY_VERIFY_DA };
int rc = AIC_verify_cert(agent_cert, untrusted, &opts);
```

## Nonce anti-replay

The spec requires a 32-byte random nonce to prevent DA replay. Threat model:

- Freshness is primarily guaranteed by the CA issuing a nonce challenge before
  signing (the `core` serve layer);
- This hook's `AIC_REPLAY_CTX` provides a session-scoped one-shot check
  (off by default, to avoid false positives in stateless verification).
  Production hardening (TODO):
  - Replace the unbounded array with a nonce → TTL (e.g. 300s) + LRU cache;
  - Optional persistence (cross-process dedup after restart);
  - Clock check: alert on deviation between `da.timestamp` and local clock.

## Security boundaries and non-goals

- This hook does **not** modify OpenSSL's certificate-chain verification main
  loop; AIC is "authorization evidence", not a trust anchor. If "some cert in
  the chain must carry critical AIC" is required, the caller (e.g. a gateway /
  proxy) calls `AIC_verify_cert` for the relevant position inside its callback
  and decides.
- JSON validation of `parameters` is structural only (e.g. `max-concurrent`
  `{"max":N}`); no permission decisions are made here. Authorization is judged
  upstream using `FullID = schemeId:capabilityId`.
- Anti-replay is off by default and in-process one-shot; do not treat
  session-scoped anti-replay as a global uniqueness guarantee.
