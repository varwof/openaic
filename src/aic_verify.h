/*
 * SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
 * SPDX-License-Identifier: Apache-2.0
 *
 * aic_verify.h — AIC semantic verification hooks (openaic patch, libcrypto).
 *
 * Verification of the DelegationAuthorization evidence carried in an AIC
 * extension, mirroring github.com/varwof/core internal/ca VerifyDelegation
 * Authorization:
 *
 *   1. Reconstruct DelegationAuthTBS with the exact field order used by the
 *      client signer and gateway-lib.
 *   2. Cross-validate: principalUid.keyHash must equal SHA-256(SPKI) of the
 *      user (principal) certificate found among the supplied certs.
 *   3. Verify the DA signature with the user certificate's public key,
 *      dispatching on the declared signatureAlgorithm OID (ECDSA / RSA-PKCS1
 *      / RSA-PSS / Ed25519).
 *
 * These hooks are OFF by default — stock OpenSSL verification behaviour is
 * unchanged. Enable explicitly with AIC_verify_cert() or the default
 * X509_STORE_CTX callback aic_verify_cb().
 */

#ifndef OSSL_CRYPTO_X509V3_V3_AIC_VERIFY_H
# define OSSL_CRYPTO_X509V3_V3_AIC_VERIFY_H

# include <openssl/x509.h>
# include <openssl/x509_vfy.h>

# ifdef __cplusplus
extern "C" {
# endif

typedef struct aic_replay_ctx_st AIC_REPLAY_CTX;

/* Flag bits for AIC_VERIFY_OPTS.flags. */
# define AIC_VERIFY_REQUIRE      0x0001 /* fail if the end-entity cert lacks AIC */
# define AIC_VERIFY_CHECK_SPKI   0x0002 /* enforce principalUid.keyHash match (default) */
# define AIC_VERIFY_VERIFY_DA    0x0004 /* verify DA signature (default) */
# define AIC_VERIFY_REPLAY       0x0008 /* anti-replay: reject reused nonces */

typedef struct aic_verify_opts_st {
    unsigned int flags;
    AIC_REPLAY_CTX *replay; /* needed if AIC_VERIFY_REPLAY is set */
} AIC_VERIFY_OPTS;

/*
 * Verify the AIC of the end-entity certificate `cert` against the user
 * (principal) certificate that signed the DelegationAuthorization.
 *
 * `untrusted` supplies the candidate user certificates (may be NULL).
 * Returns:
 *    1  verified
 *    0  AIC present but verification failed
 *   -1  no AIC extension and AIC_VERIFY_REQUIRE not set (treated as skip)
 */
int AIC_verify_cert(X509 *cert, STACK_OF(X509) *untrusted,
                    const AIC_VERIFY_OPTS *opts);

/*
 * Verify the DA signature of `da` over the reconstructed DelegationAuthTBS
 * using `userPub` (the principal's public key) and the optional hash-algo
 * override for the keyHash cross-check. Low-level entry point (unit tests).
 */
int AIC_verify_da(const AIC_DELEGATIONAUTH *da,
                  const AIC_PRINCIPALUID *pu,
                  const AIC *aic,          /* provides TBS fields */
                  EVP_PKEY *userPub);

/*
 * Default verify callback for X509_STORE_CTX. Enables AIC verification for
 * the end-entity certificate (chain position 0) when ctx->param has the
 * AIC_VERIFY_REQUIRE flag set via X509_VERIFY_PARAM_set_aic_flags() (see
 * below). Otherwise it is a pass-through that leaves stock behaviour intact.
 */
int aic_verify_cb(int ok, X509_STORE_CTX *ctx);

/* X509_VERIFY_PARAM integration (small extension, param struct untouched). */
int X509_VERIFY_PARAM_set_aic_flags(X509_VERIFY_PARAM *param, unsigned int flags);
unsigned int X509_VERIFY_PARAM_get_aic_flags(const X509_VERIFY_PARAM *param);

/* Replay cache. */
AIC_REPLAY_CTX *AIC_replay_new(void);
void AIC_replay_free(AIC_REPLAY_CTX *ctx);
int AIC_replay_check(AIC_REPLAY_CTX *ctx, const unsigned char *nonce,
                     size_t nonce_len);

# ifdef __cplusplus
}
# endif

#endif
