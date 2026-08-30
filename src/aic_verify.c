/*
 * SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
 * SPDX-License-Identifier: Apache-2.0
 *
 * aic_verify.c — AIC semantic verification hooks (openaic patch, libcrypto).
 *
 * See aic_verify.h for the contract. DA signature verification mirrors the
 * Go reference implementation (github.com/varwof/core
 * internal/ca/delegation_auth_verify.go) and the TBS reconstruction mirrors
 * github.com/varwof/types DelegationAuthTBS field order/tags.
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/x509_vfy.h>

#include "v3_aic.h"
#include "aic_verify.h"

/*
 * ── DelegationAuthTBS reconstruction ──────────────────────────────────────
 *
 * Mirrors types.DelegationAuthTBS exactly (order + tags):
 *   SEQUENCE {
 *     version                  INTEGER DEFAULT 1,
 *     agentId                  UTF8String,
 *     principalUid             SEQUENCE { ... },
 *     reason                   SEQUENCE { reasonCode UTF8String, description UTF8String },
 *     capabilities             SEQUENCE OF Capability,
 *     delegationMode           INTEGER DEFAULT 0,
 *     authorizationConstraints [0] EXPLICIT SEQUENCE OF Capability OPTIONAL,
 *     requestedLifetime        INTEGER DEFAULT 0,
 *     timestamp                GeneralizedTime,
 *     nonce                    OCTET STRING
 *   }
 */

typedef struct AIC_DATBS_st {
    ASN1_INTEGER *version;
    ASN1_UTF8STRING *agentId;
    AIC_PRINCIPALUID *principalUid;
    AIC_REASON *reason;
    STACK_OF(AIC_CAPABILITY) *capabilities;
    ASN1_INTEGER *delegationMode;
    STACK_OF(AIC_CAPABILITY) *authorizationConstraints;
    ASN1_INTEGER *requestedLifetime;
    ASN1_GENERALIZEDTIME *timestamp;
    ASN1_OCTET_STRING *nonce;
} AIC_DATBS;

ASN1_SEQUENCE(AIC_DATBS) = {
    ASN1_SIMPLE(AIC_DATBS, version, ASN1_INTEGER),
    ASN1_SIMPLE(AIC_DATBS, agentId, ASN1_UTF8STRING),
    ASN1_SIMPLE(AIC_DATBS, principalUid, AIC_PRINCIPALUID),
    ASN1_SIMPLE(AIC_DATBS, reason, AIC_REASON),
    ASN1_SEQUENCE_OF(AIC_DATBS, capabilities, AIC_CAPABILITY),
    ASN1_SIMPLE(AIC_DATBS, delegationMode, ASN1_INTEGER),
    ASN1_EXP_SEQUENCE_OF_OPT(AIC_DATBS, authorizationConstraints,
                             AIC_CAPABILITY, 0),
    ASN1_SIMPLE(AIC_DATBS, requestedLifetime, ASN1_INTEGER),
    ASN1_SIMPLE(AIC_DATBS, timestamp, ASN1_GENERALIZEDTIME),
    ASN1_SIMPLE(AIC_DATBS, nonce, ASN1_OCTET_STRING)
} static_ASN1_SEQUENCE_END(AIC_DATBS)

DECLARE_ASN1_FUNCTIONS(AIC_DATBS)
IMPLEMENT_ASN1_FUNCTIONS(AIC_DATBS)

static AIC_DATBS *aic_build_tbs(const AIC *aic,
                                const AIC_DELEGATIONAUTH *da)
{
    AIC_DATBS *tbs = AIC_DATBS_new();
    int i;
    if (tbs == NULL)
        return NULL;
    if (aic->version != NULL && !ASN1_INTEGER_set(tbs->version,
                                                  ASN1_INTEGER_get(aic->version)))
        goto err;
    if (aic->agentId != NULL && !ASN1_STRING_copy(tbs->agentId, aic->agentId))
        goto err;
    if (aic->principalUid != NULL) {
        tbs->principalUid = ASN1_item_dup(ASN1_ITEM_rptr(AIC_PRINCIPALUID),
                                          aic->principalUid);
        if (tbs->principalUid == NULL)
            goto err;
    }
    if (da->reason != NULL) {
        tbs->reason = ASN1_item_dup(ASN1_ITEM_rptr(AIC_REASON), da->reason);
        if (tbs->reason == NULL)
            goto err;
    }
    if (aic->capabilities != NULL) {
        tbs->capabilities = sk_AIC_CAPABILITY_new_reserve(NULL,
                               sk_AIC_CAPABILITY_num(aic->capabilities));
        if (tbs->capabilities == NULL)
            goto err;
        for (i = 0; i < sk_AIC_CAPABILITY_num(aic->capabilities); i++) {
            AIC_CAPABILITY *c = sk_AIC_CAPABILITY_value(aic->capabilities, i);
            AIC_CAPABILITY *cap =
                ASN1_item_dup(ASN1_ITEM_rptr(AIC_CAPABILITY), c);
            if (cap == NULL)
                goto err;
            if (sk_AIC_CAPABILITY_push(tbs->capabilities, cap) <= 0) {
                AIC_CAPABILITY_free(cap);
                goto err;
            }
        }
    }
    if (aic->delegationMode != NULL && !ASN1_INTEGER_set(
            tbs->delegationMode, ASN1_INTEGER_get(aic->delegationMode)))
        goto err;
    if (aic->authorizationConstraints != NULL) {
        tbs->authorizationConstraints = sk_AIC_CAPABILITY_new_reserve(NULL,
                               sk_AIC_CAPABILITY_num(aic->authorizationConstraints));
        if (tbs->authorizationConstraints == NULL)
            goto err;
        for (i = 0; i < sk_AIC_CAPABILITY_num(aic->authorizationConstraints); i++) {
            AIC_CAPABILITY *c = sk_AIC_CAPABILITY_value(
                aic->authorizationConstraints, i);
            AIC_CAPABILITY *cap =
                ASN1_item_dup(ASN1_ITEM_rptr(AIC_CAPABILITY), c);
            if (cap == NULL)
                goto err;
            if (sk_AIC_CAPABILITY_push(tbs->authorizationConstraints, cap) <= 0) {
                AIC_CAPABILITY_free(cap);
                goto err;
            }
        }
    }
    if (da->requestedLifetime != NULL && !ASN1_INTEGER_set(
            tbs->requestedLifetime, ASN1_INTEGER_get(da->requestedLifetime)))
        goto err;
    if (da->timestamp != NULL
        && !ASN1_STRING_copy(tbs->timestamp, da->timestamp))
        goto err;
    if (da->nonce != NULL && !ASN1_OCTET_STRING_set(tbs->nonce,
                                                    da->nonce->data,
                                                    da->nonce->length))
        goto err;
    return tbs;
 err:
    AIC_DATBS_free(tbs);
    return NULL;
}

/*
 * ── signature OIDs ─────────────────────────────────────────────────────────
 */

/* Map sig-alg OID -> EVP digest nid (0 = none, -1 = unsupported/pss handled separately). */
static int da_digest_nid(const ASN1_OBJECT *algo)
{
    if (OBJ_obj2nid(algo) == NID_sha256WithRSAEncryption)
        return NID_sha256;
    if (OBJ_obj2nid(algo) == NID_sha384WithRSAEncryption)
        return NID_sha384;
    if (OBJ_obj2nid(algo) == NID_sha512WithRSAEncryption)
        return NID_sha512;
    if (OBJ_obj2nid(algo) == NID_ecdsa_with_SHA256)
        return NID_sha256;
    if (OBJ_obj2nid(algo) == NID_ecdsa_with_SHA384)
        return NID_sha384;
    if (OBJ_obj2nid(algo) == NID_ecdsa_with_SHA512)
        return NID_sha512;
    if (OBJ_obj2nid(algo) == NID_ED25519)
        return 0;  /* none */
    if (OBJ_obj2nid(algo) == NID_rsassaPss)
        return NID_sha256;  /* RSA-PSS: reference impl uses SHA-256 */
    return -1;
}

static int is_pss_oid(const ASN1_OBJECT *algo)
{
    return OBJ_obj2nid(algo) == NID_rsassaPss;
}

/*
 * ── core DA verification ──────────────────────────────────────────────────
 */

int AIC_verify_da(const AIC_DELEGATIONAUTH *da, const AIC_PRINCIPALUID *pu,
                  const AIC *aic, EVP_PKEY *userPub)
{
    AIC_DATBS *tbs = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *der = NULL;
    const EVP_MD *md = NULL;
    const ASN1_OBJECT *algo;
    int derlen, ret = 0, digest_nid;

    if (da == NULL || pu == NULL || aic == NULL || userPub == NULL)
        return 0;
    algo = da->signatureAlgorithm == NULL ? NULL : da->signatureAlgorithm->algorithm;
    if (algo == NULL || da->signatureValue == NULL)
        return 0;

    tbs = aic_build_tbs(aic, da);
    if (tbs == NULL)
        goto out;
    derlen = i2d_AIC_DATBS(tbs, &der);
    if (derlen <= 0)
        goto out;

    digest_nid = da_digest_nid(algo);
    if (digest_nid == -1 && !is_pss_oid(algo))
        goto out;

    mctx = EVP_MD_CTX_new();
    if (mctx == NULL)
        goto out;

    if (digest_nid == 0) {
        /* Ed25519: pure, no digest. */
        if (EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, userPub) != 1)
            goto out;
    } else {
        md = EVP_get_digestbynid(digest_nid);
        if (md == NULL)
            goto out;
        if (EVP_DigestVerifyInit(mctx, &pctx, md, NULL, userPub) != 1)
            goto out;
        if (is_pss_oid(algo)) {
            if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1)
                goto out;
            /* salt length: match digest (RSA-PSS default in the reference impl) */
            if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) != 1)
                goto out;
        }
    }

    if (EVP_DigestVerifyUpdate(mctx, der, derlen) != 1)
        goto out;
    if (EVP_DigestVerifyFinal(mctx, da->signatureValue->data,
                              da->signatureValue->length) != 1)
        goto out;
    ret = 1;

 out:
    OPENSSL_free(der);
    AIC_DATBS_free(tbs);
    EVP_MD_CTX_free(mctx);
    return ret;
}

/* SPKI hash cross-check: principalUid.keyHash == SHA-256(SPKI DER). */
static int aic_keyhash_matches(const AIC_PRINCIPALUID *pu, X509 *userCert)
{
    X509_PUBKEY *spki = X509_get_X509_PUBKEY(userCert);
    unsigned char *der = NULL;
    unsigned char md[SHA256_DIGEST_LENGTH];
    const unsigned char *kh;
    int derlen, khlen, match;

    if (spki == NULL || pu == NULL || pu->keyHash == NULL)
        return 0;
    derlen = i2d_X509_PUBKEY(spki, &der);
    if (derlen <= 0) {
        OPENSSL_free(der);
        return 0;
    }
    SHA256(der, (size_t)derlen, md);
    OPENSSL_free(der);

    kh = pu->keyHash->data;
    khlen = pu->keyHash->length;
    if (khlen != SHA256_DIGEST_LENGTH) {
        /* hashAlgo may specify SHA-384/512; support SHA-256 here and treat
         * other lengths as mismatch (full algo dispatch in libopenaic layer) */
        return 0;
    }
    match = (CRYPTO_memcmp(md, kh, SHA256_DIGEST_LENGTH) == 0);
    return match;
}

static X509 *aic_find_user_by_keyhash(const AIC_PRINCIPALUID *pu,
                                      STACK_OF(X509) *untrusted)
{
    int i;
    if (untrusted == NULL || pu == NULL)
        return NULL;
    for (i = 0; i < sk_X509_num(untrusted); i++) {
        X509 *x = sk_X509_value(untrusted, i);
        if (aic_keyhash_matches(pu, x))
            return x;
    }
    return NULL;
}

/*
 * ── replay cache ──────────────────────────────────────────────────────────
 *
 * Minimal nonce cache: simple growable array of 32-byte nonces + per-entry
 * seen flag. Production hardening (hash table, TTL, bounded size) is tracked
 * in docs/verify.md.
 */

struct aic_replay_ctx_st {
    unsigned char (*nonces)[32];
    size_t n, cap;
};

AIC_REPLAY_CTX *AIC_replay_new(void)
{
    return OPENSSL_zalloc(sizeof(AIC_REPLAY_CTX));
}

void AIC_replay_free(AIC_REPLAY_CTX *ctx)
{
    if (ctx == NULL)
        return;
    OPENSSL_free(ctx->nonces);
    OPENSSL_free(ctx);
}

int AIC_replay_check(AIC_REPLAY_CTX *ctx, const unsigned char *nonce,
                     size_t nonce_len)
{
    size_t i;
    unsigned char (*p)[32];
    if (ctx == NULL || nonce_len != 32)
        return 0;
    for (i = 0; i < ctx->n; i++) {
        if (CRYPTO_memcmp(ctx->nonces[i], nonce, 32) == 0)
            return 0;  /* replay */
    }
    if (ctx->n == ctx->cap) {
        size_t newcap = ctx->cap == 0 ? 8 : ctx->cap * 2;
        p = OPENSSL_realloc(ctx->nonces, newcap * sizeof(ctx->nonces[0]));
        if (p == NULL)
            return 0;
        ctx->nonces = p;
        ctx->cap = newcap;
    }
    memcpy(ctx->nonces[ctx->n], nonce, 32);
    ctx->n++;
    return 1;
}

/*
 * ── high-level verify ─────────────────────────────────────────────────────
 */

int AIC_verify_cert(X509 *cert, STACK_OF(X509) *untrusted,
                    const AIC_VERIFY_OPTS *opts)
{
    AIC *aic = NULL;
    X509 *userCert = NULL;
    EVP_PKEY *userPub = NULL;
    int crit = 0, rc = -1;
    unsigned int flags;
    const AIC_DELEGATIONAUTH *da;

    if (cert == NULL)
        return 0;
    flags = opts == NULL ? (AIC_VERIFY_CHECK_SPKI | AIC_VERIFY_VERIFY_DA) : opts->flags;

    aic = X509_get_ext_d2i(cert, NID_AIC, &crit, NULL);
    if (aic == NULL)
        return (flags & AIC_VERIFY_REQUIRE) ? 0 : -1;

    if (!AIC_validate(aic, NULL))
        goto fail;

    if (flags & AIC_VERIFY_REPLAY) {
        da = AIC_get_delegationAuthorization(aic);
        if (da != NULL && da->nonce != NULL) {
            AIC_REPLAY_CTX *rcache = opts != NULL ? opts->replay : NULL;
            if (rcache == NULL)
                goto fail;
            if (!AIC_replay_check(rcache, da->nonce->data, da->nonce->length))
                goto fail;
        }
    }

    if (flags & AIC_VERIFY_CHECK_SPKI) {
        userCert = aic_find_user_by_keyhash(aic->principalUid, untrusted);
        if (userCert == NULL)
            goto fail;
    } else if (untrusted != NULL && sk_X509_num(untrusted) > 0) {
        /* CHECK_SPKI off: skip the keyHash cross-check, but VERIFY_DA still
         * needs a public key to validate the DA signature against. Use the
         * caller-provided principal cert without requiring a keyHash match. */
        userCert = sk_X509_value(untrusted, 0);
    }

    if (flags & AIC_VERIFY_VERIFY_DA) {
        if (userCert == NULL)
            goto fail;
        userPub = X509_get_pubkey(userCert);
        if (userPub == NULL)
            goto fail;
        da = AIC_get_delegationAuthorization(aic);
        if (!AIC_verify_da(da, aic->principalUid, aic, userPub))
            goto fail;
    }

    rc = 1;
    goto out;
 fail:
    rc = 0;
 out:
    EVP_PKEY_free(userPub);
    AIC_free(aic);
    return rc;
}

/*
 * ── X509_STORE_CTX callback + X509_VERIFY_PARAM flags ─────────────────────
 *
 * The param extension uses a small, separately-managed table keyed by the
 * X509_VERIFY_PARAM address, so the param struct itself is untouched.
 */

struct aic_param_state {
    const X509_VERIFY_PARAM *param;
    unsigned int flags;
};

static struct aic_param_state *aic_param_reg = NULL;
static size_t aic_param_reg_n = 0, aic_param_reg_cap = 0;

static unsigned int aic_param_lookup(const X509_VERIFY_PARAM *param)
{
    size_t i;
    for (i = 0; i < aic_param_reg_n; i++)
        if (aic_param_reg[i].param == param)
            return aic_param_reg[i].flags;
    return 0;
}

int X509_VERIFY_PARAM_set_aic_flags(X509_VERIFY_PARAM *param, unsigned int flags)
{
    struct aic_param_state *reg;
    size_t i, newcap;
    if (param == NULL)
        return 0;
    for (i = 0; i < aic_param_reg_n; i++)
        if (aic_param_reg[i].param == param) {
            aic_param_reg[i].flags = flags;
            return 1;
        }
    if (aic_param_reg_n == aic_param_reg_cap) {
        newcap = aic_param_reg_cap == 0 ? 4 : aic_param_reg_cap * 2;
        reg = OPENSSL_realloc(aic_param_reg, newcap * sizeof(*reg));
        if (reg == NULL)
            return 0;
        aic_param_reg = reg;
        aic_param_reg_cap = newcap;
    }
    aic_param_reg[aic_param_reg_n].param = param;
    aic_param_reg[aic_param_reg_n].flags = flags;
    aic_param_reg_n++;
    return 1;
}

unsigned int X509_VERIFY_PARAM_get_aic_flags(const X509_VERIFY_PARAM *param)
{
    return aic_param_lookup(param);
}

int aic_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    unsigned int flags;
    X509 *cert;

    if (ctx == NULL)
        return ok;
    flags = aic_param_lookup(X509_STORE_CTX_get0_param(ctx));
    if (flags == 0 || !ok)
        return ok;  /* pass-through when AIC not requested */

    cert = X509_STORE_CTX_get0_cert(ctx);
    if (cert == NULL)
        return 0;

    {
        AIC_VERIFY_OPTS opts;
        STACK_OF(X509) *untrusted = X509_STORE_CTX_get0_untrusted(ctx);
        int rc;
        opts.flags = flags;
        opts.replay = NULL;
        rc = AIC_verify_cert(cert, untrusted, &opts);
        if (rc < 0)
            return ok;  /* no AIC, not required */
        return rc == 1;
    }
}
