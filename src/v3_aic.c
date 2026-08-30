/*
 * SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
 * SPDX-License-Identifier: Apache-2.0
 *
 * v3_aic.c — AIC X.509v3 extension method for OpenSSL 3.5 LTS.
 *
 * Part of the openaic patch. This file is installed into crypto/x509/ and
 * built into libcrypto. It provides:
 *   - ASN.1 templates matching github.com/varwof/types AIC definition
 *   - X509V3_EXT_METHOD: generic d2i/i2d via ASN1_ITEM + config v2i/i2v and
 *     `openssl x509 -text` printing (i2v)
 *   - AIC_validate(): field-level spec validation
 *   - Capability.parameters is treated as an OPAQUE octet string here; JSON
 *     interpretation lives in the libopenaic auxiliary layer (lib/).
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/x509v3.h>

#include "v3_aic.h"

/*
 * ── ASN.1 templates ───────────────────────────────────────────────────────
 */

ASN1_SEQUENCE(AIC_REASON) = {
    ASN1_SIMPLE(AIC_REASON, reasonCode, ASN1_UTF8STRING),
    ASN1_SIMPLE(AIC_REASON, description, ASN1_UTF8STRING)
} ASN1_SEQUENCE_END(AIC_REASON)

IMPLEMENT_ASN1_FUNCTIONS(AIC_REASON)

ASN1_SEQUENCE(AIC_CAPABILITY) = {
    ASN1_SIMPLE(AIC_CAPABILITY, schemeId, ASN1_UTF8STRING),
    ASN1_SIMPLE(AIC_CAPABILITY, capabilityId, ASN1_UTF8STRING),
    ASN1_EXP_OPT(AIC_CAPABILITY, parameters, ASN1_OCTET_STRING, 0)
} ASN1_SEQUENCE_END(AIC_CAPABILITY)

IMPLEMENT_ASN1_FUNCTIONS(AIC_CAPABILITY)

ASN1_SEQUENCE(AIC_PRINCIPALUID) = {
    ASN1_SIMPLE(AIC_PRINCIPALUID, version, ASN1_INTEGER),
    ASN1_SIMPLE(AIC_PRINCIPALUID, realm, ASN1_UTF8STRING),
    ASN1_SIMPLE(AIC_PRINCIPALUID, identifier, ASN1_UTF8STRING),
    ASN1_SIMPLE(AIC_PRINCIPALUID, keyHash, ASN1_OCTET_STRING),
    ASN1_EXP_OPT(AIC_PRINCIPALUID, hashAlgo, X509_ALGOR, 0)
} ASN1_SEQUENCE_END(AIC_PRINCIPALUID)

IMPLEMENT_ASN1_FUNCTIONS(AIC_PRINCIPALUID)

ASN1_SEQUENCE(AIC_DELEGATIONAUTH) = {
    ASN1_SIMPLE(AIC_DELEGATIONAUTH, reason, AIC_REASON),
    ASN1_SIMPLE(AIC_DELEGATIONAUTH, requestedLifetime, ASN1_INTEGER),
    ASN1_SIMPLE(AIC_DELEGATIONAUTH, timestamp, ASN1_GENERALIZEDTIME),
    ASN1_SIMPLE(AIC_DELEGATIONAUTH, nonce, ASN1_OCTET_STRING),
    ASN1_SIMPLE(AIC_DELEGATIONAUTH, signatureAlgorithm, X509_ALGOR),
    ASN1_SIMPLE(AIC_DELEGATIONAUTH, signatureValue, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(AIC_DELEGATIONAUTH)

IMPLEMENT_ASN1_FUNCTIONS(AIC_DELEGATIONAUTH)

ASN1_SEQUENCE(AIC_EXTFIELD) = {
    ASN1_SIMPLE(AIC_EXTFIELD, extnID, ASN1_OBJECT),
    ASN1_SIMPLE(AIC_EXTFIELD, critical, ASN1_BOOLEAN),
    ASN1_SIMPLE(AIC_EXTFIELD, extnValue, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(AIC_EXTFIELD)

IMPLEMENT_ASN1_FUNCTIONS(AIC_EXTFIELD)

ASN1_SEQUENCE(AIC) = {
    ASN1_SIMPLE(AIC, version, ASN1_INTEGER),
    ASN1_SIMPLE(AIC, agentId, ASN1_UTF8STRING),
    ASN1_SIMPLE(AIC, principalUid, AIC_PRINCIPALUID),
    ASN1_SEQUENCE_OF(AIC, capabilities, AIC_CAPABILITY),
    ASN1_SIMPLE(AIC, delegationMode, ASN1_INTEGER),
    ASN1_EXP_SEQUENCE_OF_OPT(AIC, authorizationConstraints, AIC_CAPABILITY, 0),
    ASN1_OPT(AIC, delegationAuthorization, AIC_DELEGATIONAUTH),
    ASN1_EXP_SEQUENCE_OF_OPT(AIC, extensions, AIC_EXTFIELD, 1)
} ASN1_SEQUENCE_END(AIC)

IMPLEMENT_ASN1_FUNCTIONS(AIC)

/*
 * ── accessors ─────────────────────────────────────────────────────────────
 */

const AIC_PRINCIPALUID *AIC_get_principalUid(const AIC *aic)
{
    return aic == NULL ? NULL : aic->principalUid;
}

const STACK_OF(AIC_CAPABILITY) *AIC_get_capabilities(const AIC *aic)
{
    return aic == NULL ? NULL : aic->capabilities;
}

const AIC_DELEGATIONAUTH *AIC_get_delegationAuthorization(const AIC *aic)
{
    return aic == NULL ? NULL : aic->delegationAuthorization;
}

/*
 * ── PrincipalUid communication format {realm}:{identifier}:{b64url} ──────
 */

static const char b64url_enc[64] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R',
    'S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j',
    'k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1',
    '2','3','4','5','6','7','8','9','-','_'
};

static int b64url_encoded_len(size_t n)
{
    return (int)(((n + 2) / 3) * 4);
}

static char *b64url_encode(const unsigned char *in, size_t n)
{
    char *out = OPENSSL_malloc(b64url_encoded_len(n) + 1);
    int i, j = 0;
    if (out == NULL)
        return NULL;
    for (i = 0; i + 2 < (int)n; i += 3) {
        unsigned int v = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out[j++] = b64url_enc[(v >> 18) & 63];
        out[j++] = b64url_enc[(v >> 12) & 63];
        out[j++] = b64url_enc[(v >> 6) & 63];
        out[j++] = b64url_enc[v & 63];
    }
    if (n % 3 == 1) {
        unsigned int v = (unsigned int)in[i] << 16;
        out[j++] = b64url_enc[(v >> 18) & 63];
        out[j++] = b64url_enc[(v >> 12) & 63];
    } else if (n % 3 == 2) {
        unsigned int v = (in[i] << 16) | (in[i + 1] << 8);
        out[j++] = b64url_enc[(v >> 18) & 63];
        out[j++] = b64url_enc[(v >> 12) & 63];
        out[j++] = b64url_enc[(v >> 6) & 63];
    }
    out[j] = '\0';
    return out;
}

char *AIC_principalUid_to_string(const AIC_PRINCIPALUID *pu)
{
    char *fp, *out;
    size_t rl, il, fl, len;
    if (pu == NULL || pu->realm == NULL || pu->identifier == NULL
        || pu->keyHash == NULL)
        return NULL;
    fp = b64url_encode(pu->keyHash->data, pu->keyHash->length);
    if (fp == NULL)
        return NULL;
    rl = ASN1_STRING_length(pu->realm);
    il = ASN1_STRING_length(pu->identifier);
    fl = strlen(fp);
    len = rl + 1 + il + 1 + fl;
    out = OPENSSL_malloc(len + 1);
    if (out == NULL) {
        OPENSSL_free(fp);
        return NULL;
    }
    memcpy(out, ASN1_STRING_get0_data(pu->realm), rl);
    out[rl] = ':';
    memcpy(out + rl + 1, ASN1_STRING_get0_data(pu->identifier), il);
    out[rl + 1 + il] = ':';
    memcpy(out + rl + 1 + il + 1, fp, fl);
    out[len] = '\0';
    OPENSSL_free(fp);
    return out;
}

static int b64url_val(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '-')
        return 62;
    if (c == '_')
        return 63;
    return -1;
}

/* Decode a base64url (RFC 4648 §5) string into raw bytes.
 * Returns malloc'd buffer (OPENSSL_malloc) and sets *outlen; NULL on error. */
static unsigned char *b64url_decode(const char *s, size_t *outlen)
{
    size_t n = strlen(s), i, j = 0;
    unsigned char *out;
    int v, acc = 0, bits = 0;

    if (outlen == NULL || n == 0)
        return NULL;
    out = OPENSSL_malloc(n / 4 * 3 + 3);
    if (out == NULL)
        return NULL;
    for (i = 0; i < n; i++) {
        v = b64url_val(s[i]);
        if (v < 0) {
            OPENSSL_free(out);
            return NULL;
        }
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[j++] = (unsigned char)((acc >> bits) & 0xff);
        }
    }
    /* Base64url omits '='; a trailing 2- or 3-char group leaves 4 or 2
     * padding bits that must be zero. */
    if (bits > 0 && ((acc & ((1 << bits) - 1)) != 0)) {
        OPENSSL_free(out);
        return NULL;
    }
    *outlen = j;
    return out;
}

AIC_PRINCIPALUID *AIC_principalUid_from_string(const char *s)
{
    const char *c1 = strchr(s, ':');
    const char *c2;
    AIC_PRINCIPALUID *pu;
    unsigned char *fp = NULL;
    size_t rl, il, fplen;

    if (c1 == NULL)
        return NULL;
    c2 = strchr(c1 + 1, ':');
    if (c2 == NULL)
        return NULL;
    rl = (size_t)(c1 - s);
    il = (size_t)(c2 - c1 - 1);
    if (rl < 1 || rl > 128 || il < 1 || il > 256)
        return NULL;
    if (strlen(c2 + 1) == 0)
        return NULL;

    /* keyFingerprint is base64url (RFC 4648 §5) of hashAlgo(SPKI); decode it
     * to the raw hash bytes stored in keyHash, mirroring the Go types layer
     * (MakePrincipalUidFromCert). */
    fp = b64url_decode(c2 + 1, &fplen);
    if (fp == NULL || fplen < 1 || fplen > 64)
        goto err;

    pu = AIC_PRINCIPALUID_new();
    if (pu == NULL)
        goto err;
    if (!ASN1_INTEGER_set(pu->version, 1)
        || !ASN1_STRING_set(pu->realm, s, (int)rl)
        || !ASN1_STRING_set(pu->identifier, c1 + 1, (int)il)
        || !ASN1_OCTET_STRING_set(pu->keyHash, fp, (int)fplen)) {
        AIC_PRINCIPALUID_free(pu);
        OPENSSL_free(fp);
        return NULL;
    }
    OPENSSL_free(fp);

    /* The communication format has no hashAlgo component; the Go types layer
     * defaults to SHA-256 when omitted (PrincipalUid.HashAlgoOID). Emit it
     * explicitly so TBS reconstruction matches a Go-signed DA (hashAlgo [0]
     * is part of the signed TBS). */
    if (pu->hashAlgo == NULL) {
        pu->hashAlgo = X509_ALGOR_new();
        if (pu->hashAlgo == NULL)
            goto err;
        X509_ALGOR_set0(pu->hashAlgo, OBJ_nid2obj(NID_sha256), V_ASN1_UNDEF, NULL);
    }
    return pu;
 err:
    OPENSSL_free(fp);
    return NULL;
}

/*
 * ── validation (spec v1.7.1) ──────────────────────────────────────────────
 */

int AIC_validate(const AIC *aic, const char **perr)
{
    int n, i;
    if (aic == NULL) {
        if (perr != NULL) *perr = "AIC is NULL";
        return 0;
    }
    if (aic->agentId == NULL || ASN1_STRING_length(aic->agentId) == 0) {
        if (perr != NULL) *perr = "AIC agentId is required";
        return 0;
    }
    if (aic->principalUid == NULL) {
        if (perr != NULL) *perr = "AIC principalUid is required";
        return 0;
    }
    if (aic->principalUid->realm == NULL || aic->principalUid->identifier == NULL
        || aic->principalUid->keyHash == NULL) {
        if (perr != NULL) *perr = "AIC principalUid incomplete";
        return 0;
    }
    {
        int rl = ASN1_STRING_length(aic->principalUid->realm);
        int il = ASN1_STRING_length(aic->principalUid->identifier);
        int kl = ASN1_STRING_length(aic->principalUid->keyHash);
        if (rl < 1 || rl > 128) {
            if (perr != NULL) *perr = "principalUid.realm length must be 1..128";
            return 0;
        }
        if (il < 1 || il > 256) {
            if (perr != NULL) *perr = "principalUid.identifier length must be 1..256";
            return 0;
        }
        if (kl < 1 || kl > 64) {
            if (perr != NULL) *perr = "principalUid.keyHash length must be 1..64";
            return 0;
        }
    }
    if (aic->delegationAuthorization == NULL) {
        if (perr != NULL) *perr = "AIC delegationAuthorization is required";
        return 0;
    }
    if (aic->delegationAuthorization->reason == NULL
        || aic->delegationAuthorization->reason->reasonCode == NULL
        || aic->delegationAuthorization->reason->description == NULL) {
        if (perr != NULL) *perr = "AIC delegationAuth reason incomplete";
        return 0;
    }
    {
        int rc = ASN1_STRING_length(
            aic->delegationAuthorization->reason->reasonCode);
        int rd = ASN1_STRING_length(
            aic->delegationAuthorization->reason->description);
        if (rc < 1 || rc > 64) {
            if (perr != NULL) *perr = "reason.reasonCode length must be 1..64";
            return 0;
        }
        if (rd < 1 || rd > 512) {
            if (perr != NULL) *perr = "reason.description length must be 1..512";
            return 0;
        }
    }
    if (aic->delegationAuthorization->nonce == NULL
        || ASN1_STRING_length(aic->delegationAuthorization->nonce) != 32) {
        if (perr != NULL) *perr = "delegationAuth.nonce must be exactly 32 bytes";
        return 0;
    }
    if (aic->delegationAuthorization->signatureAlgorithm == NULL
        || aic->delegationAuthorization->signatureValue == NULL
        || ASN1_STRING_length(aic->delegationAuthorization->signatureValue) == 0) {
        if (perr != NULL) *perr = "delegationAuth signature incomplete";
        return 0;
    }
    if (aic->delegationAuthorization->timestamp == NULL) {
        if (perr != NULL) *perr = "delegationAuth.timestamp is required";
        return 0;
    }
    n = aic->capabilities == NULL ? 0 : sk_AIC_CAPABILITY_num(aic->capabilities);
    if (n > AIC_MAX_CAPABILITIES) {
        if (perr != NULL) *perr = "capabilities exceed max limit (256 entries)";
        return 0;
    }
    {
        int nc = aic->authorizationConstraints == NULL
            ? 0 : sk_AIC_CAPABILITY_num(aic->authorizationConstraints);
        if (nc > AIC_MAX_CONSTRAINTS) {
            if (perr != NULL) *perr = "authorizationConstraints count exceeds max 32";
            return 0;
        }
        for (i = 0; i < nc; i++) {
            AIC_CAPABILITY *c = sk_AIC_CAPABILITY_value(aic->authorizationConstraints, i);
            const char *sid = c->schemeId == NULL ? "" :
                (const char *)ASN1_STRING_get0_data(c->schemeId);
            if (strcmp(sid, "constraint") != 0 && strcmp(sid, "constraint-v1") != 0) {
                if (perr != NULL) *perr = "authorizationConstraints schemeId must be constraint or constraint-v1";
                return 0;
            }
        }
        for (i = 0; i < n; i++) {
            AIC_CAPABILITY *c = sk_AIC_CAPABILITY_value(aic->capabilities, i);
            const char *sid = c->schemeId == NULL ? "" :
                (const char *)ASN1_STRING_get0_data(c->schemeId);
            if (strcmp(sid, "constraint") == 0 || strcmp(sid, "constraint-v1") == 0) {
                if (perr != NULL) *perr = "constraint scheme forbidden in capabilities";
                return 0;
            }
        }
        if (n == 0 && nc == 0) {
            if (perr != NULL) *perr = "capabilities and authorizationConstraints must not both be empty";
            return 0;
        }
    }
    return 1;
}

/*
 * ── config support (v2i) and text printing (i2v) ─────────────────────────
 *
 * v2i parses a [ aic ] section:
 *   agentId                = agent-7
 *   principalUid           = realm:identifier:keyFingerprint
 *   delegationMode         = authorized | representative
 *   capability             = scheme:capId[:b64urlParameters]      (repeatable)
 *   authorizationConstraint = constraint:capId[:b64urlParameters] (repeatable)
 *   delegationAuthDer      = <hex DER of AIC_DELEGATIONAUTH>
 *
 * i2v emits the reverse as CONF_VALUE pairs, used by `openssl x509 -text`
 * (X509V3_EXT_print → X509V3_add_value) and x509 -extfile round-trips.
 * parameters are printed as colon-hex when present (opaque bytes).
 */

static char *asn1_str_to_c(const ASN1_STRING *s)
{
    char *out;
    if (s == NULL || ASN1_STRING_length(s) < 0)
        return NULL;
    out = OPENSSL_malloc((size_t)ASN1_STRING_length(s) + 1);
    if (out == NULL)
        return NULL;
    if (ASN1_STRING_length(s) > 0)
        memcpy(out, ASN1_STRING_get0_data(s), (size_t)ASN1_STRING_length(s));
    out[ASN1_STRING_length(s)] = '\0';
    return out;
}

static int parse_cap(const char *value, int is_constraint,
                     STACK_OF(AIC_CAPABILITY) *st)
{
    const char *c1 = strchr(value, ':');
    const char *c2;
    AIC_CAPABILITY *cap = AIC_CAPABILITY_new();
    if (cap == NULL)
        return 0;
    if (c1 == NULL) {
        c2 = NULL;
    } else {
        c2 = strchr(c1 + 1, ':');
    }
    if (!ASN1_STRING_set(cap->schemeId, value,
                         c1 == NULL ? (int)strlen(value) : (int)(c1 - value)))
        goto err;
    if (c1 != NULL) {
        if (!ASN1_STRING_set(cap->capabilityId, c1 + 1,
                             c2 == NULL ? (int)strlen(c1 + 1) : (int)(c2 - c1 - 1)))
            goto err;
    }
    if (c2 != NULL && strlen(c2 + 1) > 0) {
        /* Third colon-separated part is the parameters blob. NCONF strips
         * quotes and treats ':' specially, so raw JSON like {"level":2} is
         * mangled in a config file. Support an explicit hex: prefix that
         * decodes to the raw bytes; anything else is stored as-is (b64url
         * text, opaque tokens, ...). */
        const char *p = c2 + 1;
        long plen = 0;
        unsigned char *pbuf = NULL;
        if (strncmp(p, "hex:", 4) == 0) {
            pbuf = OPENSSL_hexstr2buf(p + 4, &plen);
            if (pbuf == NULL)
                goto err;
        }
        /* parameters is an OPTIONAL [0] EXPLICIT field; AIC_CAPABILITY_new()
         * leaves it NULL, so materialize before setting. */
        if (cap->parameters == NULL) {
            cap->parameters = ASN1_OCTET_STRING_new();
            if (cap->parameters == NULL) {
                OPENSSL_free(pbuf);
                goto err;
            }
        }
        if (pbuf != NULL) {
            if (!ASN1_OCTET_STRING_set(cap->parameters, pbuf, (int)plen)) {
                OPENSSL_free(pbuf);
                goto err;
            }
            OPENSSL_free(pbuf);
        } else if (!ASN1_OCTET_STRING_set(cap->parameters,
                                          (const unsigned char *)p,
                                          (int)strlen(p))) {
            goto err;
        }
    }
    (void)is_constraint;
    if (sk_AIC_CAPABILITY_push(st, cap) <= 0)
        goto err;
    return 1;
 err:
    AIC_CAPABILITY_free(cap);
    return 0;
}

void *v2i_AIC(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
              STACK_OF(CONF_VALUE) *nval)
{
    AIC *aic = NULL;
    CONF_VALUE *cnf;
    int i, ok = 0;
    (void)method;
    (void)ctx;

    aic = AIC_new();
    if (aic == NULL)
        return NULL;
    /* version is DEFAULT 1 in the Go types; emit it explicitly so the
     * encoded AIC matches a Go-signed DA's TBS. */
    if (!ASN1_INTEGER_set(aic->version, 1))
        goto err;

    for (i = 0; i < sk_CONF_VALUE_num(nval); i++) {
        cnf = sk_CONF_VALUE_value(nval, i);
        if (strcmp(cnf->name, "agentId") == 0) {
            if (!ASN1_STRING_set(aic->agentId, cnf->value, (int)strlen(cnf->value)))
                goto err;
        } else if (strcmp(cnf->name, "principalUid") == 0) {
            AIC_PRINCIPALUID *pu = AIC_principalUid_from_string(cnf->value);
            if (pu == NULL)
                goto err;
            AIC_PRINCIPALUID_free(aic->principalUid);
            aic->principalUid = pu;
        } else if (strcmp(cnf->name, "delegationMode") == 0) {
            int dm = strcmp(cnf->value, "representative") == 0
                ? AIC_DELEGATION_REPRESENTATIVE : AIC_DELEGATION_AUTHORIZED;
            if (!ASN1_INTEGER_set(aic->delegationMode, dm))
                goto err;
        } else if (strcmp(cnf->name, "capability") == 0) {
            if (aic->capabilities == NULL
                && (aic->capabilities = sk_AIC_CAPABILITY_new_null()) == NULL)
                goto err;
            if (!parse_cap(cnf->value, 0, aic->capabilities))
                goto err;
        } else if (strcmp(cnf->name, "authorizationConstraint") == 0) {
            /* OPTIONAL SEQUENCE_OF fields start NULL; sk_push(NULL) does not
             * auto-create, so materialize the stack before the first push. */
            if (aic->authorizationConstraints == NULL
                && (aic->authorizationConstraints = sk_AIC_CAPABILITY_new_null()) == NULL)
                goto err;
            if (!parse_cap(cnf->value, 1, aic->authorizationConstraints))
                goto err;
        } else if (strcmp(cnf->name, "delegationAuthDer") == 0) {
            AIC_DELEGATIONAUTH *da = NULL;
            const unsigned char *der = NULL;
            long derlen;
            unsigned char *buf;
            long elen;
            buf = OPENSSL_hexstr2buf(cnf->value, &elen);
            if (buf == NULL)
                goto err;
            der = buf;
            derlen = elen;
            da = d2i_AIC_DELEGATIONAUTH(NULL, &der, derlen);
            OPENSSL_free(buf);
            if (da == NULL)
                goto err;
            AIC_DELEGATIONAUTH_free(aic->delegationAuthorization);
            aic->delegationAuthorization = da;
        }
    }

    if (!AIC_validate(aic, NULL))
        goto err;
    ok = 1;
 err:
    if (!ok) {
        AIC_free(aic);
        return NULL;
    }
    return aic;
}

STACK_OF(CONF_VALUE) *i2v_AIC(const X509V3_EXT_METHOD *method, void *ext,
                              STACK_OF(CONF_VALUE) *extlist)
{
    AIC *aic = (AIC *)ext;
    int i, n, nc;
    (void)method;
    if (aic == NULL)
        return NULL;

    {
        char *s = asn1_str_to_c(aic->agentId);
        if (s == NULL || !X509V3_add_value("agentId", s, &extlist)) {
            OPENSSL_free(s);
            return NULL;
        }
        OPENSSL_free(s);
    }
    if (aic->principalUid != NULL) {
        char *pu = AIC_principalUid_to_string(aic->principalUid);
        if (pu == NULL || !X509V3_add_value("principalUid", pu, &extlist)) {
            OPENSSL_free(pu);
            return NULL;
        }
        OPENSSL_free(pu);
    }
    {
        const char *dm = aic->delegationMode != NULL
            && ASN1_INTEGER_get(aic->delegationMode)
                == AIC_DELEGATION_REPRESENTATIVE
            ? "representative" : "authorized";
        if (!X509V3_add_value("delegationMode", dm, &extlist))
            return NULL;
    }
    n = aic->capabilities == NULL ? 0 : sk_AIC_CAPABILITY_num(aic->capabilities);
    for (i = 0; i < n; i++) {
        AIC_CAPABILITY *c = sk_AIC_CAPABILITY_value(aic->capabilities, i);
        char *line = NULL;
        char *sid = asn1_str_to_c(c->schemeId);
        char *cid = asn1_str_to_c(c->capabilityId);
        size_t llen = (sid != NULL ? strlen(sid) : 0) + (cid != NULL ? strlen(cid) : 0) + 2;
        if (c->parameters != NULL)
            llen += (size_t)c->parameters->length * 3;
        line = OPENSSL_malloc(llen + 1);
        if (line == NULL) {
            OPENSSL_free(sid);
            OPENSSL_free(cid);
            return NULL;
        }
        line[0] = '\0';
        if (sid != NULL)
            strcat(line, sid);
        strcat(line, ":");
        if (cid != NULL)
            strcat(line, cid);
        if (c->parameters != NULL) {
            strcat(line, ":");
            {
                int k;
                for (k = 0; k < c->parameters->length; k++)
                    sprintf(line + strlen(line), "%02x", c->parameters->data[k]);
            }
        }
        if (!X509V3_add_value("capability", line, &extlist)) {
            OPENSSL_free(sid);
            OPENSSL_free(cid);
            OPENSSL_free(line);
            return NULL;
        }
        OPENSSL_free(sid);
        OPENSSL_free(cid);
        OPENSSL_free(line);
    }
    nc = aic->authorizationConstraints == NULL
        ? 0 : sk_AIC_CAPABILITY_num(aic->authorizationConstraints);
    for (i = 0; i < nc; i++) {
        AIC_CAPABILITY *c = sk_AIC_CAPABILITY_value(aic->authorizationConstraints, i);
        char *line = NULL;
        char *sid = asn1_str_to_c(c->schemeId);
        char *cid = asn1_str_to_c(c->capabilityId);
        size_t llen = (sid != NULL ? strlen(sid) : 0) + (cid != NULL ? strlen(cid) : 0) + 2;
        if (c->parameters != NULL)
            llen += (size_t)c->parameters->length * 3;
        line = OPENSSL_malloc(llen + 1);
        if (line == NULL) {
            OPENSSL_free(sid);
            OPENSSL_free(cid);
            return NULL;
        }
        line[0] = '\0';
        if (sid != NULL)
            strcat(line, sid);
        strcat(line, ":");
        if (cid != NULL)
            strcat(line, cid);
        if (c->parameters != NULL) {
            strcat(line, ":");
            {
                int k;
                for (k = 0; k < c->parameters->length; k++)
                    sprintf(line + strlen(line), "%02x", c->parameters->data[k]);
            }
        }
        if (!X509V3_add_value("authorizationConstraint", line, &extlist)) {
            OPENSSL_free(sid);
            OPENSSL_free(cid);
            OPENSSL_free(line);
            return NULL;
        }
        OPENSSL_free(sid);
        OPENSSL_free(cid);
        OPENSSL_free(line);
    }
    if (aic->delegationAuthorization != NULL) {
        AIC_DELEGATIONAUTH *da = aic->delegationAuthorization;
        if (!X509V3_add_value("delegationAuthorization", "present", &extlist))
            return NULL;
        if (da->reason != NULL && da->reason->reasonCode != NULL) {
            char *s = asn1_str_to_c(da->reason->reasonCode);
            if (s == NULL || !X509V3_add_value("reasonCode", s, &extlist)) {
                OPENSSL_free(s);
                return NULL;
            }
            OPENSSL_free(s);
        }
        if (da->nonce != NULL) {
            char *hex = OPENSSL_buf2hexstr(da->nonce->data, da->nonce->length);
            if (hex == NULL || !X509V3_add_value("nonce", hex, &extlist)) {
                OPENSSL_free(hex);
                return NULL;
            }
            OPENSSL_free(hex);
        }
    }
    return extlist;
}

/*
 * ── X509V3_EXT_METHOD entry ────────────────────────────────────────────────
 *
 * Registered into crypto/x509/standard_exts.h by the patch (declared in
 * crypto/x509/ext_dat.h), alongside the NID_AIC registration in
 * crypto/objects/objects.txt → obj_mac.h.
 *
 *   { NID_AIC, X509V3_EXT_MULTILINE, ASN1_ITEM_ref(AIC),
 *     0, 0, 0, 0, 0, 0,
 *     i2v_AIC, v2i_AIC, 0, 0, NULL }
 */

const X509V3_EXT_METHOD ossl_v3_aic = {
    NID_AIC, X509V3_EXT_MULTILINE,
    ASN1_ITEM_ref(AIC),
    0, 0, 0, 0, 0, 0,
    i2v_AIC, v2i_AIC,
    0, 0,
    NULL
};
