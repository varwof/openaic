/*
 * SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
 * SPDX-License-Identifier: Apache-2.0
 *
 * v3_aic.h — AIC (Authorization in Certificates) X.509v3 extension.
 *
 * This file is part of the openaic patch for OpenSSL 3.5 LTS. It is dropped
 * into crypto/x509/ by the patch and compiled into libcrypto. It follows the
 * spec of github.com/varwof/types and the reference implementation in
 * github.com/varwof/core (internal/ca/aic.go).
 *
 * Extension OID:  1.3.6.1.4.1.66257.1.1   (IANA PEN 66257, Varwof PKI)
 * Critical:       false (spec v1.7.1)
 */

#ifndef OSSL_CRYPTO_X509V3_V3_AIC_H
# define OSSL_CRYPTO_X509V3_V3_AIC_H

# include <openssl/asn1.h>
# include <openssl/asn1t.h>
# include <openssl/x509v3.h>

# ifdef __cplusplus
extern "C" {
# endif

/* DelegationMode (spec §3.x). */
# define AIC_DELEGATION_AUTHORIZED     0
# define AIC_DELEGATION_REPRESENTATIVE 1

/* Max capability count guards (spec v1.7.1). */
# define AIC_MAX_CAPABILITIES          256
# define AIC_MAX_CONSTRAINTS           32

/*
 * Reason — the DA reason description (audit/display only).
 * ASN.1 SEQUENCE { reasonCode UTF8String, description UTF8String }
 */
typedef struct AIC_REASON_st {
    ASN1_UTF8STRING *reasonCode;   /* 1..64 */
    ASN1_UTF8STRING *description;  /* 1..512 */
} AIC_REASON;

DECLARE_ASN1_FUNCTIONS(AIC_REASON)

/*
 * AIC_CAPABILITY — a single capability.
 * ASN.1 SEQUENCE {
 *   schemeId     UTF8String,
 *   capabilityId UTF8String,
 *   parameters   [0] EXPLICIT OCTET STRING OPTIONAL   -- opaque bytes
 * }
 */
typedef struct AIC_CAPABILITY_st {
    ASN1_UTF8STRING *schemeId;
    ASN1_UTF8STRING *capabilityId;
    ASN1_OCTET_STRING *parameters;   /* opaque; JSON only at libopenaic layer */
} AIC_CAPABILITY;

DECLARE_ASN1_FUNCTIONS(AIC_CAPABILITY)
DEFINE_STACK_OF(AIC_CAPABILITY)

/*
 * AIC_PRINCIPALUID — principal identity.
 * ASN.1 SEQUENCE {
 *   version    INTEGER DEFAULT 1,
 *   realm      UTF8String (1..128),
 *   identifier UTF8String (1..256),
 *   keyHash    OCTET STRING (SIZE(1..64)),
 *   hashAlgo   [0] EXPLICIT AlgorithmIdentifier OPTIONAL
 * }
 * keyHash = hashAlgo(SPKI); hashAlgo defaults to SHA-256 when omitted.
 * Communication format: {realm}:{identifier}:{base64url keyFingerprint}.
 */
typedef struct AIC_PRINCIPALUID_st {
    ASN1_INTEGER *version;
    ASN1_UTF8STRING *realm;
    ASN1_UTF8STRING *identifier;
    ASN1_OCTET_STRING *keyHash;
    X509_ALGOR *hashAlgo;    /* [0] EXPLICIT, OPTIONAL */
} AIC_PRINCIPALUID;

DECLARE_ASN1_FUNCTIONS(AIC_PRINCIPALUID)

/*
 * AIC_DELEGATIONAUTH — cryptographic evidence of authorization.
 * ASN.1 SEQUENCE {
 *   reason             Reason,
 *   requestedLifetime INTEGER DEFAULT 0 (effective 1..86400, 0 → 3600),
 *   timestamp          GeneralizedTime,
 *   nonce              OCTET STRING (32 bytes),
 *   signatureAlgorithm AlgorithmIdentifier,
 *   signatureValue     OCTET STRING
 * }
 */
typedef struct AIC_DELEGATIONAUTH_st {
    AIC_REASON *reason;
    ASN1_INTEGER *requestedLifetime;
    ASN1_GENERALIZEDTIME *timestamp;
    ASN1_OCTET_STRING *nonce;
    X509_ALGOR *signatureAlgorithm;
    ASN1_OCTET_STRING *signatureValue;
} AIC_DELEGATIONAUTH;

DECLARE_ASN1_FUNCTIONS(AIC_DELEGATIONAUTH)

/* AIC_EXTFIELD — vendor extension slot in [1]. */
typedef struct AIC_EXTFIELD_st {
    ASN1_OBJECT *extnID;
    ASN1_BOOLEAN critical;
    ASN1_OCTET_STRING *extnValue;
} AIC_EXTFIELD;

DECLARE_ASN1_FUNCTIONS(AIC_EXTFIELD)

/*
 * AIC — the X.509v3 extension ASN.1 structure.
 * ASN.1 SEQUENCE {
 *   version                  INTEGER DEFAULT 1,
 *   agentId                  UTF8String,
 *   principalUid             PrincipalUid,
 *   capabilities             SEQUENCE OF Capability,
 *   delegationMode           INTEGER DEFAULT 0,
 *   authorizationConstraints [0] EXPLICIT SEQUENCE OF Capability OPTIONAL,
 *   delegationAuthorization  SEQUENCE OPTIONAL,   -- required by spec; enforced
 *   extensions               [1] EXPLICIT SEQUENCE OF ExtField OPTIONAL
 * }
 */
typedef struct AIC_st {
    ASN1_INTEGER *version;
    ASN1_UTF8STRING *agentId;
    AIC_PRINCIPALUID *principalUid;
    STACK_OF(AIC_CAPABILITY) *capabilities;
    ASN1_INTEGER *delegationMode;
    STACK_OF(AIC_CAPABILITY) *authorizationConstraints;  /* [0] EXPLICIT */
    AIC_DELEGATIONAUTH *delegationAuthorization;         /* required */
    STACK_OF(AIC_EXTFIELD) *extensions;                  /* [1] EXPLICIT */
} AIC;

DECLARE_ASN1_FUNCTIONS(AIC)

/*
 * Semantic validation (spec v1.7.1): verifies field-level constraints that
 * the ASN.1 decoder cannot express (lengths, nonce size, lifetime range,
 * capability counts, DA presence, constraint scheme whitelist).
 * Returns 1 on success, 0 on failure (set *perr to a static message if
 * non-NULL). Does NOT verify signatures — see aic_verify.h for that.
 */
int AIC_validate(const AIC *aic, const char **perr);

/* Convenience accessors (safe on NULL/absent). */
const AIC_PRINCIPALUID *AIC_get_principalUid(const AIC *aic);
const STACK_OF(AIC_CAPABILITY) *AIC_get_capabilities(const AIC *aic);
const AIC_DELEGATIONAUTH *AIC_get_delegationAuthorization(const AIC *aic);

/* PrincipalUid communication-format helpers. */
char *AIC_principalUid_to_string(const AIC_PRINCIPALUID *pu);
AIC_PRINCIPALUID *AIC_principalUid_from_string(const char *s);

# ifdef __cplusplus
}
# endif

#endif
