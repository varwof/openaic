# AIC ASN.1 ↔ C structure mapping

This document describes the ASN.1 templates implemented in `src/v3_aic.c`
and their consistency with `github.com/varwof/types`
(`DelegationAuthTBS` / `AIC`) and `github.com/varwof/core`
(`internal/ca/aic.go`).

Extension OID: `1.3.6.1.4.1.66257.1.1` (IANA PEN 66257, Varwof PKI).
Critical: `false` (spec v1.7.1).

## Top-level structure AIC

```
AIC ::= SEQUENCE {
    version                  INTEGER DEFAULT 1,
    agentId                  UTF8String,
    principalUid             PrincipalUid,
    capabilities             SEQUENCE OF Capability,
    delegationMode           INTEGER DEFAULT 0,
    authorizationConstraints [0] EXPLICIT SEQUENCE OF Capability OPTIONAL,
    delegationAuthorization  SEQUENCE OPTIONAL,   -- required by spec; AIC_validate() enforces
    extensions               [1] EXPLICIT SEQUENCE OF ExtField OPTIONAL
}
```

| Go (types/ca)          | C (openaic)                   | Tag                      |
|------------------------|-------------------------------|--------------------------|
| AIC.Version            | AIC.version (ASN1_INTEGER)    | INTEGER                  |
| AIC.AgentId            | AIC.agentId (UTF8String)      | UTF8String               |
| AIC.PrincipalUid       | AIC.principalUid              | SEQUENCE                 |
| AIC.Capabilities       | AIC.capabilities (STACK_OF)   | SEQUENCE OF              |
| AIC.DelegationMode     | AIC.delegationMode            | INTEGER                  |
| AIC.AuthorizationConstraints | AIC.authorizationConstraints | [0] EXPLICIT SEQUENCE OF OPTIONAL |
| AIC.DelegationAuthorization | AIC.delegationAuthorization | SEQUENCE OPTIONAL (required) |
| AIC.Extensions         | AIC.extensions                | [1] EXPLICIT SEQUENCE OF OPTIONAL |

## PrincipalUid

```
PrincipalUid ::= SEQUENCE {
    version    INTEGER DEFAULT 1,
    realm      UTF8String (SIZE(1..128)),
    identifier UTF8String (SIZE(1..256)),
    keyHash    OCTET STRING (SIZE(1..64)),
    hashAlgo   [0] EXPLICIT AlgorithmIdentifier OPTIONAL
}
```

`keyHash = hashAlgo(SPKI)`; defaults to SHA-256 when `hashAlgo` is absent.
Communication format: `{realm}:{identifier}:{base64url keyFingerprint}`.

> Note: `AIC_principalUid_from_string()` inside libcrypto only performs
> structural parsing and keeps the keyFingerprint's raw base64url bytes;
> base64url decode/encode normalization happens in the libopenaic layer
> (see [verify.md](verify.md) "Layered design").

## Capability

```
Capability ::= SEQUENCE {
    schemeId     UTF8String,
    capabilityId UTF8String,
    parameters   [0] EXPLICIT OCTET STRING OPTIONAL
}
```

`parameters` holds **opaque bytes**. libcrypto passes them through unchanged
(hex print / raw d2i); JSON semantics (e.g. `{"max":N}`) are handled by
libopenaic + cJSON.

## Reason / DelegationAuthorization

```
Reason ::= SEQUENCE {
    reasonCode  UTF8String (SIZE(1..64)),
    description UTF8String (SIZE(1..512))
}

DelegationAuthorization ::= SEQUENCE {
    reason             Reason,
    requestedLifetime  INTEGER DEFAULT 0,   -- valid 1..86400, 0 → 3600
    timestamp          GeneralizedTime,
    nonce              OCTET STRING (32),
    signatureAlgorithm AlgorithmIdentifier,
    signatureValue     OCTET STRING
}
```

## DelegationAuthTBS (DA signature input, verification path only)

Strictly matches `types.DelegationAuthTBS` (field order + tags). It is
rebuilt in `aic_verify.c` through the internal `AIC_DATBS` template, `i2d`-ed,
and used as the signature input:

```
DelegationAuthTBS ::= SEQUENCE {
    version                  INTEGER DEFAULT 1,
    agentId                  UTF8String,
    principalUid             PrincipalUid,
    reason                   Reason,
    capabilities             SEQUENCE OF Capability,
    delegationMode           INTEGER DEFAULT 0,
    authorizationConstraints [0] EXPLICIT SEQUENCE OF Capability OPTIONAL,
    requestedLifetime        INTEGER DEFAULT 0,
    timestamp                GeneralizedTime,
    nonce                    OCTET STRING
}
```

## Consistency verification

- Forward: Go (`test/vectors`) emits `aic.der` → C side `d2i_AIC` parses it →
  per-field assertions (`test/aic_ext_test.c`).
- Reverse: C side `i2d_AIC` output → Go side `types.ParseAIC` parses and
  compares (planned for a later milestone).
- Value semantics (keyHash / lengths / schemeId allow-list) are jointly
  constrained by each side's validator (`AIC_validate` / `ValidateAIC`);
  the cross-tests guarantee agreement.
