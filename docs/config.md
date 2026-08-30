# Issuing an AIC certificate from a config file

`openssl x509 -req -extfile <cfg> -extensions aic` invokes the patch's
`v2i_AIC`, which parses the AIC fields from an OpenSSL config section. This is
convenient for tests and manual/ops issuance; for production, prefer the Go
side (`github.com/varwof/core`, `internal/ca`).

## Config section structure

Define an `[ aic ]` extension section that references a body section with
`aic = @aicbody`:

```ini
[ aic ]
aic = @aicbody

[ aicbody ]
agentId = agent-7
principalUid = acme:alice:OAeuHp-nMa4Retf8rm04-okJoRuhxOWzLQV4a7G4qCQ
delegationMode = authorized
capability = tt:smart-device:hex:7b226c6576656c223a327d
authorizationConstraint = constraint:max-concurrent:hex:7b226d6178223a337d
delegationAuthDer = 3081ba302b0c0b6d61696e74656e616e63650c1c7363686564756c6564206d61696e74656e616e63652077696e646f7702020e10180f32303236303832393230303532375a042049a619a38d5408bce386d4ee2dfcca2a796b372d7ad32c5c17035c19f25acaf1300a06082a8648ce3d04030204483046022100fb09b83cca0813694ee7cc57d30cfb773a4c25d073c3eb9c712d4c83c896a2ae022100b8ee65b411940cb39593f3a2c606e54a1635d4c47d038708a4e917aa2e0b9977
```

```sh
openssl x509 -req -in agent.csr -signkey agent.key \
    -extfile aic.cnf -extensions aic -out agent-aic.pem
```

## Field reference

| Field | Required | Value | Notes |
|-------|----------|-------|-------|
| `agentId` | yes | UTF-8 text | agent identifier |
| `principalUid` | yes | `realm:identifier:base64url` | principal identity; `keyHash` is base64url (unpadded) of `hashAlgo(SPKI)` |
| `delegationMode` | no | `authorized` \| `representative` | defaults to `authorized` |
| `capability` | no* | `scheme:capabilityId[:params]` | repeatable; *spec requires at least one |
| `authorizationConstraint` | no | same as `capability` | repeatable |
| `delegationAuthDer` | no | hex DER | full `DelegationAuthorization` DER (including signature) |

`v2i_AIC` validates all fields; any invalid field fails the whole section
(`AIC_validate`).

## Third-segment parameters for capability / constraint

`Capability.parameters` is a `[0] EXPLICIT OCTET STRING OPTIONAL`, and per
spec holds **opaque bytes**. The third config segment has two forms:

- `scheme:capabilityId:hex:<HEX>` — decodes hex into raw bytes (**recommended**,
  see below);
- `scheme:capabilityId:<text>` — stored as-is as ASCII bytes (e.g. base64url
  tokens, plain text without quotes).

JSON semantics of `parameters` (e.g. `{"level":2}`, `{"max":3}`) are parsed by
the libopenaic layer; libcrypto only passes bytes through.

### NCONF pitfall: why you must use `hex:`

OpenSSL's NCONF parser **strips quotes** and treats `:` specially. A value like
`capability = tt:smart-device:{"level":2}` is actually read as
`tt:smart-device:{level:2}` — the JSON quotes are lost and the inner `:` can
confuse parsing. This previously caused DA verification to fail (rebuilt TBS
did not match what was signed). **Use the `hex:` prefix for any parameter
containing quotes or colons:**

```ini
# wrong: NCONF strips the quotes, mangling the parameter
capability = tt:smart-device:{"level":2}

# correct: hex prefix, raw bytes intact
capability = tt:smart-device:hex:7b226c6576656c223a327d
# {"level":2} → 7b226c6576656c223a327d
# {"max":3}   → 7b226d6178223a337d
```

To get the hex of JSON bytes:

```sh
printf '%s' '{"level":2}' | xxd -p -c 1000   # 7b226c6576656c223a327d
```

## Sourcing delegationAuthDer

`delegationAuthDer` is the signed `DelegationAuthorization` DER. Extract it
from a known-good certificate with `asn1parse` (offsets/lengths change when
vectors are regenerated):

```sh
openssl x509 -in agent.pem -outform DER -out a.der
openssl asn1parse -inform DER -in a.der -i   # locate the DA SEQUENCE offset & length
dd if=a.der bs=1 skip=<OFFSET> count=<LEN> | xxd -p -c 1000
```

## Verifying the resulting certificate

```sh
openssl x509 -in agent-aic.pem -noout -text | grep -A8 AIC
openaic-tool verify agent-aic.pem --user user-principal.pem
```

Note: the certificate's `principalUid.keyHash`, the `capability`/`constraint`
parameters, and the TBS inside `delegationAuthDer` must all match exactly what
was signed, otherwise DA verification fails (`AIC_verify_cert` returns 0).
That is why generating parameters from the Go side vectors is recommended.
