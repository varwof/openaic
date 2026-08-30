# openaic-tool reference

`openaic-tool` links against the patched OpenSSL 3.5 LTS, libopenaic and
cJSON, and provides parsing/printing and verification of the AIC extension.

## Build

```sh
make build            # build the patched OpenSSL first
cc -o openaic-tool cmd/openaic-tool/main.c lib/openaic.c lib/cjson/cJSON.c \
    -Ilib -Ilib/cjson -Isrc -Ipatch-dir/include \
    -Lpatch-dir -Wl,-rpath,$(PWD)/patch-dir -lcrypto -lssl -O2
```

## General

```sh
openaic-tool <print|verify> ...
```

With no arguments or an unknown command, prints usage and exits 2.

## print

```sh
openaic-tool print <agent.pem>
```

Parses and prints the AIC extension:

- No AIC: prints `certificate has no AIC extension`, exits 0;
- AIC present: prints each field; `capability`/`authorizationConstraint`
  parameters are pretty-printed when valid JSON (e.g. `params={"level":2}`),
  otherwise marked `params=<non-json N bytes>`;
- `AIC_validate` failure prints `WARNING: fails spec validation`.

Example:

```text
AIC extension (critical=0):
  version: 1
  agentId: agent-7
  principalUid: acme:alice:OAeuHp-nMa4Retf8rm04-okJoRuhxOWzLQV4a7G4qCQ
  capability: tt:smart-device params={"level":2}
  authorizationConstraint: constraint:max-concurrent params={"max":3}
  delegationAuthorization:
    reasonCode: maintenance
    requestedLifetime: 3600
    timestamp: 2026-08-29 20:05:27Z
    nonce (32 bytes)
    signatureValue (72 bytes)
```

## verify

```sh
openaic-tool verify <agent.pem> [options]
```

Performs semantic verification of the end-entity certificate's AIC
(`AIC_verify_cert`).

| Option | Effect |
|--------|--------|
| `--user <principal.pem>` | principal cert; repeatable. `--verify-da` needs at least one |
| `--check-spki` | require `principalUid.keyHash == SHA-256(SPKI)` (default on) |
| `--no-check-spki` | skip the keyHash cross-check; still uses `--user` cert for DA verify |
| `--verify-da` | verify the DA signature (default on) |
| `--no-verify-da` | skip DA signature verification |
| `--require` | fail if the cert lacks an AIC extension |
| `--no-require` | tolerate missing AIC (return success with a notice, default) |
| `--replay` | anti-replay: reject reused nonces (stateful, in-process one-shot) |

Exit codes:

| Result | Prints | Exit code |
|--------|--------|-----------|
| verification passed | `AIC verified OK` | 0 |
| AIC present but failed | `AIC verification FAILED` | 1 |
| no AIC and not `--require` | `certificate has no AIC extension (not required)` | 0 |
| argument/usage error | usage message | 2 |

Typical usage:

```sh
# default: keyHash cross-check + DA signature
openaic-tool verify agent.pem --user user-principal.pem

# structural check only (no signature verification)
openaic-tool verify agent.pem --no-verify-da

# skip the keyHash cross-check (e.g. principal SPKI rotated) but still verify
openaic-tool verify agent.pem --user user-principal.pem --no-check-spki

# with anti-replay (second use of the same nonce is rejected)
openaic-tool verify agent.pem --user user-principal.pem --replay
```

## Mapping to `AIC_verify_cert` return values

| Exit code | `AIC_verify_cert` return |
|-----------|--------------------------|
| 0 | 1 (pass) or -1 (no AIC, not required) |
| 1 | 0 (AIC present but failed) |
| 2 | — (usage error, not invoked) |

Verification semantics (flow, signature-algorithm dispatch, security
boundaries) are in [verify.md](verify.md).
