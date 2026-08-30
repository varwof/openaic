# openaic — AIC (Authorization in Certificates) for OpenSSL 3.5 LTS

> **Maintainers wanted.** This is an open, community-oriented implementation.
> We welcome active maintainers for review, porting, packaging, and platform
> testing. See [CONTRIBUTING.md](../../.github/CONTRIBUTING.md) (org-wide) and
> the "Contributing" section below.

openaic adds native support for the Varwof **AIC** X.509v3 extension
(`1.3.6.1.4.1.66257.1.1`, IANA PEN 66257) to OpenSSL **3.5 LTS** (baseline
**3.5.7**, supported until 2030-04-08). AIC turns an ordinary end-entity
certificate into a machine-readable **delegation of authority**: the *agent*
certificate carries a signed DelegationAuthorization (`DA`) from a *principal*
user, together with capabilities, authorization constraints and an anti-replay
nonce.

The work is split into three layers:

1. **Extension method** (patched into libcrypto): parse, human-readable print
   and config-file generation of the AIC extension through an
   `X509V3_EXT_METHOD` (`openssl x509 -text`, `-extfile`). Per spec,
   `Capability.parameters` is treated as **opaque bytes**; no runtime
   dependency is introduced.
2. **Verification hooks** (patched into libcrypto): `aic_verify.c` verifies the
   DA signature (ECDSA / RSA-PKCS1 / RSA-PSS / Ed25519, dispatched by the
   signature-algorithm OID), cross-checks `principalUid.keyHash` against
   `SHA-256(SPKI)` of the user certificate, and optionally rejects replayed
   nonces. **Off by default** — stock OpenSSL verification behaviour is
   unchanged.
3. **Helper layer `libopenaic`** (outside the patch, vendored
   [cJSON](https://github.com/DaveGamble/cJSON), MIT): JSON parsing/validation
   of `parameters` (e.g. the `max-concurrent` constraint `{"max":N}`),
   human-readable pretty-print, base64url helpers, and the `openaic-tool` CLI.

README in English (this file) · [中文版 README](README.zh-CN.md)

Documentation: [docs/index.md](docs/index.md)

## Why AIC?

An ordinary X.509 certificate proves *who* an entity is; it says nothing about
*what it is allowed to do*. AI agents act on behalf of humans, often across
organizational boundaries, so a relying party needs to know not just the
agent's identity but also:

- which human (principal) delegated to this agent,
- what capabilities were granted, under what constraints,
- that the grant is fresh and cannot be replayed.

AIC (Authorization in Certificates) encodes exactly that evidence into the
certificate itself as an X.509v3 extension, so a gateway or proxy can decide
permission locally, offline, without consulting a central authority at
request time.

## Language matrix

AIC is implemented in five languages, all byte-compatible with the Go
reference:

| Language | Repository | Status |
|----------|-----------|--------|
| Go (reference) | [varwof/types](https://github.com/varwof/types) | complete |
| TypeScript | [varwof/aic-jwt](https://github.com/varwof/aic-jwt) | complete (18 tests) |
| C / OpenSSL | **this repo (openaic)** | complete (13 tests) |
| Java | [varwof/aic-lib-java](https://github.com/varwof/aic-lib-java) | complete (69 tests) |
| C# | [varwof/aic-lib-dotnet](https://github.com/varwof/aic-lib-dotnet) | complete (69 tests) |

## Background

AIC (Authorization in Certificates) embeds authorization evidence directly
into a certificate so that a gateway / proxy / relying party can decide
**what the certificate holder is allowed to do** without consulting a central
authority at request time. The certificate's `principalUid` identifies the
delegating user; the `DA` proves that the user actually delegated to this
agent (the private key holder of the certificate); `capability` /
`authorizationConstraint` bound what may be done; `nonce` defeats replay.

Normative Go definitions live in
[`github.com/varwof/types`](https://github.com/varwof/types); certificate
issuance/parsing lives in [`github.com/varwof/core`](https://github.com/varwof/core)
(`internal/ca`). This repository is the C/OpenSSL-side implementation and is
kept byte-compatible with those Go types (see [docs/asn1.md](docs/asn1.md)).

## Repository layout

```
openaic/
├── patch/openssl-3.5.7-aic.patch   the distributable patch (source of truth;
│                                   regenerate via `make gen-patch`)
├── src/                            C sources the patch adds to libcrypto
│   ├── v3_aic.c / v3_aic.h         extension method: ASN.1 + print + config v2i/i2v
│   └── aic_verify.c / aic_verify.h verification hooks (DA verify / SPKI / replay)
├── lib/                            libopenaic (outside the patch)
│   ├── openaic.c / openaic.h       parameter JSON, pretty-print, validation
│   └── cjson/                      vendored cJSON (MIT)
├── cmd/openaic-tool/               CLI: print / verify
├── test/                           unit tests + Go cross-consistency vectors
│   ├── aic_ext_test.c              extension tests against the patched build
│   ├── openaic_json_test.c         libopenaic JSON/validation tests
│   └── vectors/main.go             Go (varwof/types) emits shared DER vectors
├── docs/                           ASN.1 mapping, verify semantics, config,
│                                   CLI reference, patch mechanics
└── ci/build.sh                     fetch → patch → build (single step)
```

## Quick start

```sh
make fetch        # download & sha256-verify the openssl-3.5.7 tarball
make build        # unpack → copy surgery tree → Configure → make (serial)
make test         # full OpenSSL test suite (4499 tests) + openaic tests
make test-aic     # rebuild Go vectors + run AIC extension tests
make gen-patch    # regenerate patch/openssl-3.5.7-aic.patch from the surgery tree
```

Notes:

- `make build` builds into `patch-dir/` (a copy of the surgery tree
  `openssl-src/`). `-j1` is used deliberately: OpenSSL 3.5's `-MMD` dep files
  race under parallel make (see [docs/patch.md](docs/patch.md)).
- `config.mk` sets `no-asm` because this host's binutils predates AVX-512; that
  is a build option, not part of the patch.
- Download goes through a Tor SOCKS5 proxy by default
  (`CONNECTION_PROXY := 127.0.0.1:9050` in `config.mk`); set it empty for a
  direct download.
- The Go vector step requires `github.com/varwof/types` at `../types`
  (replace directive in `go.mod`).

## 5-minute end-to-end check

```sh
make fetch && make build        # patched OpenSSL 3.5.7
make test-aic                   # AIC extension tests (13 cases)
```

Then walk through [docs/config.md](docs/config.md), which contains a complete
`[ aicbody ]` config snippet and the exact `openssl x509 -req -extfile`
command to issue an AIC certificate, followed by `openaic-tool verify`
against the user-principal certificate.

## The AIC extension

- OID: `1.3.6.1.4.1.66257.1.1` → `NID_AIC` 1487
- Critical: `false` (spec v1.7.1)
- Structs: `AIC`, `AIC_PRINCIPALUID`, `AIC_CAPABILITY`, `AIC_REASON`,
  `AIC_DELEGATIONAUTH`, `AIC_DATBS` — see [docs/asn1.md](docs/asn1.md) for the
  ASN.1 ↔ C mapping.
- Issuing an AIC cert from a config file:
  [docs/config.md](docs/config.md).

Example (rebuilt from the Go vector):

```text
AIC extension (critical=0):
  version: 1
  agentId: agent-7
  principalUid: acme:alice:OAeuHp-nMa4Retf8rm04-okJoRuhxOWzLQV4a7G4qCQ
  capability: tt:smart-device:{"level":2}
  authorizationConstraint: constraint:max-concurrent:{"max":3}
  delegationAuthorization:
    reasonCode: maintenance
    requestedLifetime: 3600
    timestamp: 2026-08-29 20:05:27Z
    nonce (32 bytes)
```

## Verification hooks (off by default)

```c
#include <openssl/x509_vfy.h>
#include "aic_verify.h"

/* Enable via the verify callback + param flag (chain position 0). */
X509_VERIFY_PARAM_set_aic_flags(ctx->param, AIC_VERIFY_REQUIRE
                                              | AIC_VERIFY_CHECK_SPKI
                                              | AIC_VERIFY_VERIFY_DA);
X509_STORE_CTX_set_verify_cb(ctx, aic_verify_cb);

/* Or call directly, independent of X509_STORE_CTX. */
AIC_VERIFY_OPTS opts = { .flags = AIC_VERIFY_CHECK_SPKI | AIC_VERIFY_VERIFY_DA };
int rc = AIC_verify_cert(agent_cert, untrusted, &opts);
/* rc == 1 verified, 0 AIC present but failed, -1 no AIC (not required) */
```

See [docs/verify.md](docs/verify.md) for the full verification flow, signature
algorithm dispatch and security boundaries.

## CLI

```sh
openaic-tool print  <agent.pem>
openaic-tool verify <agent.pem> --user <principal.pem> [--no-check-spki]
                    [--no-verify-da] [--require] [--replay]
```

Reference: [docs/cli.md](docs/cli.md).

## Contributing

This SDK is community-maintained. You do not need to be a core team member
to contribute:

- **Report bugs / request features** — open an issue; bug reports do not
  require a contributor agreement.
- **Send a patch** — code contributions go through pull requests and require a
  DCO sign-off (a `Signed-off-by` line in the commit message). The org-wide
  process is in [CONTRIBUTING.md](../../.github/CONTRIBUTING.md).
- **Become a maintainer** — after a few merged PRs, ask for collaborator
  access; regular reviewers are invited to take ownership of this SDK.

## License

Apache-2.0. `lib/cjson` is vendored under the separate MIT license. See
[LICENSE](LICENSE).

## Community

Questions, feedback, and port status: [AIC Discussions](https://github.com/varwof/aic-jwt/discussions)
