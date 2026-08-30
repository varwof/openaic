# openaic Documentation

openaic adds support for the AIC (Authorization in Certificates) X.509v3
extension to OpenSSL 3.5 LTS. The docs are organized by protocol, mechanism,
and usage. Code comments and commit messages are in English; the Chinese
editions of these pages live under [zh-CN/](zh-CN/).

Language: [English](#) · [中文](zh-CN/index.md)

## Protocol & implementation

| Document | Contents |
|----------|----------|
| [asn1.md](asn1.md) | AIC ASN.1 definitions and their C structure mapping, consistency with the Go `varwof/types` reference |
| [verify.md](verify.md) | Verification hooks: layered design, `AIC_verify_cert` flow, signature-algorithm dispatch, security boundaries |

## Mechanism

| Document | Contents |
|----------|----------|
| [patch.md](patch.md) | Why a patch instead of a provider; the file-by-file diff; OID/symbol regeneration and the `make gen-patch` workflow |

## Usage

| Document | Contents |
|----------|----------|
| [config.md](config.md) | Issuing an AIC certificate from an OpenSSL config file (`-extfile`): fields, NCONF pitfalls, full example |
| [cli.md](cli.md) | `openaic-tool` reference: `print` / `verify`, all options and exit codes |

## Quick entry points

- Build & test: see the root `README.md` (`make fetch/build/test/test-aic`).
- Common Make targets: `fetch`, `build`, `test`, `test-aic`, `cross`,
  `gen-patch`, `clean`, `distclean`.
