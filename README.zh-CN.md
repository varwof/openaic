# openaic — 为 OpenSSL 3.5 LTS 提供 AIC（证书内授权）支持

> **⚠️ 实验性。** 本 C/OpenSSL 实现需要从源码打补丁并重建 OpenSSL 3.5，当前
> **不维护到 CI 全绿**，可能无法在所有环境构建。**不可用于生产。** 评估请使用
> Go 实现（[varwof/core](https://github.com/varwof/core)）或其他语言移植。

> **招募维护者。** 这是一个开放、面向社区的实现。我们欢迎活跃维护者参与
> 代码审查、移植、打包与平台测试。参与方式见
> [CONTRIBUTING.md](../../.github/CONTRIBUTING.md)（org 级）与下文"贡献"一节。

openaic 让 OpenSSL **3.5 LTS**（基线 **3.5.7**，支持至 2030-04-08）原生支持
Varwof **AIC** X.509v3 扩展（`1.3.6.1.4.1.66257.1.1`，IANA PEN 66257）。
AIC 把一张普通的终端实体证书变成**机器可读的授权委托**：*代理（agent）*
证书携带由*主体（principal）* 用户签名的 DelegationAuthorization（DA），
并附带 capability、授权约束与防重放 nonce。

项目分为三层：

1. **扩展方法层**（打进 libcrypto 的补丁）：通过 `X509V3_EXT_METHOD` 支持
   AIC 扩展的解析、人类可读打印与配置文件生成（`openssl x509 -text`、
   `-extfile`）。按规范，`Capability.parameters` 作为**不透明字节**处理，
   不引入运行时外部依赖。
2. **验证钩子层**（打进 libcrypto 的补丁）：`aic_verify.c` 按签名算法 OID
   分发完成 DA 验签（ECDSA / RSA-PKCS1 / RSA-PSS / Ed25519），交叉校验
   `principalUid.keyHash` 是否等于用户证书的 `SHA-256(SPKI)`，并可选拒绝
   重放 nonce。**默认关闭**，不改变 OpenSSL 原厂验证行为。
3. **辅助层 `libopenaic`**（补丁外，vendored
   [cJSON](https://github.com/DaveGamble/cJSON)，MIT）：`parameters` 的 JSON
   解析/校验（如 `max-concurrent` 约束 `{"max":N}`）、人类可读 pretty-print、
   base64url 工具，以及 `openaic-tool` CLI。

英文 README：[README.md](README.md) · 中文版（本文件）

文档入口：[docs/zh-CN/index.md](docs/zh-CN/index.md)

## 为什么需要 AIC？

普通 X.509 证书只证明*实体是谁*，不证明*它能做什么*。AI agent 代表人类行动，
且常跨组织边界，因此依赖方需要知道的不只是 agent 身份，还包括：

- 哪个责任人（principal）把权限委托给了这个 agent；
- 授予了哪些能力、在什么约束之下；
- 授权是否新鲜、能否防重放。

AIC（Authorization in Certificates）把上述证据作为 X.509v3 扩展直接编码进
证书，网关或代理即可在本地、离线地决定权限，无需在请求时咨询中央权威。

## 语言矩阵

AIC 有五种语言实现，全部与 Go 参考实现字节级兼容：

| 语言 | 仓库 | 状态 |
|------|------|------|
| Go（参考实现） | [varwof/types](https://github.com/varwof/types) | 完整 |
| TypeScript | [varwof/aic-jwt](https://github.com/varwof/aic-jwt) | 完整（18 测试） |
| C / OpenSSL | **本仓库（openaic）** | 实验性（13 测试） |
| Java | [varwof/aic-lib-java](https://github.com/varwof/aic-lib-java) | 完整（69 测试） |
| C# | [varwof/aic-lib-dotnet](https://github.com/varwof/aic-lib-dotnet) | 完整（69 测试） |

## 背景

AIC（Authorization in Certificates）把授权证据直接嵌入证书，使网关/代理/
依赖方无需在请求时咨询中央权威即可判断**证书持有者被允许做什么**：
`principalUid` 标识委托用户；`DA` 证明该用户确实授权给本代理（证书私钥持有者）；
`capability` / `authorizationConstraint` 限定可执行的操作；`nonce` 用于防重放。

规范性的 Go 类型定义在 [`github.com/varwof/types`](https://github.com/varwof/types)，
证书签发/解析在 [`github.com/varwof/core`](https://github.com/varwof/core)
（`internal/ca`）。本仓库是 C/OpenSSL 侧实现，与上述 Go 类型保持**逐字节兼容**
（见 [docs/zh-CN/asn1.md](docs/zh-CN/asn1.md)）。

## 仓库结构

```
openaic/
├── patch/openssl-3.5.7-aic.patch   可分发补丁（唯一真相源；`make gen-patch` 再生成）
├── src/                            补丁新增进 libcrypto 的 C 源
│   ├── v3_aic.c / v3_aic.h         扩展方法：ASN.1 + 打印 + config v2i/i2v
│   └── aic_verify.c / aic_verify.h 验证钩子（DA 验签 / SPKI 交叉校验 / replay）
├── lib/                            libopenaic（补丁外辅助层）
│   ├── openaic.c / openaic.h       参数 JSON、pretty-print、校验
│   └── cjson/                      vendored cJSON（MIT）
├── cmd/openaic-tool/               CLI：print / verify
├── test/                           单测 + Go 交叉一致性向量
│   ├── aic_ext_test.c              针对补丁后构建的扩展单测
│   ├── openaic_json_test.c         libopenaic JSON/校验单测
│   └── vectors/main.go             Go（varwof/types）生成共享 DER 向量
├── docs/                           ASN.1 映射、验证语义、config 语法、CLI 参考、补丁机制
└── ci/build.sh                     fetch → 打补丁 → 构建（单步）
```

## 快速开始

```sh
make fetch        # 下载并 sha256 校验 openssl-3.5.7 tarball
make build        # 解压 → 复制手术树 → Configure → make（串行）
make test         # 完整 OpenSSL 测试套件（4499 用例）+ openaic 测试
make test-aic     # 重建 Go 向量 + 跑 AIC 扩展测试
make gen-patch    # 从手术树再生成 patch/openssl-3.5.7-aic.patch
```

说明：

- `make build` 在 `patch-dir/`（手术树 `openssl-src/` 的副本）中构建。刻意使用
  `-j1`：OpenSSL 3.5 的 `-MMD` 依赖文件在并行 make 下会竞争（见
  [docs/zh-CN/patch.md](docs/zh-CN/patch.md)）。
- `config.mk` 设了 `no-asm`（本机 binutils 早于 AVX-512）；这是构建选项，不是补丁内容。
- 下载默认走 Tor SOCKS5 代理（`config.mk` 中 `CONNECTION_PROXY := 127.0.0.1:9050`）；
  置空即为直连。
- Go 向量步骤需要 `github.com/varwof/types` 位于 `../types`（`go.mod` 的 replace 指令）。

## 5 分钟端到端验证

```sh
make fetch && make build        # 打补丁后的 OpenSSL 3.5.7
make test-aic                   # AIC 扩展测试（13 用例）
```

随后按 [docs/zh-CN/config.md](docs/zh-CN/config.md) 走一遍：文档含完整的
`[ aicbody ]` 配置段与确切的 `openssl x509 -req -extfile` 签发命令，
再用 `openaic-tool verify` 对照用户主体证书验证。

## AIC 扩展

- OID：`1.3.6.1.4.1.66257.1.1` → `NID_AIC` 1487
- Critical：`false`（spec v1.7.1）
- 结构：`AIC`、`AIC_PRINCIPALUID`、`AIC_CAPABILITY`、`AIC_REASON`、
  `AIC_DELEGATIONAUTH`、`AIC_DATBS` — 见 [docs/zh-CN/asn1.md](docs/zh-CN/asn1.md)。
- 用配置文件签发 AIC 证书：[docs/zh-CN/config.md](docs/zh-CN/config.md)。

示例输出（由 Go 向量重建）：

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

## 验证钩子（默认关闭）

```c
#include <openssl/x509_vfy.h>
#include "aic_verify.h"

/* 方式 A：verify 回调 + param 开关（链位置 0） */
X509_VERIFY_PARAM_set_aic_flags(ctx->param, AIC_VERIFY_REQUIRE
                                              | AIC_VERIFY_CHECK_SPKI
                                              | AIC_VERIFY_VERIFY_DA);
X509_STORE_CTX_set_verify_cb(ctx, aic_verify_cb);

/* 方式 B：直接调用，不依赖 X509_STORE_CTX */
AIC_VERIFY_OPTS opts = { .flags = AIC_VERIFY_CHECK_SPKI | AIC_VERIFY_VERIFY_DA };
int rc = AIC_verify_cert(agent_cert, untrusted, &opts);
/* rc == 1 通过；0 AIC 存在但失败；-1 无 AIC 且未 require */
```

完整验证流程、签名算法分发与安全边界见 [docs/zh-CN/verify.md](docs/zh-CN/verify.md)。

## CLI

```sh
openaic-tool print  <agent.pem>
openaic-tool verify <agent.pem> --user <principal.pem> [--no-check-spki]
                    [--no-verify-da] [--require] [--replay]
```

参考：[docs/zh-CN/cli.md](docs/zh-CN/cli.md)。

## 贡献

本 SDK 由社区共同维护，无需成为核心成员即可参与：

- **报告 bug / 提需求** — 直接开 issue；bug 报告无需签署贡献者协议。
- **提交补丁** — 代码贡献走 pull request，需在提交信息中带 `Signed-off-by`
  行（DCO）。org 级流程见 [CONTRIBUTING.md](../../.github/CONTRIBUTING.md)。
- **成为维护者** — 合并数个 PR 后可申请 collaborator 权限；长期活跃的
  reviewer 将被邀请接管本 SDK 的维护。

## License

Apache-2.0。`lib/cjson` 以独立 MIT 许可 vendored。见 [LICENSE](LICENSE)。

## 社区

问题、反馈与移植状态：[AIC Discussions](https://github.com/varwof/aic-jwt/discussions)
