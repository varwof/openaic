# AIC 验证语义（验证钩子层）


**EN:** AIC verification semantics — layered design, `AIC_verify_cert` flow,
signature-algorithm dispatch (ECDSA/RSA-PSS/Ed25519), anti-replay, and
security boundaries (off by default; stock OpenSSL verification unchanged).

## 分层原则

openaic 刻意把"扩展表示"与"JSON 语义"分开，使 libcrypto 补丁尽可能小且
不引入运行时外部依赖：

| 层 | 位置 | 职责 | 依赖 |
|----|------|------|------|
| 扩展方法 | libcrypto 补丁（`src/v3_aic.c`） | ASN.1 模板、d2i/i2d、打印、config v2i/i2v；parameters 不透明字节 | 无 |
| 验证钩子 | libcrypto 补丁（`src/aic_verify.c`） | DA 验签、SPKI keyHash 交叉校验、nonce 防重放（默认关） | 无 |
| 辅助层 | `lib/openaic.c` | parameters 的 JSON 解析/校验/pretty-print；base64url；max-concurrent 约束 | cJSON（vendored） |
| CLI | `cmd/openaic-tool` | 集成以上两层 | patched OpenSSL + libopenaic + cJSON |

## 验证流程（AIC_verify_cert）

1. 取 end-entity 证书的 AIC 扩展（`X509_get_ext_d2i(cert, NID_aic, ...)`）。
   - 无 AIC：`AIC_VERIFY_REQUIRE` 未置位 → 返回 -1（跳过，视为通过）；
     置位 → 返回 0。
2. `AIC_validate()`：字段级约束（长度 / nonce 32 / lifetime 范围 /
   能力数量 / DA 必填 / constraint schemeId 白名单）。失败 → 0。
3. `AIC_VERIFY_REPLAY`（可选，默认关）：对 `da.nonce` 做防重放检查，
   需外部提供 `AIC_REPLAY_CTX`。重复 → 0。
4. `AIC_VERIFY_CHECK_SPKI`（默认开）：在 `untrusted`（及 verify 时的
   chain/untrusted）中按 `principalUid.keyHash == SHA-256(SPKI)` 查找
   **principal（用户）证书**。找不到 → 0。
5. `AIC_VERIFY_VERIFY_DA`（默认开）：重建 `DelegationAuthTBS`（字段序/标签
   严格对应 types），用 principal 证书公钥按 `signatureAlgorithm` OID 验签。
   失败 → 0。

## 签名算法分发

| OID | 验证方式 |
|-----|----------|
| rsaEncryption + SHA-256/384/512 | `EVP_DigestVerify`，RSA-PKCS1 |
| rsassaPss + SHA-256 | `EVP_PKEY_CTX` 设 `RSA_PKCS1_PSS_PADDING`，saltlen = digest |
| ecdsa-with-SHA256/384/512 | `EVP_DigestVerify`，ECDSA（ASN.1 签名） |
| Ed25519 | `EVP_DigestVerify`，无摘要（digest NULL） |
| 其他 | 拒绝 |

keyHash 交叉校验目前支持 SHA-256 长度；SHA-384/512/SM3 的长度分派与
`hashAlgo` 解析位于 libopenaic 层（后续里程碑补全）。

## 默认关闭、显式启用

OpenSSL 3.5 原厂验证行为**不被改变**。启用方式：

```c
#include <openssl/x509_vfy.h>
#include "aic_verify.h"

/* 方式 A：verify 回调（推荐，可配合现有 X509_STORE_CTX） */
X509_VERIFY_PARAM_set_aic_flags(ctx->param, AIC_VERIFY_REQUIRE
                                              | AIC_VERIFY_CHECK_SPKI
                                              | AIC_VERIFY_VERIFY_DA);
X509_STORE_CTX_set_verify_cb(ctx, aic_verify_cb);

/* 方式 B：直接调用（不依赖 X509_STORE_CTX） */
AIC_VERIFY_OPTS opts = { .flags = AIC_VERIFY_CHECK_SPKI | AIC_VERIFY_VERIFY_DA };
int rc = AIC_verify_cert(agent_cert, untrusted, &opts);
```

## nonce 防重放（anti-replay）

规范要求 nonce 为 32 字节随机数，用于防止 DA 重放。防御模型：

- 新鲜性由 CA 侧"签发前发出 nonce 挑战"保证（`core` serve 层）；
- 本钩子的 `AIC_REPLAY_CTX` 提供会话级一次性检查（默认关闭，避免在无状态
  验证场景误伤）。

已知限制（Known limitations）：

- 防重放上下文是进程内、一次性的，不提供跨重启或跨副本的全局唯一性保证。
  需要跨进程去重的部署，应在本钩子之前自行实现 nonce 存储（如 TTL + LRU）。
- 本钩子不校验 `da.timestamp` 与验证方本地时钟的偏差；要求时间新鲜性的
  验证方应在网关/策略层强制检查。

## 安全边界与不做的事

- 本钩子**不**修改 OpenSSL 的证书链验证主循环；AIC 是"授权证据"，不是
  信任锚。若需要"链上某证书强制 AIC-critical"，由调用方（如网关/代理）
  在回调里对对应位置证书调用 `AIC_verify_cert` 决定。
- `parameters` 的 JSON 校验只做**结构**校验（max-concurrent 的 `{"max":N}`），
  不做权限决策；权限判定由上层依据 `FullID = schemeId:capabilityId` 执行。
- 防重放默认关闭且为进程内一次性；不要把会话级防重放当作全局唯一性保证。
