# AIC ASN.1 ↔ C 结构映射


**EN:** ASN.1 definitions of the AIC X.509v3 extension and their C structure
mapping, kept byte-compatible with the Go reference (`varwof/types`).

本文件描述 openaic 在 `src/v3_aic.c` 中实现的 ASN.1 模板与
`github.com/varwof/types`（`DelegationAuthTBS` / `AIC`）以及
`github.com/varwof/core`（`internal/ca/aic.go`）的一致性。

扩展 OID：`1.3.6.1.4.1.66257.1.1`（IANA PEN 66257，Varwof PKI）。
Critical：`false`（spec v1.7.1）。

## 顶层结构 AIC

```
AIC ::= SEQUENCE {
    version                  INTEGER DEFAULT 1,
    agentId                  UTF8String,
    principalUid             PrincipalUid,
    capabilities             SEQUENCE OF Capability,
    delegationMode           INTEGER DEFAULT 0,
    authorizationConstraints [0] EXPLICIT SEQUENCE OF Capability OPTIONAL,
    delegationAuthorization  SEQUENCE OPTIONAL,   -- 规范要求必填，AIC_validate() 强制
    extensions               [1] EXPLICIT SEQUENCE OF ExtField OPTIONAL
}
```

| Go (types/ca)          | C (openaic)                   | 标签                     |
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

keyHash = hashAlgo(SPKI)；缺省 SHA-256。
通信格式：`{realm}:{identifier}:{base64url keyFingerprint}`。

> 注意：libcrypto 内的 `AIC_principalUid_from_string()` 仅做结构解析并保留
> keyFingerprint 的原始 base64url 字节；base64url 解码/编码归一在
> libopenaic 层（见 [verify.md](verify.md)「分层原则」）。

## Capability

```
Capability ::= SEQUENCE {
    schemeId     UTF8String,
    capabilityId UTF8String,
    parameters   [0] EXPLICIT OCTET STRING OPTIONAL
}
```

`parameters` 为**不透明字节**。libcrypto 内只透传（hex 打印 / 原样 d2i）；
JSON 语义（如 `{"max":N}`）由 libopenaic + cJSON 处理。

## Reason / DelegationAuthorization

```
Reason ::= SEQUENCE {
    reasonCode  UTF8String (SIZE(1..64)),
    description UTF8String (SIZE(1..512))
}

DelegationAuthorization ::= SEQUENCE {
    reason             Reason,
    requestedLifetime  INTEGER DEFAULT 0,   -- 有效 1..86400，0 → 3600
    timestamp          GeneralizedTime,
    nonce              OCTET STRING (32),
    signatureAlgorithm AlgorithmIdentifier,
    signatureValue     OCTET STRING
}
```

## DelegationAuthTBS（DA 签名目标，仅存在于验签路径）

与 types.DelegationAuthTBS 严格一致（字段序 + 标签），在 `aic_verify.c`
中通过内部 `AIC_DATBS` 模板重建并 `i2d` 后做签名验证：

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

## 一致性验证方法

- 正向：Go（`test/vectors`）生成 `aic.der` → C 侧 `d2i_AIC` 解析 → 逐字段断言
  （`test/aic_ext_test.c`）。
- 反向：C 侧 `i2d_AIC` 输出 DER → Go 侧 `types.ParseAIC` 解析比对
  （M3 加入）。
- 值语义（keyHash / 长度 / schemeId 白名单）由两端各自的 validator
  （`AIC_validate` / `ValidateAIC`）共同约束，交叉测试保证一致。
