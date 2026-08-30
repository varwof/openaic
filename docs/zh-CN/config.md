# 用配置文件签发 AIC 证书


**EN:** Issuing an AIC certificate from an OpenSSL config file
(`-extfile`): the `[ aicbody ]` section, field reference, opaque-parameter
encodings, NCONF pitfalls, and a complete example.

`openssl x509 -req -extfile <cfg> -extensions aic` 会调用补丁中的 `v2i_AIC`，
从 OpenSSL 配置文件段解析 AIC 字段。适用于测试与运维手工签发；生产路径
推荐用 Go 侧 `github.com/varwof/core`（`internal/ca`）签发。

## 配置段结构

配置需先定义 `[ aic ]` 扩展段，用 `aic = @aicbody` 引用字段段：

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

## 字段表

| 字段 | 必填 | 值 | 说明 |
|------|------|----|------|
| `agentId` | 是 | UTF-8 文本 | 代理标识 |
| `principalUid` | 是 | `realm:identifier:base64url` | 主体标识；`keyHash` 为 `hashAlgo(SPKI)` 的 base64url（无填充） |
| `delegationMode` | 否 | `authorized` \| `representative` | 缺省 `authorized` |
| `capability` | 否* | `scheme:capabilityId[:参数]` | 可重复；*规范要求至少一个 |
| `authorizationConstraint` | 否 | 同 `capability` | 可重复 |
| `delegationAuthDer` | 否 | hex DER | `DelegationAuthorization` 完整 DER（含签名） |

`v2i_AIC` 校验所有字段，任一非法则整段失败（`AIC_validate`）。

## capability / constraint 的第三段参数

`Capability.parameters` 是 `[0] EXPLICIT OCTET STRING OPTIONAL`，按规范为
**不透明字节**。配置文件第三段两种写法：

- `scheme:capabilityId:hex:<HEX>` —— 按 hex 解码为原始字节（**推荐**，见下）；
- `scheme:capabilityId:<文本>` —— 原样按 ASCII 字节存储（如 base64url token、
  无引号的裸文本）。

`parameters` 的 JSON 语义（`{"level":2}`、`{"max":3}` 等）由 libopenaic 层
解析，libcrypto 只透传。

### NCONF 陷阱：为什么必须用 `hex:`

OpenSSL 的 NCONF 解析器会**吃掉引号**并把 `:` 当成分隔/特殊字符，因此
`capability = tt:smart-device:{"level":2}` 实际读到的值是
`tt:smart-device:{level:2}` —— JSON 引号丢失，且内部 `:` 干扰解析。曾因此
导致 DA 验签失败（重建 TBS 与签名时不一致）。**含引号/冒号的参数一律写成
`hex:` 前缀**：

```ini
# 错误：引号被 NCONF 吃掉，参数损坏
capability = tt:smart-device:{"level":2}

# 正确：hex 前缀，原始字节完整
capability = tt:smart-device:hex:7b226c6576656c223a327d
# {"level":2} → 7b226c6576656c223a327d
# {"max":3}   → 7b226d6178223a337d
```

获取 JSON 字节 hex 的方法：

```sh
printf '%s' '{"level":2}' | xxd -p -c 1000   # 7b226c6576656c223a327d
```

## delegationAuthDer 来源

`delegationAuthDer` 是签名后的 `DelegationAuthorization` 的 DER。可以从一张
已知正确的证书里用 `asn1parse` 提取（偏移/长度随向量重生成变化）：

```sh
openssl x509 -in agent.pem -outform DER -out a.der
openssl asn1parse -inform DER -in a.der -i   # 定位 DA 的 SEQUENCE 偏移与长度
dd if=a.der bs=1 skip=<OFFSET> count=<LEN> | xxd -p -c 1000
```

## 验证生成的证书

```sh
openssl x509 -in agent-aic.pem -noout -text | grep -A8 AIC
openaic-tool verify agent-aic.pem --user user-principal.pem
```

注意：证书的 `principalUid.keyHash`、`capability`/`constraint` 参数以及
`delegationAuthDer` 中的 TBS 必须与签名时完全一致，否则 DA 验签失败
（`AIC_verify_cert` 返回 0）。这也是为什么参数建议直接用 Go 侧向量生成。
