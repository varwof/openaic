# openaic-tool 命令参考


**EN:** Reference for the `openaic-tool` CLI — `print` (parse/pretty-print an
AIC extension) and `verify` (DA signature, SPKI keyHash cross-check, replay)
with all options, exit codes, and usage examples.

`openaic-tool` 链接补丁后的 OpenSSL 3.5 LTS、libopenaic 与 cJSON，提供
AIC 扩展的解析打印与验证。

## 构建

```sh
make build            # 先构建补丁后 OpenSSL
cc -o openaic-tool cmd/openaic-tool/main.c lib/openaic.c lib/cjson/cJSON.c \
    -Ilib -Ilib/cjson -Isrc -Ipatch-dir/include \
    -Lpatch-dir -Wl,-rpath,$(PWD)/patch-dir -lcrypto -lssl -O2
```

## 通用

```sh
openaic-tool <print|verify> ...
```

无参数或未知命令时打印用法并返回 2。

## print

```sh
openaic-tool print <agent.pem>
```

解析并打印 AIC 扩展：

- 无 AIC：打印 `certificate has no AIC extension`，返回 0；
- 有 AIC：打印各字段；`capability`/`authorizationConstraint` 的参数若为 JSON
  则 pretty-print（如 `params={"level":2}`），否则标记
  `params=<non-json N bytes>`；
- `AIC_validate` 不过时打印 `WARNING: fails spec validation`。

示例：

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

对终端证书的 AIC 做语义验证（`AIC_verify_cert`）。

| 选项 | 作用 |
|------|------|
| `--user <principal.pem>` | 主体（principal）证书；可重复。`--verify-da` 至少需要一个 |
| `--check-spki` | 要求 `principalUid.keyHash == SHA-256(SPKI)`（默认开） |
| `--no-check-spki` | 跳过 keyHash 交叉校验；仍用 `--user` 提供的证书验 DA 签 |
| `--verify-da` | 校验 DA 签名（默认开） |
| `--no-verify-da` | 跳过 DA 签名校验 |
| `--require` | 证书无 AIC 时报失败 |
| `--no-require` | 无 AIC 视为跳过（返回成功并打印提示，默认） |
| `--replay` | 防重放：拒绝重复 nonce（有状态，进程内一次性） |

退出码：

| 结果 | 打印 | 退出码 |
|------|------|--------|
| 验证通过 | `AIC verified OK` | 0 |
| AIC 存在但验证失败 | `AIC verification FAILED` | 1 |
| 无 AIC 且未 `--require` | `certificate has no AIC extension (not required)` | 0 |
| 参数/用法错误 | 用法说明 | 2 |

典型用法：

```sh
# 默认：keyHash 交叉校验 + DA 验签
openaic-tool verify agent.pem --user user-principal.pem

# 只做结构校验（不验签）
openaic-tool verify agent.pem --no-verify-da

# 跳过 keyHash 交叉校验（例如主体证书 SPKI 已轮换但仍验签）
openaic-tool verify agent.pem --user user-principal.pem --no-check-spki

# 带防重放（同一 nonce 第二次拒绝）
openaic-tool verify agent.pem --user user-principal.pem --replay
```

## 与 `AIC_verify_cert` 的返回值对应

| 退出码 | `AIC_verify_cert` 返回值 |
|--------|--------------------------|
| 0 | 1（通过）或 -1（无 AIC，未 require） |
| 1 | 0（AIC 存在但失败） |
| 2 | —（用法错误，未调用） |

验证语义细节（流程、签名算法分发、安全边界）见 [verify.md](verify.md)。
