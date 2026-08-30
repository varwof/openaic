# openaic 文档

语言：[English](../index.md) · [中文](#)

openaic 为 OpenSSL 3.5 LTS 提供 AIC（Authorization in Certificates）X.509v3
扩展支持。本文档按"协议 → 机制 → 用法"组织。

## 协议与实现

| 文档 | 内容 |
|------|------|
| [asn1.md](asn1.md) | AIC ASN.1 定义与 C 结构映射，与 Go `varwof/types` 的一致性方法 |
| [verify.md](verify.md) | 验证钩子：分层原则、`AIC_verify_cert` 流程、签名算法分发、安全边界 |

## 机制

| 文档 | 内容 |
|------|------|
| [patch.md](patch.md) | 为什么用补丁而非 provider；补丁改动清单；OID/符号再生成与 `make gen-patch` 流程 |

## 用法

| 文档 | 内容 |
|------|------|
| [config.md](config.md) | 用配置文件（`-extfile`）签发 AIC 证书：`aicbody` 各字段、NCONF 陷阱、完整示例 |
| [cli.md](cli.md) | `openaic-tool` 命令参考：`print` / `verify` 全部选项与退出码 |

## 快速入口

- 构建与测试：见根目录 `README.zh-CN.md`（`make fetch/build/test/test-aic`）。
- 常用 Make 目标：`fetch`、`build`、`test`、`test-aic`、`cross`、`gen-patch`、
  `clean`、`distclean`。
