# patch/ — OpenSSL 3.5 LTS AIC 补丁

`openssl-3.5.7-aic.patch` 是唯一分发物。完整说明（改动清单、为什么用补丁而
非 provider、版本策略、手术树与 `make gen-patch` 流程、OID/符号再生成、串行
构建与 ordinals 踩坑）见：

**→ [docs/patch.md](../docs/patch.md)**

一句话要点：

```sh
make gen-patch                                  # 从手术树 openssl-src/ 再生成补丁
git apply --check patch/openssl-3.5.7-aic.patch # 对原始 3.5.7 树校验
make build test                                 # 全量验证
```
