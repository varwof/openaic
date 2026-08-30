# OpenSSL 3.5 LTS AIC 补丁（patch/）


**EN:** The single distributable patch (`patch/openssl-3.5.7-aic.patch`):
file-by-file changes, why a patch instead of a provider, version strategy,
and the `make gen-patch` workflow.

## 单一补丁文件

`patch/openssl-3.5.7-aic.patch` 是唯一分发物，对 **OpenSSL 3.5.7 release
tarball** 的源码树做如下改动：

| 文件 | 改动 |
|------|------|
| `crypto/objects/objects.txt` | 新增 `1 3 6 1 4 1 66257 1 1 : aic : AIC` |
| `crypto/objects/obj_mac.num` | 重生成：`AIC` → `NID 1487`（`objects.pl -n`） |
| `include/openssl/obj_mac.h` | 重生成：`SN_AIC`/`LN_AIC`/`NID_AIC 1487`/`OBJ_AIC` |
| `crypto/objects/obj_dat.h` | 重生成：OID 序列化字节 + `nid_objs`/`sn_objs`/`ln_objs`/`obj_objs` |
| `crypto/objects/obj_xref.h` | 重生成（仅版权年份变化） |
| `crypto/x509/ext_dat.h` | 追加 `extern const X509V3_EXT_METHOD ossl_v3_aic;` |
| `crypto/x509/standard_exts.h` | `standard_exts[]` 末尾追加 `&ossl_v3_aic`（NID 最大，保持升序） |
| `crypto/x509/v3_aic.c`（新增） | 扩展方法：ASN.1 模板、d2i/i2d、打印、config v2i/i2v（见 `../src/v3_aic.c`，本仓库同步维护） |
| `crypto/x509/aic_verify.c`（新增） | 验证钩子：DA 验签、SPKI 交叉校验、replay 缓存（见 `../src/aic_verify.c`） |
| `crypto/x509/v3_aic.h`（新增） | 见 `../src/v3_aic.h` |
| `crypto/x509/aic_verify.h`（新增） | 见 `../src/aic_verify.h` |
| `crypto/x509/build.info` | 加入 `v3_aic.c aic_verify.c` |
| `util/libcrypto.num` | 追加 51 个 AIC 符号（ordinals 6055–6105）导出 |

## 为什么用"补丁"而不是 provider

- 自定义 X.509 扩展要让 `openssl x509 -text` 打印、config 段 `v2i` 生成，
  必须注册进 `standard_exts[]`（编译进 libcrypto）；
- provider 无法接入 `X509V3_EXT_METHOD` 表，也不能触及验证层语义钩子。

## 版本策略

- 只打 **3.5 LTS**（基线 3.5.7，支持至 2030-04-08）。补丁按 tag 严格对应，
  升级补丁版本时重新生成 `git diff` 并跑全量测试。
- 未来若需要 3.0 LTS：x509 在 3.0/3.5 差异极小，按 `git cherry-pick` 思路
  另出一份 `openssl-3.0-*.patch`。

## 手术树（surgery tree）与 `make gen-patch`

`openssl-src/` 是一个独立的 git 仓库，作为**唯一真相源**：

- 第一个提交 = 纯净基线（3.5.7 tarball 解压后 `git add -A` 提交）；
- 后续提交 = AIC 手术改动（同步自本仓库 `src/`）；
- `make gen-patch` 执行 `git diff --binary HEAD~1..HEAD` 生成统一补丁。

构建目标**从不删除**手术树：`make build` 把它复制到 `patch-dir/` 再 Configure。
维护者本地保留手术树的独立备份。

```sh
make gen-patch            # 再生成 patch/openssl-3.5.7-aic.patch
git apply --check patch/openssl-3.5.7-aic.patch   # 对原始 3.5.7 树校验
make build test           # 全量验证
```

## 维护注意（踩坑记录）

### 串行构建（-j1）

OpenSSL 并行 make 会把同一个 `.c` 编译成 `libcrypto-lib-*` 与
`libcrypto-shlib-*`，两者竞争同一个 `.d.tmp`，常报
`mv: cannot stat '*.d.tmp'`。**必须 `-j1`** 编译；`make test` 的测试阶段可并行。

### OID 再生成

等价于 `make update` 的 `generate_crypto_objects`，但 `obj_mac.num` 必须先写
临时文件再 `mv`，避免 `>` 重定向截断输入导致全部 NID 重排：

```sh
perl crypto/objects/objects.pl -n crypto/objects/objects.txt crypto/objects/obj_mac.num > /tmp/num && mv /tmp/num crypto/objects/obj_mac.num
perl crypto/objects/objects.pl   crypto/objects/objects.txt crypto/objects/obj_mac.num > /tmp/h
perl crypto/objects/obj_dat.pl   /tmp/h > crypto/objects/obj_dat.h
perl crypto/objects/objxref.pl   crypto/objects/obj_mac.num crypto/objects/obj_xref.txt > crypto/objects/obj_xref.h
sed -e '1,8d' crypto/objects/obj_compat.h >> /tmp/h && mv /tmp/h include/openssl/obj_mac.h
```

缺 `obj_compat.h` 的追加会丢失 `DEPRECATED_3_0` 段。

### 符号导出与 ordinals

`libcrypto.ld` 版本脚本的 `local: *` 会隐藏新符号，因此 51 个 AIC 符号必须
追加进 `util/libcrypto.num`（格式 `NAME<pad>N\t3_5_0\tEXIST::FUNCTION:`），
再 `make libcrypto.ld`（mkdef.pl 重新生成）。

- 新增行要保持 ordinal 严格递增、版本为 `3_5_0`；
- **不要**在文件内留空行：`test/recipes/02-test_ordinals.t` 会把空行当作
  非法行而失败（曾因此挂掉一次全量测试）。

## 校验

- `make fetch` 校验 tarball 的 SHA-256；
- `make build` 在副本上构建；
- CI（`ci/build.sh`）在干净的 3.5.7 源树上验证 `git apply --check` 全绿后再构建；
- 全量 `make test` 运行 OpenSSL 344 个文件 4499 个用例 + openaic 测试。
