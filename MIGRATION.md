# 目录重构迁移对照表（2026-09-30）

本次重构把原来扁平的 `out/` 工作区改造为 **按职责分层的标准化目录**。
本文件是 **旧路径 → 新路径** 的权威对照表；历史文档中出现的旧路径均可在此查到去向。

## 一、顶层分层

| 旧路径 | 新路径 | 说明 |
|---|---|---|
| `packages/protocol/` | `src/` | 可复用库上提为独立源码层 |
| `packages/protocol/jcy_protocol/` | `src/jcy_protocol/` | 包本体 |
| `packages/protocol/tests/` | `tests/` | 测试独立成层 |
| `python/requirements*.txt` | `config/requirements*.txt` | 依赖声明归入配置层 |
| `apk/` | `assets/apk/` | 原始样本归入资源层 |
| `out/` | `research/` | 分析工作区改名并内部分层 |
| `tools/` | `tools/`（未变） | 被运行中进程占用无法移动，保留为「第三方工具链」层 |

## 二、`out/` → `research/` 内部再分层

| 旧路径 | 新路径 |
|---|---|
| `out/v11/libcore_dev_img.bin`、`out/v11/regions_all/`、`out/v11/regions_all.json` | `research/artifacts/` |
| `out/base_decoded/lib/arm64-v8a/libcore.so` | `research/artifacts/libcore.so` |
| `out/blutter_out/` | `research/artifacts/blutter_out/` |
| `out/v11/{emu_v11,emu_v12,emu_v14,v13,dasm,sm4,trace*,probe*,...}.py` | `research/toolchain/` |
| `out/v11/*.log`、`out/v11/faults.json` | `research/toolchain/logs/` |
| `out/v12/`（authgen / verify_* / probe_matrix* / engine_min） | `research/deliverables/` |
| `out/decrypt_v5/` | `research/deliverables/decrypt_v5/` |
| `out/client/` | `research/deliverables/client/` |
| `out/demo/` | `research/deliverables/demo/` |
| `out/v5/proxy_capture.jsonl`、`out/v5/proxy_bodies.jsonl` | `research/captures/` |
| `out/ggcap.pcap` | `research/captures/ggcap.pcap` |
| `out/v9/brute/O_corpus.json`、`out/v9/brute/O_true_corpus.json` | `research/corpus/` |
| `out/auth_samples.json`、`out/auth_full_rows.json` | `research/corpus/` |
| `out/VERIFICATION.txt` | `research/reports/VERIFICATION.txt` |
| `out/API_MATRIX_V5.md`、`out/API_ANALYSIS.md`、`out/API_TEST_REPORT_V6.md`、`out/ASSESSMENT_V5.md` | `research/reports/` |
| `out/HANDOFF_PROMPT*.md` | `research/reports/handoff/` |
| `out/v5`、`out/v6`、`out/v9`、`out/v10`、`out/v11`（残留）、`out/v12`（残留） | `research/archive/versions/` |
| `out/gg_*.py`、`out/gg_*.js`、`out/full_run*.py`、`out/dec_test*.py`、`out/fs_*.py` 等早期脚本 | `research/archive/legacy-scripts/` |
| `out/*.xml`、`out/*.tsv`、`out/*.log`、`out/*_strings.txt` 等 | `research/archive/test-artifacts/` |
| `out/ROLLBACK.*`、`out/DIFF_smali.patch`、`out/RSA_PUBLIC_KEY.pem`、`out/sm4_sbox.bin` 等 | `research/archive/legacy-artifacts/` |

## 三、已永久删除 · 第一批（可重建，删除前均已核验）

| 路径 | 体积 | 删除理由与重建方式 |
|---|---|---|
| `out/v11/d.tar` | 445 MB | `regions_all/` 的 tar 副本（已核验：884 条目 = 883 文件，逐一对应） |
| `out/v6/authgen/dumps/mdump.tar` | 1.6 GB | `mdump/` 的 tar 副本（已核验：1990 条目 = 1 目录 + 1989 文件） |
| `out/v6/dartsdk-win.zip` | 222 MB | Dart SDK 安装包，可从官网重新下载 |
| `out/v6/blutter/`、`blutter_in/`、`icu/`、`icu.zip`、`bin64/`、`lib64/`、`include/` | 650 MB | blutter 构建树，可由 `pnpm tools:install:all` 重建 |
| `out/base_smali/`、`base_smali_patched/`、`base_nores/`、`jadx_src/` | 1.10 GB | 反编译产物，可由 `apktool d` / `jadx` 从 `assets/apk/base.apk` 重建 |
| `out/base_decoded/`（除 libcore.so） | 90 MB | 解包产物，可由 `apktool d` 重建；`libcore.so` 已复制到 `research/artifacts/` |
| `out/lua_dump/`、`blutter_lib/`、`nativelibs/` | 74 MB | 派生中间产物，可重建 |
| `out/libcore.so`、`out/libcore2.so` | 14 MB | 与 `research/artifacts/libcore.so` 重复 |
| `out/v11/t304_full.log`、`out/v11/t304.log` | 16 MB | 运行时 trace 日志，可重跑 `trace304.py` 生成 |

**合计释放约 7.2 GB。**

## 四、已永久删除 · 第二批（隔离区，验证算法无误后清除）

这批是 **不可再生** 的原始采集数据（设备整块内存转储），先隔离保留、
**在算法正确性验证通过后**才删除。

| 原路径 | 体积 | 说明 |
|---|---|---|
| `out/mem_dump.bin` | 178 MB | 早期整进程内存 dump |
| `out/v6/authgen/dumps/mem_all.bin` | 1.60 GB | 与 `mdump/` 内容等长（1603067904 B），疑为拼接产物 |
| `out/v6/authgen/dumps/mdump/` | 1.60 GB | 1989 个区域切片（来自**另一台实例**，与当前 `research/artifacts/` 不同源） |
| `out/v9/dyn5/` | 299 MB | 早期内存快照序列 |

**合计释放约 3.4 GB。**

**清除前的验证（全部通过，2026-09-30 18:40）**：

```
语料 O[0:32] 全量核验（最小区域集）   485/485 MATCH, 0 失败
端点矩阵                             22/22 HTTP 200 + 加密业务数据
服务端正例 / 阴性对照                 3/3 通过 / 3/3 正确拒绝
tests/test_auth_pure.py               全部通过
tests/test_channels.py                10/10
tests/test_authgen.py                 5/5
scripts/validate-structure.mjs        通过
```

**删除内容清单（2139 行，含每个文件的字节数）已归档到
[`research/reports/TRASH_PURGED_20260930.txt`](research/reports/TRASH_PURGED_20260930.txt)。**

> `.gitignore` 中保留 `_trash_*/` 规则：后续如需再次隔离，沿用同一约定。

## 五、代码适配

| 文件 | 改动 |
|---|---|
| `research/toolchain/paths.py` | **新增**：研究区统一路径解析（artifacts / toolchain / deliverables / captures / corpus / reports） |
| `research/toolchain/emu_v11.py` | `SO` / `IMG` 改为经 `paths.py` 解析 |
| `research/toolchain/emu_v14.py` | `regions_all` 路径改为经 `paths.py` 解析；**默认改用最小区域集 `regions_min`** |
| `research/toolchain/v13.py` | `regions` / `maps` / `faults` 路径改为经 `paths.py` 解析 |
| `research/toolchain/{dasm,trace304,trace_E,dump_all,run_dump}.py` | 同上 |
| `src/jcy_protocol/auth.py` | **新增**：算法纯逻辑 + `EBackend` 协议 |
| `research/deliverables/authgen.py` | 依赖目录 `../v11` → `../toolchain`；纯逻辑迁到 `src/`；新增 `UnicornESession` |
| `research/deliverables/verify_corpus*.py` | 依赖目录 + 语料路径 `../v9/brute/` → `../corpus/` |
| `scripts/run-tests.mjs` | 依次跑三个测试文件，支持 SKIP=77 |
| `scripts/validate-structure.mjs` | 骨架区/产物区根、必需文件与目录清单全部更新 |
| `pnpm-workspace.yaml` | `packages/*` → `src` |
| `.gitignore` | `out/` → `research/`，`apk/` → `assets/apk/`，新增 `_trash_*/` |

## 六、验证

重构与清理后已复跑（全部通过）：

```
node scripts/validate-structure.mjs                 通过
tests/test_auth_pure.py                             全部通过
tests/test_channels.py                              10/10
tests/test_authgen.py                               5/5
research/deliverables/authgen.py --selftest         PASS
research/deliverables/authgen.py --test-server      GET /app/config → HTTP 200 (2905 B)
research/deliverables/verify_corpus_batch.py        485/485 O[0:32] MATCH
```

详见 [`research/reports/VERIFICATION.txt`](research/reports/VERIFICATION.txt)。
