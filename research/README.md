# research/ — 研究分析工作区

本目录是逆向分析的过程与产物区（原 `out/`，2026-09-30 重构）。
对外结论在 [`../docs/`](../docs/README.md)，本目录保存**证据、脚本与中间产物**。

## 分层

| 目录 | 职责 | 入库 |
|---|---|---|
| `artifacts/` | 必需二进制产物（`libcore.so`、设备内存镜像、区域 dump、blutter 产物） | 否（体积大） |
| `toolchain/` | 分析脚本：Unicorn 模拟器、探针、反追踪、反汇编工具 | 是 |
| `deliverables/` | **对外交付**：`authgen.py`、三通道解密、验证脚本 | 是 |
| `captures/` | 真实抓包（HTTP 请求/响应 JSONL） | 是 |
| `corpus/` | 语料（`ts` ↔ 密文，用于回归与核验） | 是 |
| `reports/` | 阶段报告：`VERIFICATION.txt`、`API_MATRIX_V5.md` 等 | 是 |
| `archive/` | 历史版本（v5–v12）与早期脚本归档，**只读** | 部分 |

## 快速使用

```bash
# 生成 authentication 头（离线）
./.venv/Scripts/python.exe research/deliverables/authgen.py --selftest
./.venv/Scripts/python.exe research/deliverables/authgen.py --test-server

# 服务端正例/阴性对照
./.venv/Scripts/python.exe research/deliverables/verify_server.py

# 语料 O[0:32] 批量核验（约 30 分钟，485 个唯一 ts）
./.venv/Scripts/python.exe research/deliverables/verify_corpus_batch.py
```

## 产物重建

`artifacts/` 中的大二进制不入库。完整重建需要一台已 root 的 Android 设备（或雷电模拟器）
与目标 App 运行态：

```bash
# 1) 取得 libcore.so（从 APK 解包）
java -jar tools/apktool.jar d assets/apk/base.apk -o /tmp/base_decoded
cp /tmp/base_decoded/lib/arm64-v8a/libcore.so research/artifacts/libcore.so

# 2) dump 设备内存（需要 adb + root）
./.venv/Scripts/python.exe research/toolchain/run_dump.py    # → libcore_dev_img.bin
./.venv/Scripts/python.exe research/toolchain/v13.py auto     # 迭代收集缺失区域
./.venv/Scripts/python.exe research/toolchain/dump_all.py     # → regions_all/
```

> 注意：`libcore_dev_img.bin` 与 `regions_all/` 必须来自**同一台设备实例**，
> 否则 `device_fp` 不一致会导致 `O[32:96]` 与历史语料对不上
> （详见 [`../docs/algorithm-auth.md`](../docs/algorithm-auth.md) §6.3）。

## 路径约定

所有脚本通过 [`toolchain/paths.py`](toolchain/paths.py) 取路径：

```python
import paths as _P
_P.SO                # research/artifacts/libcore.so
_P.REGIONS_ALL_DIR   # research/artifacts/regions_all/
_P.O_CORPUS          # research/corpus/O_corpus.json
```

禁止在脚本中硬编码 `../v11/...` 之类的相对路径。
