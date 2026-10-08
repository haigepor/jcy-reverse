# apk/ — 原始样本

| 文件 | 说明 |
|---|---|
| `base.apk` | 囧次元 Android 安装包原始样本，43 MB，只读 |

- 包名：`com.tudou.tool`，versionName 1.5.8.0（Dart 3.6.0 / Flutter 3.27.x）
- SHA256 前缀：`AC170C12...`（完整值见 `docs/analysis/evidence.md`）
- **不入库**：二进制体积与版权原因，仅本地保存。

## 用途

- `research/base_*` 系列解包目录均由本文件生成（apktool）
- `research/artifacts/blutter_out/` 由 `libapp.so`（本 apk 内）经 blutter 生成
- 所有抓包、hook、动态调试均基于本样本安装的设备环境
