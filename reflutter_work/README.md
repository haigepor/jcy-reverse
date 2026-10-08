# reflutter_work/ — reflutter 工作区

[ReFlutter](https://github.com/souravkalal/ReFlutter) 框架重打包工作区，用于 Flutter 流量拦截与 Dart 快照 dump。

## 本地内容（均不入库）

| 文件 | 说明 |
|---|---|
| `base.apk` | 输入样本副本（43 MB） |
| `release.RE.apk` 系列 | ReFlutter 重打包产物（release / surgery / combo 三种方案） |
| `dump.dart` / `dump2.dart` | Dart 快照 dump（4.7 MB / 9.4 MB） |
| `dump_parsed.jsonl` / `dump2_parsed.jsonl` | 快照解析结果（类/函数清单） |

## 与其他目录的关系

- `dump.dart` 经解析后支撑了 `research/artifacts/blutter_out/pp.txt` 的交叉验证
- `combo.RE-gadget.apk`（已删除，可重建）= ReFlutter + Frida Gadget 组合包，配合 `tools/libgadget.so` 使用
- 重打包签名统一使用 `tools/uber-apk-signer.jar`
