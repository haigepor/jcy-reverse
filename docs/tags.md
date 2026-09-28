# 版本标签（Tags）说明

本文件的标签体系与 GitHub 仓库的 Topics（仓库标签）和 Git Tags（版本标签）一一对应。

## Git 版本标签

| 标签 | 日期 | 说明 |
|---|---|---|
| `v0.1.0` | 2026-09-28 | 首个完整分析版本：接口全链路还原 + 监控/信令双通道加密破解 + Python 客户端库 + 文档站 |

### v0.1.0 变更明细

- 新增 `docs/` 文档站（crypto 5 篇 / api 5 篇 / analysis 4 篇）
- 新增 `out/client/gg_client.py` 离线客户端（信令解密验证通过）
- 新增 `out/blutter_out/`（pp.txt 对象池 2.6 MB / objs.txt / frida 模板）
- 新增 `out/demo/index.html` hls.js 离线播放验证页
- 收录分析脚本族 104 个（out 根目录 py/js/c）
- 项目清理：移除 181 个中间产物文件（1.05 GB），明细见 `CLEANUP_REPORT.md`

## 仓库 Topics（GitHub 标签）

| Topic | 含义 |
|---|---|
| `reverse-engineering` | 逆向工程 |
| `android` | Android 平台 |
| `flutter` / `dart` | Flutter 壳 + Dart 快照分析 |
| `frida` | Frida 动态 hook |
| `blutter` | blutter Dart 反编译 |
| `apk-analysis` | APK 静态分析（apktool/jadx） |
| `encryption` / `aes-cbc` / `rsa` | 协议加解密研究 |
| `ctf` | 安全研究向 |
| `security-research` | 安全研究 |

## 后续标签规划

- `v0.2.0` — HTTP body 随机会话 key 的运行时提取（当前遗留项，见 `docs/analysis/open-questions.md`）
- `v0.3.0` — 客户端库补全 HTTP body 加密发送能力
