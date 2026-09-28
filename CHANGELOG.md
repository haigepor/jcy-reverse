# 变更日志

本文件记录本项目的显著变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循语义化版本。

## [未发布]

### 计划中

- HTTP body 随机会话 key 的运行时提取（遗留项，见 `docs/analysis/open-questions.md`）
- `jcy_protocol` 补全 HTTP body 加密发送能力

## [0.1.0] - 2026-09-29

首个完整分析版本。

### 新增

- 逆向文档站 `docs/`：crypto 5 篇、api 5 篇、analysis 4 篇（docsify）
- `out/client/gg_client.py`：Python 离线客户端，监控/信令双通道解密经真机验证
- `out/blutter_out/`：blutter Dart 结构产物（pp.txt 对象池 2.6 MB、objs.txt、Frida 模板）
- `out/demo/index.html`：hls.js 离线播放验证页
- `out/`：分析脚本 104 个（Dart hook、加密层 hook、FFI、认证链路、构建与扫描工具）
- `packages/protocol/`：`jcy_protocol` 可安装协议库 + 10 项单元测试（含真机向量）
- pnpm 工程化骨架：`pnpm install` 自动安装工具链与 Python 依赖
- `config/tools.json`：工具清单（core 4 项 / all 7 项）
- `scripts/validate-structure.mjs`：README 目录树 ↔ 文件系统双向一致性校验
- 工程规范：`.gitattributes`、`.editorconfig`、LICENSE、CONTRIBUTING、SECURITY、CI 工作流
- `docs/structure.md`、`docs/scripts-index.md`、`docs/installation.md`、`docs/tags.md`

### 变更

- README 目录结构改为与仓库实际结构逐条对齐，并由 `pnpm validate` 强制校验

### 移除

- 清理运行过程产物 181 个文件（截图、日志、中间 APK、重复压缩包，约 1.05 GB）

[未发布]: https://github.com/haigepor/jcy-reverse/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/haigepor/jcy-reverse/releases/tag/v0.1.0
