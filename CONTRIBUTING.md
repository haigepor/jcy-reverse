# 贡献指南

## 适用范围

本项目是个人逆向研究记录，欢迎以 Issue 形式提出分析纠错与补充；提交代码前请先阅读本文件。

## 环境准备

```bash
pnpm install          # Node 依赖 + core 工具 + .venv
pnpm test             # 协议测试 + 结构校验
```

## 提交前必须通过

```bash
pnpm test
```

该命令依次执行：

1. `scripts/run-tests.mjs` —— 运行 `packages/protocol/tests/test_channels.py`（10 项断言，含真机向量）
2. `scripts/validate-structure.mjs` —— README 目录树 ↔ 文件系统双向校验 + 文档内链校验

两项任一失败即退出码非 0。

## 提交信息规范

采用 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/)：

```
<type>(<scope>): <subject>
```

| type | 含义 |
|---|---|
| `feat` | 新功能 |
| `fix` | 修复缺陷 |
| `docs` | 仅文档改动 |
| `style` | 格式调整（不影响逻辑） |
| `refactor` | 重构（非新增功能、非修 bug） |
| `perf` | 性能优化 |
| `test` | 测试相关 |
| `build` | 构建系统或依赖 |
| `ci` | 流水线配置 |
| `chore` | 其他杂项 |
| `revert` | 回滚提交 |

要求：

- subject 用祈使句，不超过 50 字，结尾不加句号
- 正文说明「为什么改」，与标题空一行，每行不超过 72 字符
- 关联 issue 写在 footer：`Closes #123` 或 `Refs #123`
- 破坏性变更必须写明 `BREAKING CHANGE:` 及其影响

## 改动约定

- **新增/删除顶层目录或文件后，必须同步更新 `README.md` 的目录树**，否则 `pnpm validate` 会失败（这是刻意设计，用于保证文档与结构不漂移）
- 新增文档请登记到 `docs/_sidebar.md`，否则不会被文档站导航到
- 新增工具请加入 `config/tools.json`，并在 `tools/README.md` 说明用途
- 不要在 `out/` 中新增非分析产物；`out/` 是过程记录区
- 可复用能力抽取到 `packages/`，不要复制 `out/client/` 的取证代码

## 禁止事项

- 不得提交 `.env`、token、证书、私钥；本项目中的协议密钥属研究对象，不要加入真实账号凭证
- 不得提交大体积二进制（工具、APK、内存转储）；这些由 `.gitignore` 排除、由 `pnpm` 恢复
- 不得使用 `git push --force` 推送到 `main`
- 不得跳过校验（`--no-verify`）
