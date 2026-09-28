# 项目结构说明

本文说明仓库的目录职责、数据流与关键约束。目录树的权威来源是
[`README.md`](../README.md)，并由 `pnpm validate` 强制校验一致性。

## 一、目录职责

| 路径 | 职责 | 入库 |
|---|---|---|
| `docs/` | 逆向文档站（docsify），分析结论的**唯一权威出口** | 是 |
| `packages/` | 从分析脚本抽取的**可复用库**（当前：`protocol`） | 是 |
| `scripts/` | 工程脚本：工具安装、Python 环境、测试、结构校验 | 是 |
| `config/` | 工具安装清单 `tools.json` | 是 |
| `python/` | Python 依赖声明 | 是 |
| `out/` | **分析过程记录**：脚本、样本数据、分析主文档 | 部分 |
| `tools/` | 第三方逆向工具 | 否（`pnpm` 恢复） |
| `apk/` | 原始样本 `base.apk` | 否 |
| `reflutter_work/` | reFlutter 工作区与 Dart dump | 否 |

## 二、分层原则

```
         ┌─────────────────────────────────────────┐
         │  docs/          结论与文档（人读）        │
         ├─────────────────────────────────────────┤
         │  packages/      可复用库（代码依赖）      │
         ├─────────────────────────────────────────┤
         │  out/           过程记录（迭代、一次性）  │
         └─────────────────────────────────────────┘
```

- `out/` 是**证据与过程**，允许存在 `gg_dart_hook2` 这类迭代版本，不追求整洁
- `packages/` 是**稳定接口**，必须可测试、可安装
- `docs/` 是**结论**，必须与代码和结构一致（由 `pnpm validate` 保证）

同一能力不要在 `out/` 与 `packages/` 重复实现：`out/client/gg_client.py` 保持冻结作为取证产物，
新代码从 `jcy_protocol` 引用。

## 三、数据流

```
apk/base.apk
   │
   ├─ apktool ──────────▶ out/base_smali(_patched)/      smali 补丁与重打包
   ├─ jadx ─────────────▶ out/jadx_src/                  Java 层阅读
   └─ blutter ──────────▶ out/blutter_out/                pp.txt 对象池 / asm / frida 模板
                                   │
                                   ▼
   设备 (arm64) ── frida hook ──▶ out/*.jsonl（原始日志）
                                   │
                                   ▼
                          out/analyze_keylog.py 等
                                   │
                                   ▼
                          docs/crypto/  docs/api/        结论
                                   │
                                   ▼
                          packages/protocol/             可复用实现
                                   │
                                   ▼
                          out/client/gg_client.py        客户端（冻结）
```

## 四、关键约束

1. **README 目录树必须与文件系统一致**。新增顶层条目后不更新 README，`pnpm validate` 会失败。
2. **文档内链必须有效**。`docs/_sidebar.md` 与各文档中的相对链接会被逐一校验。
3. **新增文档要登记到 `docs/_sidebar.md`**，否则文档站导航不到。
4. **工具不手工下载**：加入 `config/tools.json`，由 `pnpm tools:install` 获取。
5. **二进制不入库**：`.gitignore` 已覆盖工具、APK、内存转储、截图、日志。

## 五、扩展点

| 需求 | 落点 |
|---|---|
| 新增分析文档 | `docs/<分类>/`，并登记 `_sidebar.md` |
| 新增可复用能力 | `packages/<name>/`，含 README + 测试，并接入 `pnpm test` |
| 新增工具 | `config/tools.json` + `tools/README.md` |
| 新增工程脚本 | `scripts/`，共用逻辑放 `scripts/lib/` |
| 新增 CI 校验 | `.github/workflows/` |

## 六、验证

```bash
pnpm validate       # 结构 + 内链 + 完整性 + 工具清单
pnpm test           # 协议测试 + 结构校验
```
