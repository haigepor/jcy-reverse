# 项目结构说明

本文说明仓库的目录职责、分层原则、数据流与关键约束。
目录树的权威来源是 [`README.md`](../README.md)，并由 `pnpm validate` 强制校验一致性。
系统架构与模块职责见 [`architecture.md`](architecture.md)。

## 一、目录职责

| 路径 | 职责 | 入库 |
|---|---|---|
| `docs/` | 逆向文档站（docsify），分析结论的**唯一权威出口**；子目录 `analysis/ api/ assets/ crypto/ prompts/ setup/` | 是 |
| `src/` | **可复用库**（`jcy_protocol`）：协议加解密、测试向量 | 是 |
| `tests/` | **测试**：协议向量回归、`authentication` 算法回归、固化向量 | 是 |
| `scripts/` | **工程脚本**：工具安装、Python 环境、测试、结构校验；`re-env/` 为动态环境拉起 | 是 |
| `config/` | **配置**：工具清单 `tools.json`、Python 依赖声明 | 是 |
| `assets/` | **资源**：原始样本 `assets/assets/apk/base.apk`（只读基线） | 否 |
| `research/` | **研究过程**：分析脚本、证据、交付、历史归档（原 `research/`） | 部分 |
| `tools/` | 第三方逆向工具链 | 否（`pnpm` 恢复） |
| `reflutter_work/` | reFlutter 工作区与 Dart dump | 否 |

## 二、分层原则

```
┌──────────────────────────────────────────────────┐
│ docs/         结论与文档（人读，权威出口）        │
├──────────────────────────────────────────────────┤
│ src/ tests/   可复用实现 + 回归保障（代码依赖）   │
├──────────────────────────────────────────────────┤
│ research/     过程与证据（迭代、一次性）          │
├──────────────────────────────────────────────────┤
│ scripts/ config/ assets/ tools/   支撑层          │
└──────────────────────────────────────────────────┘
```

- **依赖方向单向**：`research/` 可以依赖 `src/`；`src/` **不得**依赖 `research/`。
- `research/` 是**证据与过程**，允许存在 `probe_A..I` 这类迭代版本，不追求整洁；
  但**对外交付**必须收敛到 `research/deliverables/`。
- `src/` 是**稳定接口**，必须可测试、可安装。
- `docs/` 是**结论**，必须与代码和结构一致（由 `pnpm validate` 保证）。

同一能力不要在 `research/deliverables/client/` 与 `src/jcy_protocol/` 重复实现：
前者保持冻结作为取证产物，新代码从 `jcy_protocol` 引用。

## 三、`research/` 内部分层

| 子目录 | 内容 | 入库 |
|---|---|---|
| `artifacts/` | `libcore.so`、设备内存镜像、区域 dump、blutter 产物 | 否（体积大） |
| `toolchain/` | Unicorn 模拟器、探针、调用树追踪、反汇编工具 | 是 |
| `deliverables/` | `authgen.py`、三通道解密、验证脚本 | 是 |
| `captures/` | 真实抓包 JSONL | 是 |
| `corpus/` | 语料（`ts` ↔ 密文） | 是 |
| `reports/` | 阶段报告（`VERIFICATION.txt` 等） | 是 |
| `archive/` | 历史版本（v5–v12）与早期脚本归档，**只读** | 部分 |

## 四、数据流

```
assets/assets/assets/apk/base.apk
   │
   ├─ apktool ──────────▶ smali（重建步骤见 research/README.md）
   ├─ jadx ─────────────▶ Java 层源码
   └─ blutter ──────────▶ research/artifacts/blutter_research/    pp.txt 对象池 / asm / frida 模板

设备（arm64 + Houdini）
   │
   ├─ frida / root dd ──▶ research/captures/proxy_*.jsonl     真实抓包
   │                      research/artifacts/regions_all/     设备内存区域 dump
   ▼
research/toolchain/（Unicorn 模拟器 + 探针）
   │
   ├─▶ research/corpus/O_corpus.json        语料
   ├─▶ research/deliverables/authgen.py     算法交付
   └─▶ docs/algorithm-auth.md               结论
   │
   ▼
src/jcy_protocol/                            稳定实现
tests/                                       回归保障
```

## 五、关键约束

1. **README 目录树必须与文件系统一致**。新增顶层条目后不更新 README，`pnpm validate` 会失败。
   骨架区（`.github/ assets/ config/ docs/ scripts/ src/ tests/`）还需**逐层登记**；
   产物区（`research/ reflutter_work/ tools/`）只要求顶层登记。
2. **文档内链必须有效**。`docs/_sidebar.md` 与各文档中的相对链接会被逐一校验。
3. **新增文档要登记到 `docs/_sidebar.md`**（`README.md` / `_sidebar.md` 除外）。
4. **工具不手工下载**：加入 `config/tools.json`，由 `pnpm tools:install` 获取。
5. **二进制不入库**：`.gitignore` 已覆盖工具链、APK、内存镜像、区域 dump。
6. **路径统一**：研究区脚本一律 `import paths as _P`（`research/toolchain/paths.py`），
   禁止硬编码 `../v11/...` 之类的相对路径。

## 六、扩展点

| 需求 | 落点 |
|---|---|
| 新增分析文档 | `docs/<分类>/`，并登记 `_sidebar.md` |
| 新增可复用能力 | `src/jcy_protocol/`，并在 `tests/` 加回归 |
| 新增测试 | `tests/`，向量放 `tests/fixtures/` |
| 新增分析脚本 | `research/toolchain/`，用 `paths.py` 取路径 |
| 新增对外交付 | `research/deliverables/`，并在其 README 登记 |
| 新增工具 | `config/tools.json` + `tools/README.md` |
| 新增工程脚本 | `scripts/`，共用逻辑放 `scripts/lib/` |
| 新增动态环境脚本 | `scripts/re-env/`，并在 README 目录树登记 |
| 新增 CI 校验 | `.github/workflows/` |

## 七、验证

```bash
pnpm validate       # 结构 + 内链 + 完整性 + 工具清单
pnpm test           # 协议测试 + authgen 回归 + 结构校验
```
