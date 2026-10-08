# 结构深度分析与专业规范对照

本文是对仓库目录结构的**深度分析报告**：现状全景、与业界规范的对照、
偏差清单与处置、演进路线。目录职责的日常约定见 [`structure.md`](structure.md)，
架构与模块职责见 [`architecture.md`](architecture.md)。

- 分析基线：2026-10-07（v0.2.0 之后、`src/web` 引入之初）
- 方法：全量目录扫描 + git 跟踪状态核对 + `pnpm validate` 实测 + 业界规范检索

---

## 一、现状全景：三区模型

仓库顶层 14 个目录 + 20 个文件。按治理方式分为三区，这是本仓库最核心的结构特征：

| 分区 | 目录 | 治理方式 | 结构校验 |
|---|---|---|---|
| **环境区**（不入库） | `.venv/ node_modules/ .workbuddy/ .workbuddy-ai/ .zcode/` | `.gitignore` + 校验器忽略清单 | 不校验 |
| **骨架区**（逐层登记） | `src/ tests/ docs/ scripts/ config/ assets/ .github/` | README 目录树**逐层**登记 | 双向校验 |
| **产物区**（顶层登记） | `research/ reflutter_work/ tools/` | README 只登记顶层；内容白名单入库 | 仅顶层 |

骨架区/产物区分层的合理性：骨架区是"人写的小而关键的代码与文档"，漂移代价高，
故逐层强制；产物区是"机器生成的大体量中间产物"，强求逐层登记只会制造维护噪音。

### 各目录实测画像

| 目录 | 规模 | git 跟踪 | 说明 |
|---|---|---|---|
| `src/tools/jcy_protocol/` | 4 个 py 模块 | 全部 | 稳定协议库（auth/channels/vectors） |
| `src/web/` | 61 个 UI 组件 + 64 份注册表 JSON | 全部（除 dist） | jcy-web 前端，脚手架阶段 |
| `tests/` | 3 个测试 + 1 份固化向量 | 全部 | 协议/算法回归 |
| `docs/` | 29 篇 md（6 个子分类） | 全部 | docsify 文档站，结论唯一出口 |
| `scripts/` | 6 个 mjs + re-env 2 件 | 全部 | 工程自动化 |
| `research/` | **约 8.8 GB**；根层散文件 420+ | 白名单 | 根层 `tmp_*` 386 个（**269 个已跟踪**） |
| `research/engine_c/` | 974 MB（6 个 DLL 入库） | DLL 白名单 | ARM64→C 转译引擎 |
| `research/tmp_perf/ tmp_regions/ tmp_go_jocy/` 等 | 309M / 102M / 58M | 不入库 | 临时实验工作区 |
| `tools/` | jadx / apktool / blutter / platform-tools | 不入库 | `pnpm tools:install` 可重建 |
| `assets/` | base.apk 样本 | APK 不入库 | 只读基线 |

---

## 二、与业界规范对照

参照三类规范：**monorepo 工程惯例**（Turborepo/Nx 生态的 `apps/ packages/ docs/ tools/`
布局与依赖方向约束）、**通用仓库命名惯例**（`src/` 小写短名、根级标准文件齐全）、
**研究数据管理惯例**（原始数据 / 处理脚本 / 产出物三分，证据可溯源）。
参考来源见文末。

| 业界惯例 | 本仓库对应 | 评价 |
|---|---|---|
| `apps/ + packages/` 分工作区，依赖单向 | `src/web`（应用）+ `src/tools/jcy_protocol`（库）双工作区，依赖单向（web→桥→协议） | ✅ 形态一致（应用与库同挂 `src/` 下，靠 README 分层说明补偿） |
| `docs/` 根置、与代码同库 | `docs/` docsify 站，29 篇分类文档 + 侧边栏覆盖校验 | ✅ 强于多数项目：文档登记有 CI 级强制 |
| 质量门禁进 CI（lockfile 漂移、受影响构建） | `pnpm validate`（结构↔文档双向 + 内链 + 完整性 + 工具清单）进 `.github/workflows/validate.yml` | ✅ 同类实践 |
| 研究数据三分：raw / scripts / outputs | `captures/`（raw）+ `toolchain/`（scripts）+ `deliverables/ reports/`（outputs）+ `archive/` | ✅ 完整对应，且冻结交付物（`client/gg_client.py`）与稳定库（`src/`）分离是安全研究仓库的加分实践 |
| 大文件不进 git、可重建 | `.gitignore` 白名单制 + `pnpm tools:install` + `research/README.md` 重建步骤 | ✅ 白名单制比黑名单制更稳（8.8GB 产物区仅代码与小样本入库） |
| 根级标准文件（LICENSE/CHANGELOG/CONTRIBUTING/SECURITY/.editorconfig） | 全部齐备 + `.gitattributes` + issue/PR 模板 | ✅ |
| 短小写目录名、根置工具配置 | 全部合规；`启动本地取签服务.bat` 为唯一非 ASCII 顶层名（面向人的一键脚本，可接受） | ✅ |

**结论：骨架已经达到专业水准**，且"结构↔文档自动互查"这一点超出常见开源项目。
偏差集中在两类：**新增工作区后的登记滞后**与**研究区根层的散落文件**。

---

## 三、偏差清单与处置

### P0 — 本次已修复（2026-10-07）

| # | 偏差 | 实测影响 | 处置 |
|---|---|---|---|
| 1 | `src/web/` 未登记 README 目录树 | `pnpm validate` **失败 8 项**（红） | README 树补登 `src/web` 全部骨架层级；校验器跳过 `.registry/`（shadcn 工具元数据，与 node_modules 同类） |
| 2 | `.zcode/`（AI 助手工作区）未忽略 | git 未跟踪但校验器报"未登记" | `.gitignore` 增补 + 校验器忽略清单（与 `.workbuddy` 同类） |
| 3 | 文档陈旧路径：`assets/assets/apk/...`、`research/auth_samples.json`（已不存在） | 误导新人 | `docs/structure.md`、`docs/architecture.md`、`docs/README.md` 已修正 |
| 4 | `package.json` 缺 web 工作区入口 | 每次要 `--filter` 手打 | 新增 `web:dev / web:build / web:preview` |

### P1 — 遗留项（建议，未执行）

**`research/` 根层散落文件整理**：根层有 420+ 个文件，其中 `tmp_*` 386 个
（269 个已被 git 跟踪，含 `tmp_perf/` 309M、`tmp_regions/` 102M 等临时目录）。
理想目标是把"当前迭代草稿"与"留档脚本"分离，例如：

```
research/
├── scratch/          # 一次性实验（tmp_* 大多数去处，gitignore）
├── bench/            # 基准脚本（bench_*.py，whitelist 入库）
└── …（现有分层不变）
```

**本次不执行**，原因（影响面实测）：
1. 269 个已跟踪文件的 rename 会产生巨型 diff，污染 `git blame`；
2. 5 篇文档把具体 `tmp_*` 路径作为**证据链接**引用（`e2e-decrypt`、`live-matrix`、
   `http-body`、`video-play`、`apipost-testing`），移动即断链；
3. `.gitignore` 白名单按文件名精确放行 4 个 `tmp_*` 文件，需同步迁移；
4. 项目章程（`structure.md`）明确"研究区允许迭代产物，不追求整洁"——
   在交付与文档全部收官的 V16 之后，收益/风险比不划算。

若未来执行，按 `MIGRATION.md` 的方式出对照表，并用
`git mv` + 文档链接批量修正 + `pnpm validate` 三步走。

### P2 — 观察项

| 项 | 现状 | 建议 |
|---|---|---|
| 根目录 `libcore.so`（6.8 MB 本地样本） | gitignore + 校验器已忽略；`research/artifacts/` 才是它的登记住所 | 属本地便利副本，可保留；若要清理，确认 `research/artifacts/libcore.so` 在位后删除 |
| 后端桥落点 | ~~建议落 `src/web/server/`~~ **已落地**：`server/main.py`（/api 透传、/resolve 播放解析、/stream 流代理、/health） | 前端入口与路由落码时同步 README 目录树登记 |
| `reflutter_work/` 价值 | reFlutter 工作区，活跃度低 | 若确认不再使用，整目录降级进 `research/archive/` 或删除 |

---

## 四、目标结构（分类后的专业形态）

```
jcy-reverse/
├── docs/                    结论层（唯一权威出口，docsify）
├── src/
│   ├── tools/jcy_protocol/  稳定库：协议加解密（可安装、可测试）
│   └── web/                 应用层：Web 前端（→ 后端桥 → 协议）
├── tests/                   回归保障（向量固化）
├── research/                研究层（白名单入库）
│   ├── deliverables/        对外交付（冻结取证产物 + 现役客户端）
│   ├── toolchain/           分析工具（模拟器/探针/反汇编）
│   ├── artifacts/           二进制产物（不入库，可重建）
│   ├── captures/ corpus/ reports/   证据与数据
│   ├── engine_c/            ARM64→C 转译引擎（DLL 白名单）
│   └── archive/             历史版本（只读）
├── scripts/ config/         工程自动化与配置
├── assets/ tools/ reflutter_work/   资源与外部工具（不入库/可重建）
└── 根级文件                  README / CHANGELOG / MIGRATION / CONTRIBUTING / SECURITY / LICENSE
```

依赖方向：`docs` ← `src/web` ← `src/tools/jcy_protocol` ← `research` ← 支撑层。

---

## 五、维护规则（保持专业的四条铁律）

1. **新增顶层条目 / 骨架区子目录 → 同一个 commit 里更新 README 目录树**，
   `pnpm validate` 红不算完。
2. **新增文档 → 登记 `docs/_sidebar.md`**（校验器逐篇核对）。
3. **大文件 → 白名单或 gitignore**，重建步骤写进对应 README，不入库。
4. **研究区收尾节奏**：一次战役（如 V16 播放链）结束后，把可复用结论沉淀到
   `docs/`、可复用代码沉淀到 `src/`，其余留在 `research/` 由白名单决定入库范围。

---

## 参考来源

- [Turborepo：monorepo 布局与缓存实践](https://www.getclaudeskills.com)
- [Architecting JavaScript Monorepos: Structural Patterns](https://javascript.plainenglish.io)
- [Designing for Scale: Repository Structures that Boost Productivity](https://dev.to)
- [kriasoft/Folder-Structure-Conventions](https://github.com/kriasoft/Folder-Structure-Conventions/blob/master/README.md)
- [Andrews Lab Handbook：raw / processed / scripts / outputs 三分法](https://andrewslabucsf.github.io/Lab-Handbook/scripts/directories.html)
- [NBIS：Organising files and folders（研究数据管理）](https://nbisweden.github.io/module-organising-data-dm-practices/002-files-and-folders/index.html)
- [CASRAI：研究数据文件命名与目录约定](https://casrai.org/guides/file-naming-and-folder-structure-conventions-for-research-data)
