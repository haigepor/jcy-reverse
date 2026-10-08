# 系统架构与模块职责

本文说明本仓库的**分层架构、模块职责、数据流与依赖方向**。
目录职责与「入库策略」见 [`structure.md`](structure.md)；`authentication` 算法见 [`algorithm-auth.md`](algorithm-auth.md)。

---

## 一、分层视图

```
┌───────────────────────────────────────────────────────────────┐
│  docs/            结论层：分析结论、算法说明、接口文档          │  ← 人读，权威出口
├───────────────────────────────────────────────────────────────┤
│  src/web/         应用层：Web 前端（jcy-web，经后端桥消费）     │  ← 浏览器先行，预留 Tauri v2
├───────────────────────────────────────────────────────────────┤
│  src/             源码层：可复用库 jcy_protocol                │  ← 稳定接口，可安装
│  tests/           测试层：向量回归 + 算法回归                  │
├───────────────────────────────────────────────────────────────┤
│  research/        研究层：分析脚本、证据、交付、历史归档        │  ← 过程与证据
│  ├─ deliverables/  对外交付（authgen、三通道解密）             │
│  ├─ toolchain/     分析工具（模拟器、探针、反汇编）            │
│  ├─ artifacts/     必需二进制产物                              │
│  ├─ captures/ corpus/ reports/   证据与数据                    │
│  └─ archive/       历史版本归档                                │
├───────────────────────────────────────────────────────────────┤
│  scripts/ config/ assets/ tools/   支撑层：自动化、配置、资源   │
└───────────────────────────────────────────────────────────────┘
```

**依赖方向是单向的**：`docs` ← `src/web` ← `src/tests` ← `research` ← `scripts/config/assets`。
`research/` 允许依赖 `src/`，但 `src/` **不得**依赖 `research/`；
`src/web/` 只经 HTTP 调后端桥（`src/web/server/`），不得直接 import Python 层。

---

## 二、模块职责

### 2.1 `src/tools/jcy_protocol/` — 可复用协议库

| 模块 | 职责 |
|---|---|
| `jcy_protocol/auth.py` | **`authentication` 算法的纯逻辑实现**：自定义字母表编解码、输入串构造、body 拆分、头拼装；定义 `EBackend` 协议。零大文件依赖 |
| `jcy_protocol/channels.py` | 监控通道（AES-128-CBC，key `qPwClBj7j7ZQraSm`）与信令通道（AES-128-CBC，key `kFGTbLlOzFHQCIKp`）的加解密实现 |
| `jcy_protocol/vectors.py` | 测试向量与已知明文/密文对 |
| `jcy_protocol/__init__.py` | 包导出 |

> 设计原则：**稳定、可测试、无外部大文件依赖**。
> `auth.py` 把分组密码 `E` 抽象为 `EBackend` 协议，实现方由 `research/` 注入
> （当前是 Unicorn 后端）。这样 `src/` 不会反向依赖 `research/` 的大产物，
> 未来若把 `E` 还原为纯 Python，只需实现一个满足该协议的类即可无缝替换。
> 与 `research/deliverables/client/gg_client.py` 的关系：后者是**冻结的取证产物**，
> 新代码从 `jcy_protocol` 引用，同一能力不重复实现。

### 2.2 `src/web/` — Web 前端（jcy-web）

| 项 | 说明 |
|---|---|
| 技术栈 | Vite 7 + React 19 + TypeScript 5.9 + Tailwind 4 + shadcn/ui（61 组件）+ ArtPlayer + hls.js |
| 职责 | 频道 / 列表 / 详情 / 播放的浏览器端 UI；预留 Tauri v2 桌面打包 |
| 边界 | **不实现协议**：`/api`、`/stream` 反代到后端桥 `server/main.py`（FastAPI :8792，封装 `jcy_api.py`） |
| 状态 | 前端脚手架 + 后端桥就绪（`/api` 透传、`/resolve` 播放解析、`/stream` 流代理）；`src/main.tsx` 应用入口与路由待落码 |

### 2.3 `tests/` — 测试层

| 文件 | 覆盖 | 依赖 |
|---|---|---|
| `test_channels.py` | 两条 AES 通道的加解密向量回归 | `pycryptodome`、`src/tools/jcy_protocol` |
| `test_auth_pure.py` | `authentication` 算法**纯逻辑**单元测试（字母表往返、输入串、body 结构、主流程） | 无（可随时运行） |
| `test_authgen.py` | `authentication` 端到端回归（5 项断言） | `unicorn`、`research/artifacts/`；缺失时 SKIP=77 |
| `fixtures/authgen_vector.json` | 固化的真机向量 | — |

### 2.4 `research/toolchain/` — 分析工具

| 模块 | 职责 |
|---|---|
| `paths.py` | **统一路径解析**：所有研究区脚本的唯一路径入口 |
| `emu_v11.py` | libcore.so 的 Unicorn 模拟器（真机基址 `0x400024a00000` + 运行时内存镜像） |
| `emu_v12.py` / `emu_v14.py` | 模拟器变体：后者额外加载全部 813 个设备 rw 区域 |
| `v13.py` | 驱动：`collect`（收集缺页）/ `dump`（拉取区域）/ `run`（执行）/ `auto`（迭代补区） |
| `dasm.py` | capstone 反汇编工具（vaddr 区间） |
| `trace304.py` / `trace_E.py` | 运行时调用树追踪 |
| `trace_sbox.py` | S-box 内存读取监视（用于定位密码原语） |
| `probe_*.py` | 阶段性探针：中间量 dump、受控实验（`probe_D.py` 支持 `A1HEX/KEYHEX/IVHEX/TAG`） |
| `sm4.py` | 纯 Python SM4（含 GB/T 32907-2016 自检），用于排除性验证 |
| `brute_E.py` | E 的算法爆破（AES/SM4 全参数空间） |
| `dump_all.py` / `run_dump.py` | 设备内存区域批量 dump |

### 2.5 `research/deliverables/` — 对外交付

| 文件 | 职责 |
|---|---|
| `authgen.py` | **`authentication` 头离线生成器**（含 `--selftest` / `--test-server`） |
| `verify_server.py` | 服务端正例 + 阴性对照 |
| `verify_corpus.py` / `verify_corpus_batch.py` | 语料 `O[0:32]` 核验（逐进程 / 单模拟器批量） |
| `probe_matrix.py` / `probe_matrix2.py` | 端点可请求性矩阵 |
| `engine_min.py` | 最小内存引擎尝试（未成功，留档） |
| `decrypt_v5/` | 三通道解密脚本 + 内存明文提取 + 播放链路 |
| `client/` | 冻结的取证客户端与 frida 脚本族 |
| `demo/` | 离线播放验证页 |

---

## 三、数据流

```
assets/apk/base.apk
   │
   ├─ apktool ─────▶ smali（重建步骤见 research/README.md）
   ├─ jadx ────────▶ Java 源码
   └─ blutter ─────▶ research/artifacts/blutter_out/   Dart 对象池 / asm / frida 模板

设备（arm64 + Houdini）
   │
   ├─ frida / root dd ─▶ research/captures/proxy_*.jsonl     真实抓包
   │                     research/artifacts/regions_all/     设备内存区域 dump
   │
   ▼
research/toolchain/（Unicorn 模拟器 + 探针）
   │
   ├─▶ research/corpus/O_corpus.json        语料（ts ↔ 密文）
   ├─▶ research/deliverables/authgen.py     算法交付
   └─▶ docs/algorithm-auth.md               结论
   │
   ▼
src/tools/jcy_protocol/   稳定实现
tests/              回归保障
   │
   ▼
research/deliverables/jcy_api.py   App 级客户端（签名 / 加密 / 解密全自动）
   │  HTTP（/api、/stream，后端桥 src/web/server/ :8792）
   ▼
src/web/            Web 前端
```

---

## 四、`authentication` 生成时序

```
authgen.gen(ts)
   │
   ├─ build_input(ts)                       → S   (78B)
   ├─ custom_b64(S)                         → A1  (104B)
   ├─ encrypt_body(A1)  ── Unicorn ──┐
   │     Emu4()                       │
   │       ├─ 加载 libcore.so         │
   │       ├─ 加载 libcore_dev_img.bin│
   │       ├─ 加载 regions_all/ (813) │
   │       ├─ fix_long_string(0x688130, KEY)
   │       ├─ hook 0x304fb8：把 A1 写回 A 的输出向量
   │       ├─ hook 0x3050fc：读取 E 的输出
   │       └─ call 0x304eb0(S, &key, &iv)
   │                                  │
   │                                  ▼
   └─ custom_b64(BODY)                      → AUTH (152 字符)
```

> `0x304eb0` 内部的 A 编码器在模拟环境中不可靠，因此**用 Python 计算 A1 并强制回写**，
> 只让模拟器负责 E 的计算。这样既精确又稳定。

---

## 五、关键约束

| 约束 | 说明 |
|---|---|
| 路径 | 研究区脚本一律 `import paths as _P`，禁止硬编码相对路径 |
| 产物 | `research/artifacts/` 中的二进制不入库，重建步骤见 `research/README.md` |
| 文档 | `docs/` 下每篇文档必须登记到 `docs/_sidebar.md`（由 `pnpm validate` 强制） |
| 结构 | 骨架区目录必须逐层登记在 `README.md` 目录树中（由 `pnpm validate` 强制） |
| 环境 | 一律使用项目 `.venv`（`./.venv/Scripts/python.exe`），不用系统 Python |
