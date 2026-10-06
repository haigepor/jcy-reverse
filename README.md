# 囧次元逆向工程 (jcy-reverse)

Android 应用 **囧次元**（`com.tudou.tool`，Flutter / Dart AOT 3.6.0 arm64，versionName 1.5.8.0）
的逆向研究工程：协议取证、加密通道还原、`authentication` 头算法完全破解与离线生成器。

> **本仓库是研究记录 + 可运行工具链，不是产品代码。**
> 目录分层与数据流见 [`docs/structure.md`](docs/structure.md)；
> 系统架构与模块职责见 [`docs/architecture.md`](docs/architecture.md)；
> `authentication` 算法原理与用法见 [`docs/algorithm-auth.md`](docs/algorithm-auth.md)。

---

## 目录结构

```
囧次元/
├── README.md                     项目总览（本文件）
├── MIGRATION.md                  2026-09-30 目录重构迁移对照表
├── CHANGELOG.md                  变更记录
├── CONTRIBUTING.md               贡献约定
├── SECURITY.md                   安全与披露说明
├── LICENSE                       授权
├── package.json                  Node 工程入口（工具安装/测试/校验/文档）
├── pnpm-workspace.yaml           pnpm 工作区声明
├── pnpm-lock.yaml                Node 依赖锁
├── recipes.json                  文档站/工具链配方索引
├── .editorconfig                 编辑器统一风格
├── .gitattributes                Git 属性
├── .gitignore                    忽略规则（工具链、大二进制、隔离区）
├── .npmrc                        npm 源与引擎策略
├── .zcodeignore                  检索排除规则
├── 启动本地取签服务.bat          一键常驻本地取签/解密服务（Apipost 点发送前先跑它）
│
├── .github/                      CI 配置
│   ├── ISSUE_TEMPLATE/
│   └── workflows/
│
├── src/                          【源码层】可复用库
│   ├── README.md
│   ├── pyproject.toml            jcy-protocol 打包声明
│   └── jcy_protocol/             ★ auth.py 为 authentication 算法纯逻辑实现
│
├── tests/                        【测试层】
│   ├── README.md
│   ├── test_channels.py          三通道向量回归
│   ├── test_auth_pure.py         authentication 纯逻辑单元测试（无需模拟器）
│   ├── test_authgen.py           authentication 端到端回归（5 项断言）
│   └── fixtures/                 固化测试向量
│
├── docs/                         【文档层】docsify 文档站（结论的唯一权威出口）
│   ├── README.md
│   ├── _sidebar.md
│   ├── index.html
│   ├── installation.md           环境安装
│   ├── structure.md              目录职责与数据流
│   ├── architecture.md           系统架构与模块职责
│   ├── algorithm-auth.md         ★ authentication 算法原理与用法
│   ├── reverse-journal-auth.md   ★ authentication 逆向全记录（思路与推理）
│   ├── scripts-index.md          脚本索引
│   ├── tags.md                   标签与版本
│   ├── git-push-prompt.md        推送流程提示词
│   ├── analysis/                 分析过程（evidence / journey / open-questions / toolchain）
│   ├── api/                      接口层结论（overview / endpoints / video-list / video-play / device-base / apipost-library / apipost-testing）
│   ├── assets/                   文档站静态资源
│   ├── crypto/                   加密层结论（overview / http-body / monitor-channel / signaling-channel / x-token）
│   ├── prompts/                  提示词模板
│   └── setup/                    环境搭建（ldplayer-magisk-env / re-modules）
│
├── config/                       【配置层】
│   ├── tools.json                第三方工具清单与安装集
│   ├── requirements.txt          Python 运行依赖
│   └── requirements-analysis.txt Python 分析依赖
│
├── scripts/                      【脚本层】工程自动化
│   ├── bootstrap.mjs             工具链安装/状态
│   ├── python-setup.mjs          Python 环境构建
│   ├── run-tests.mjs             测试入口
│   ├── validate-structure.mjs    结构 ↔ 文档一致性校验
│   ├── lib/
│   └── re-env/                   动态环境拉起与验收
│
├── assets/                       【资源层】
│   ├── README.md
│   └── apk/                      原始样本 base.apk（只读基线）
│
├── research/                     【研究层】分析过程与产物
│   ├── README.md
│   ├── artifacts/                必需二进制产物（libcore.so、设备内存镜像、区域 dump）
│   ├── toolchain/                分析脚本（Unicorn 模拟器、探针、反汇编工具）
│   ├── deliverables/             ★ 对外交付（authgen、三通道解密、验证脚本）
│   ├── captures/                 真实抓包（proxy_capture / proxy_bodies）
│   ├── corpus/                   语料（O_corpus / O_true_corpus）
│   ├── reports/                  阶段报告（VERIFICATION.txt、API_MATRIX_V5 等）
│   └── archive/                  历史版本与早期脚本归档（v5–v12、legacy-*）
│
├── reflutter_work/               reFlutter 工作区（Dart dump 等大文件不入库）
└── tools/                        第三方工具链（apktool / jadx / blutter / frida；不入库）
```

---

## 成果速览

| 目标 | 状态 | 位置 |
|---|---|---|
| `authentication` 头算法 | **完全破解**，服务端实测通过 | [`research/deliverables/authgen.py`](research/deliverables/authgen.py) |
| 监控通道解密（AES-128-CBC） | 已破解 | `research/deliverables/decrypt_v5/chan1_monitor.py` |
| 信令通道解密（AES-128-CBC） | 已破解 | `research/deliverables/decrypt_v5/chan2_signaling.py` |
| HTTP body 结构（双向 RSA-2048 + AES） | 结构已定论 | `research/deliverables/decrypt_v5/chan3_http.py` |
| 视频播放接口全链路 | 端点/参数/头/链路全部还原 | [`docs/api/`](docs/api/overview.md) |
| 登录逻辑（设备静默登录） | device-base + X-Token 机制 | [`docs/api/device-base.md`](docs/api/device-base.md)、[`docs/crypto/x-token.md`](docs/crypto/x-token.md) |
| 播放直链提取 | 已打通（含 MP4 直链实测） | `research/deliverables/decrypt_v5/run_play.py` |
| 离线客户端库 | 加密层已验证 | `research/deliverables/client/gg_client.py` |
| Dart 结构还原 | blutter 产物（对象池/asm/frida 模板） | `research/artifacts/blutter_research/` |
| 离线验证页 | hls.js 播放验证 | `research/deliverables/demo/index.html` |

---

## 快速开始

```bash
# 1) 环境（Node 22+ / pnpm 9+）
pnpm install                  # 依赖 + core 工具 + Python .venv
pnpm tools:status             # 查看工具链状态
pnpm validate                 # 校验目录结构 ↔ 文档一致

# 2) 测试
pnpm test                                      # 协议向量 + authgen 回归
./.venv/Scripts/python.exe tests/test_authgen.py

# 3) 生成 authentication 头（离线，无需真机/网络）
./.venv/Scripts/python.exe research/deliverables/authgen.py --selftest
./.venv/Scripts/python.exe research/deliverables/authgen.py                 # 当前时间
./.venv/Scripts/python.exe research/deliverables/authgen.py --test-server   # 顺带打真实服务器

# 4) 文档站
pnpm docs:serve
```

---

## 约定

- **文档优先**：结论先写进 `docs/`，脚本再从结论实现。
- **路径统一**：研究区脚本一律通过 `research/toolchain/paths.py` 取路径，禁止硬编码相对路径。
- **证据可复现**：每个结论都指向 `research/reports/` 或 `research/captures/` 中的真实数据。
- **大文件不入库**：工具链、内存镜像、区域 dump 由 `pnpm tools:install` 或
  [`research/README.md`](research/README.md) 中的重建步骤恢复。
