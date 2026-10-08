# 囧次元逆向工程 (jcy-reverse)

Android 应用 **囧次元**（`com.tudou.tool`，Flutter / Dart AOT 3.6.0 arm64，versionName 1.5.8.0）
的逆向研究工程：协议取证、加密通道还原、`authentication` 头算法完全破解与离线生成器；
并在结论之上重建了两套可运行客户端 —— **Web 前端**与**安卓 App**（复用同一份 `libcore.so`）。

> **本仓库以研究记录 + 可运行工具链为主**，`src/` 下的 Web 前端与安卓客户端是在
> 逆向结论之上重建的完整实现（非官方代码）。
> 目录分层与数据流见 [`docs/structure.md`](docs/structure.md)；
> 系统架构与模块职责见 [`docs/architecture.md`](docs/architecture.md)；
> 结构深度分析与专业规范对照见 [`docs/structure-review.md`](docs/structure-review.md)；
> `authentication` 算法原理与用法见 [`docs/algorithm-auth.md`](docs/algorithm-auth.md)；
> 安卓客户端（Capacitor + JNI → libcore.so）见 [`docs/app-client.md`](docs/app-client.md)。

---

## 目录结构

```
jcy-reverse/
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
├── src/                          【源码层】三个并列工作区：协议库 + Web 前端 + 安卓客户端
│   ├── README.md
│   ├── tools/                    【库·Python】jcy_protocol 协议加解密库（可 pip 安装）
│   │   ├── README.md             定位 / 谁在用它 / 安装方式
│   │   ├── pyproject.toml        jcy-protocol 打包声明
│   │   └── jcy_protocol/         ★ auth.py 为 authentication 算法纯逻辑实现
│   ├── web/                      【应用层·Web】jcy-web 前端（shadcn/ui + ArtPlayer）
│   │   ├── README.md
│   │   ├── package.json          前端工作区声明（Vite 7 / React 19 / Tailwind 4）
│   │   ├── vite.config.ts        dev:5174；/api、/resolve、/stream 反代后端桥 :8792
│   │   ├── tsconfig.json
│   │   ├── components.json       shadcn/ui 配置
│   │   ├── index.html            Vite 入口
│   │   ├── public/               静态资源（favicon.svg）
│   │   ├── server/               后端桥（FastAPI :8792，封装 jcy_api）
│   │   │   ├── main.py           /api 透传 + /resolve 播放解析 + /stream 流代理
│   │   │   └── requirements.txt
│   │   └── src/
│   │       ├── main.tsx          应用入口（QueryClient + Router，6 路由）
│   │       ├── index.css         Tailwind v4 + shadcn 主题变量
│   │       ├── components/
│   │       │   ├── layout/       应用外壳（桌面侧边栏 / 移动底部 tab）
│   │       │   ├── player/       ArtPlayer 播放器封装（弹幕/清晰度/续播）
│   │       │   └── ui/           shadcn/ui 生成组件（61 个）
│   │       ├── hooks/            use-danmu（60s 增量轮询）等
│   │       ├── pages/            home / channel-more / search / time-line / video / mine
│   │       ├── store/            zustand 全局状态（弹幕设置/清晰度偏好/本地进度）
│   │       └── lib/              api 客户端 / types（GVideo 模型）/ codec（HEVC 检测）
│   └── app/                      【应用层·Android】jcy-app（Capacitor + React + Kotlin/JNI）
│       ├── README.md             技术选型结论与构建步骤
│       ├── package.json          工作区声明（@capacitor/* v7）
│       ├── capacitor.config.ts   appId/appName/webDir=www；androidScheme=http
│       ├── scripts/
│       │   ├── build_web.sh      构建 src/web → src/app/www（注入 VITE_API_BASE）
│       │   ├── extract_so.sh     从 assets/apk/base.apk 提取 libcore.so → jniLibs
│       │   ├── gen_cap_template.sh  生成标准 Capacitor 工程用于补模板文件
│       │   └── install_android_sdk.sh  安装 SDK/NDK/CMake 到 C:\Android\Sdk
│       └── android/              Capacitor 安卓工程
│           ├── settings.gradle / build.gradle / variables.gradle / gradle.properties
│           ├── local.properties   sdk.dir（不入库）
│           └── app/
│               ├── build.gradle   AGP 8.7.2 + NDK + abiFilters arm64-v8a
│               └── src/main/
│                   ├── AndroidManifest.xml
│                   ├── cpp/        jcy_core_jni.c（dlopen libcore.so 的 JNI 桥）+ CMakeLists.txt
│                   ├── java/app/video/guoguo/
│                   │   ├── MainActivity.kt       宿主：注册插件 + 启动本机桥 + init libcore
│                   │   ├── Diag.kt               诊断总线（/diag、__JCY_DIAG__、落盘 三出口）
│                   │   ├── JcyCore.kt            libcore.so 的 Kotlin 门面（init/call/encrypt/decrypt）
│                   │   ├── JcyCorePlugin.kt      暴露给 WebView 的 Capacitor 插件（后台线程执行）
│                   │   ├── JcyApi.kt             主 API 客户端（信封搬运 + 播放解析 + 直链头规则）
│                   │   └── JcyBridgeServer.kt    本机 127.0.0.1:8792 桥（与 FastAPI 桥同路由契约）
│                   └── res/        图标、主题、network_security_config（明文 HTTP 放行）
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
│   ├── app-client.md             ★ 安卓客户端（Capacitor + JNI → libcore.so）
│   ├── frontend.md               ★ Web 前端架构与播放器设计（含原 App 播放器分析）
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
| Dart 结构还原 | blutter 产物（对象池/asm/frida 模板） | `research/artifacts/blutter_out/` |
| 离线验证页 | hls.js 播放验证 | `research/deliverables/demo/index.html` |
| Web 前端（jcy-web） | 6 页面应用已落码（首页/频道/搜索/排期/播放/我的），61 个 shadcn/ui 组件 + FastAPI 后端桥 + ArtPlayer 弹幕播放器闭环 | `src/web/` |
| **安卓 App（jcy-app）** | **端到端跑通**：Capacitor 7 + React 复用 + Kotlin/JNI 直调 `libcore.so`；首页/频道/搜索/播放全链路 `code=20000` | `src/app/`、[`docs/app-client.md`](docs/app-client.md) |
| 安卓端性能 | 冷启动首个业务响应 **+2.47 s**、首屏全量 **+4.38 s**、热态单接口 **p50 ≈ 100 ms** | `research/reports/V31_performance_benchmark.md` |
| `init` 真值取证 | 从官方 App 运行内存直读出 `tcp=43.145.33.254:8191`、`files_path=<dataDir>/files` | `research/reports/V30_init_json_groundtruth.md` |

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

# 5) Web 前端
pnpm web:dev                    # http://localhost:5173
#   后端桥（另开终端，先装依赖：./.venv/Scripts/pip install -r src/web/server/requirements.txt）
./.venv/Scripts/python.exe src/web/server/main.py     # 127.0.0.1:8792

# 6) 安卓 App（前置：Android SDK + NDK 27 + JDK 21）
bash src/app/scripts/extract_so.sh                    # 从原版 APK 提取 libcore.so（只需一次）
pnpm app:web                                          # 构建 React → src/app/www
pnpm app:sync                                         # cap sync android
pnpm app:apk                                          # 产物 build/outputs/apk/debug/app-debug.apk
#   装机自检见 docs/app-client.md「构建与自检」
```

---

## 约定

- **文档优先**：结论先写进 `docs/`，脚本再从结论实现。
- **路径统一**：研究区脚本一律通过 `research/toolchain/paths.py` 取路径，禁止硬编码相对路径。
- **证据可复现**：每个结论都指向 `research/reports/` 或 `research/captures/` 中的真实数据。
- **大文件不入库**：工具链、内存镜像、区域 dump 由 `pnpm tools:install` 或
  [`research/README.md`](research/README.md) 中的重建步骤恢复。
