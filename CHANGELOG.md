# 变更日志

本文件记录本项目的显著变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循语义化版本。

## [未发布]

### 新增

- **安卓客户端（`src/app/`）端到端跑通**：Capacitor 7 + React（复用 `src/web`）+
  Kotlin/JNI(C) 直接 `dlopen` `libcore.so`。首页 / 频道 / 搜索 / 播放全链路
  `code=20000`，冷启动首个业务响应 **+2.47 s**、首屏全量 **+4.38 s**、
  热态单接口 **p50 ≈ 100 ms**。详见 [`docs/app-client.md`](docs/app-client.md)
- **`init` 真值取证（V30）**：用自研内存扫描器 `research/tools/memfind.c` 直接读官方 App
  `com.tudou.tool` 运行内存，取出它传给 libcore 的原始 JSON —— 修正了两处导致
  `call` 永久挂死的参数：`tcp` 应为 **`43.145.33.254:8191`**（不是 HTTP 业务端口的 27990）、
  `files_path` 应为 **`<dataDir>/files`**（不是 `<dataDir>/app_flutter/files`）
- **回调 ABI 纠正**：真机实证回调参数顺序是 `(result, ctx)`（x0 才是 base64 载荷），
  与 Dart 侧 `(dynamic, Pointer<Utf8>)` 声明的静态推断相反；现行 `jcy_callback()`
  改为**双探针自动判序**（谁像 base64 谁就是载荷），并新增 `safe_new_string()`
  防止 `NewStringUTF` 收到非 UTF-8 时 `SIGABRT` 整个进程
- **性能基准（V31）**：`research/reports/V31_performance_benchmark.md` ——
  冷启动时间线、热态接口分布、native 层耗时分解、与官方 App 的对照
- **`docs/app-client.md`**：安卓客户端权威文档（技术选型 / 架构 / JNI 契约 /
  启动顺序 / 性能 / 本机桥路由 / 已知限制）
- **`src/web/`：jcy-web 前端工作区入库**（React 19 + Vite 7 + Tailwind 4 +
  61 个 shadcn/ui 组件 + ArtPlayer 弹幕播放器 + FastAPI 后端桥）
- **`src/tools/`：协议库新家** —— `jcy_protocol`（`auth.py` / `channels.py` / `vectors.py`）
  与 `pyproject.toml` 由 `src/` 根迁入，`src/` 确立为「tools / web / app」三并列工作区
- `scripts/validate-structure.mjs`：结构校验增强（嵌套目录逐层校验 + 文档内链 + 侧边栏覆盖）
- `scripts/cleanup-artifacts.py` / `scripts/move_leftovers.sh`：产物清理与目录搬迁工具

### 变更

- **前端全站样式重设计（深色优先 + 品牌橙红 `#FF5C39`）**：建立统一设计 token
  （`src/web/src/index.css`），6 个页面全部重做布局层级。结构性改动：
  1. **取消移动端全局顶栏** —— 旧版它是「搜索番剧…」输入框 + 琥珀色「诊断」胶囊，
     在**所有页面**（含视频详情页）常驻，导致首页/搜索页各自又加搜索入口（同屏两个
     搜索框）、详情页无法沉浸。现改为各页自带 `PageHeader`。
  2. **诊断入口收走**：不再常驻悬浮按钮；保留「/health 连续 3 次不通自动展开」兜底，
     手动入口移到「我的」页底部（`jcy:open-diag` 事件）。
  3. **底部 tab 重做**：`flex-1` 均分 + 选中态品牌色 + 顶部指示条 + 图标加粗。
  4. **卡片角标体系统一**：旧版 rail 用底部渐变条、grid 用左上小标签（两套语言），
     现统一为「左上=更新状态、右上=评分」；标题改两行截断。
  5. **详情页沉浸化**：播放器贴顶全出血 + 浮动返回钮；简介规范化（折叠原始数据里的
     全角空格填充，去掉中文标点后空格）；类型/年份/地区拆成独立胶囊；选集改 5 列网格；
     「展开全部（1 集）」与「选集 N」tab 的重复表达去掉。
  6. **搜索页补空态**：搜索历史（localStorage）+ 大家都在搜 + 热门推荐网格，
     替换原来那句「输入关键词开始搜索」+ 90% 空白；分页改无限滚动。
  7. **排期页**：7 个日期从 3 行网格改单行横滑；去掉页脚给开发者看的接口说明。
  8. **ArtPlayer 主题色对齐**：其默认 `--art-theme` 是**纯红 `#f00`**（源码实证），
     与品牌色打架 —— 症状是播放器进度条最左端停着一个孤立红点，已设 `theme: "#FF5C39"`。
  9. 「我的」页文案用户化（去掉「服务端返回 50008」这类接口黑话）。

  真机验证（雷电 14 / Android 14）：首页 / 搜索 / 排期 / 我的 / 详情 / 频道列表
  6 个页面截图核对通过，`validate-structure.mjs` 通过。

### 修复

- **POST body 中文被破坏成 U+FFFD（「视频解析链接失败」根因）**：前端发的是
  `Content-Type: application/json`（**不带 charset**），NanoHTTPD 的 `parseBody()`
  按默认字符集解码，body 里**每个**非 ASCII 字节都被换成 U+FFFD ——
  `{"vid":"103558","part":"第1集"}` 的集数名变成 3 个替换字符，
  编码后发往服务端即 `part=%EF%BF%BD%EF%BF%BD%EF%BF%BD1%EF%BF%BD…`，
  服务端查不到该集 → `400404 查询无果`。修复：`JcyBridgeServer.readBodyUtf8()`
  改按 Content-Length **读原始字节、强制 UTF-8 解码**，绕开 NanoHTTPD 的字符集猜码；
  另在 `JcyApi.play()` 加 U+FFFD 探针，让同类损坏在日志里立刻可见。
  验证：吞噬星空（id=103558）7 个集 × 2 清晰度 = 14 条直链全部 `code=20000`，
  取流 200 OK（221 MB / 355 MB / 667 MB / 1.44 GB）
- **启动顺序**：桥必须先于 `init` 起监听。旧顺序（load → init → 起桥）下
  `init` 阻塞使桥迟迟不监听，前端首批 `/api` 请求全部 `ECONNREFUSED`，
  React Query 重试耗尽后**界面永久停在骨架屏**且不再自愈
- **`init` 不再空等回调**：实测三轮冷启动回调 0 次（init 是同步语义），
  原 3000 ms 等待会占住 `g_call_lock` 并被 1:1 转嫁成首屏延迟 ——
  改为 0 后首个业务响应 **+6146 ms → +2473 ms（−60%）**
- **native 调用超时贯通**：新增 JNI `nativeCallTimeout(b64, ms)` 与 Kotlin
  `callRawTimeout()`，`JcyApi.request()` 端到端透传超时；`/probe` 每项 4 s 超时，
  避免一个挂死的 action 钉住 `g_call_lock` 并耗干 NanoHTTPD 的 4 个请求线程
- **本机桥契约对齐**（4 处）：`/stream` 无 Range 时不再注入 `Range: bytes=0-0`
  （否则视频播不出来）、白名单 `xajtl.com` 拼写、`/resolve` 缓存命中续白名单 TTL、
  `/resolve` 缓存写入条件补 `playAddr`
- **`init` 字段顺序**：对齐官方原文 `{app_id, device_id, code_version, app_version,
  files_path, tcp}`；并移除 `appId ?: resolveAppId()` 回落（那会在 init 之前先发一次
  native call，导致 `10032 未初始化`）

### 变更

- **研究区白名单扩容**：`research/reports/*.md` 纳入版本库（约 612 KB 的阶段报告，
  README 约定「每个结论都指向 `research/reports/`」需要它们可被检出）
- **清理 262 个中间脚本**：`research/tmp_*.py`（一次性探索脚本，结论已固化进
  `docs/` 与 `research/reports/`）

### 文档

- `README.md`：新增「成果速览」中安卓 App 与性能条目、目录树补 `docs/app-client.md`
  与 `Diag.kt`、快速开始补 App 构建命令
- `src/app/README.md`：修正过时的 `tcp=27990`、`jcyCore.ts` 引用与构建命令
  （`NODE_OPTIONS=` 而非 `CODEBUDDY_SAFE_DELETE_ENABLED=0`）；
  「待验证项」改为「装机自检（全部通过）」+「已知限制」
- `docs/_sidebar.md`：登记 `app-client.md`

### 移除

- `src/app/web/`（空目录，其中的 `jcyCore.ts` 适配层未随代码落地）
- `research/tmp_*.py`（262 个一次性探索脚本）

- **`authentication` 头算法完全破解**：`CUSTOM_B64( E( CUSTOM_B64( S ) ) )`，
  服务端实测 HTTP 200；交付 `research/deliverables/authgen.py`
  （详见 `docs/algorithm-auth.md`、`research/reports/VERIFICATION.txt` 第四阶段 [G1]–[G8]）
- **`src/tools/jcy_protocol/auth.py`**：算法的**纯逻辑实现**（字母表编解码、输入串构造、
  body 拆分、头拼装）+ `EBackend` 协议；零大文件依赖，可独立测试
  （原路径 `src/jcy_protocol/`，2026-10-08 迁入 `src/tools/`）
- **`docs/reverse-journal-auth.md`**：`authentication` 逆向全记录 ——
  14 个阶段、每步的观察/假设/验证/结论，含被证伪的假设与可复用手法清单
- **`tests/test_auth_pure.py`**：纯逻辑单元测试（字母表往返、输入串格式、
  body 结构、主流程拼装），无需模拟器
- **最小区域集**：`research/artifacts/regions_min/`（5 个区域 / 28.6 MB，
  原 813 个 / 424 MB），由 `toolchain/probe_regions.py` 统计得出，结果逐字节一致
- 新探针：`toolchain/{probe_ksa,probe_xtime,probe_regions,try_custom_aes}.py`
- `research/`：由原 `out/` 重构而来，内部分层为
  `artifacts/ toolchain/ deliverables/ captures/ corpus/ reports/ archive/`
- `research/toolchain/paths.py`：研究区统一路径解析（禁止硬编码相对路径）
- `tests/test_authgen.py` + `tests/fixtures/authgen_vector.json`：算法回归（5 项断言）
- `MIGRATION.md`：目录重构的新旧路径对照表与清理记录
- `docs/architecture.md`：系统架构与模块职责
- `docs/algorithm-auth.md`：`authentication` 算法原理、判定依据、用法与注意事项
- **`research/deliverables/jcy_api.py`：App 级接口客户端**——在 35 接口实测矩阵管线
  （`jcy_client.py`）之上封装业务层（config/频道/列表/详情/搜索/联想/弹幕/评论/播放），
  authentication 签名（磁盘缓存 80s）、POST 信封加密、响应离线解密全自动，
  正常调用直接返回明文 JSON，附 CLI；`play()` 全链自动：播放凭证 → 解析器签名
  （盐/aes_key/解析器地址从 play 响应下发的现役 Lua 现提取，缺省 pzizhsqjjt）→
  playAddr 多清晰度与单 URL 双结构 → 直链 + 按 Lua `custom_head` 规则的请求头。
  实测：暖态播放链 1.3–1.6s，1080P/4K 直链 HTTP 206 可播
- **播放链 V16 收官（`docs/api/video-play.md`）**：`/app/video/play` 参数走 query +
  body `{}` 伪造信封；解析器响应实测出现标准 base64 编码的 AES128-CBC 密文形态
  （明文 JSON / AES 双兜底均已支持）；旧结构单 URL 端点无清晰度分级属片源差异
- **仓库治理**：研究区（约 8.8GB 抓包/镜像/转储）改为白名单入库——仅代码、
  小型样本与文档引用留档进入版本库；移除废弃 `out/` 产物区与失效下载
- **`src/web/`（jcy-web）：Web 前端工作区**——Vite 7 + React 19 + Tailwind 4 +
  shadcn/ui（61 组件）+ ArtPlayer/hls.js；浏览器先行、预留 Tauri v2 打包；
  协议能力经后端桥（FastAPI :8792，规划中）消费，脚手架阶段，应用入口待落码
- `docs/structure-review.md`：结构深度分析与专业规范对照（现状全景、
  业界惯例比对、偏差处置、演进路线）
- 根 `package.json`：新增 `web:dev` / `web:build` / `web:preview` 工作区脚本

### 变更

- **顶层目录分层重构**：`packages/protocol/` → `src/`，`packages/protocol/tests/` → `tests/`，
  `python/requirements*.txt` → `config/`，`apk/` → `assets/apk/`，`out/` → `research/`
- `authgen.py` 重构：纯逻辑迁到 `src/jcy_protocol/auth.py`，
  `authgen.py` 只提供 Unicorn 后端与 CLI；新增 `UnicornESession` 供批量复用
- `scripts/run-tests.mjs`：依次跑三个测试文件，支持 SKIP=77 语义
- `scripts/validate-structure.mjs`：骨架区改为 `assets/ config/ docs/ scripts/ src/ tests/ .github/`，
  产物区改为 `research/ reflutter_work/ tools/`；必需文件与目录清单同步更新
- `pnpm-workspace.yaml`：`packages/*` → `src`
- `.gitignore`：路径同步到新结构，新增 `_trash_*/`
- `docs/api/overview.md`：按实测校正（见下）
- 文档内所有旧路径引用批量迁移

### 修正（旧文档错误）

| 旧说法 | 实测结论 |
|---|---|
| `APPID: com.tudou.tool` | 应为 `4150439554430529` |
| `authentication` 是服务器签发的 X-Token | 客户端本地生成，算法已破解 |
| 用 HTTP 状态码判断成功/失败 | 错误也返回 200，要看 body 是密文还是明文错误 JSON |
| `auth` 绑定路径 / query | 不绑定；同一 auth 可跨 22 个端点 |
| `/app/config/channel`、`/app/config/video` 是 GET | 实际为 POST |

### 修复（结构，2026-10-07）

- `pnpm validate` 8 项失败清零：README 目录树补登 `src/web/` 骨架层级；
  校验器忽略 `.zcode/`（AI 助手工作区）、跳过 `src/web/.registry/`（shadcn 工具元数据）
- `.gitignore` 增补 `.zcode/`
- 文档陈旧路径批量修正：`assets/assets/apk/…` → `assets/apk/base.apk`；
  移除指向已不存在的 `research/auth_samples.json`；
  `blutter_research` → `blutter_out`（10 篇存活文档，CHANGELOG/tags 历史记录保留原貌）

### 移除

- 约 **7.2 GB** 可重建产物（已核验后删除）：`d.tar`、`mdump.tar`、Dart SDK 安装包、
  blutter 构建树、反编译产物（smali/jadx/nores）、早期内存快照、trace 日志
- 约 **3.4 GB** 不可再生的原始采集数据（`mem_dump.bin` / `mem_all.bin` / `mdump/` /
  `dyn5/`）：先隔离到 `_trash_20260930/`，**在算法正确性验证通过后**才清除。
  删除清单（2139 行）归档于 `research/reports/TRASH_PURGED_20260930.txt`

### 验证（2026-09-30 18:40 复跑，全部通过）

```
语料 O[0:32] 全量核验（最小区域集）   485/485 MATCH, 0 失败
端点矩阵                             22/22 HTTP 200 + 加密业务数据
服务端正例 / 阴性对照                 3/3 通过 / 3/3 正确拒绝
tests/test_auth_pure.py               全部通过
tests/test_channels.py                10/10
tests/test_authgen.py                 5/5
scripts/validate-structure.mjs        通过
```

### 计划中

- 把 `E` 的自定义分组密码还原为纯 Python（已确认 CBC / 16B 分组 / AES `xtime` /
  RC4 式 KSA；已证伪标准 AES、SM4、140 组「自定义 S 盒 + 标准轮」）
- HTTP body 随机会话 key 的运行时提取（遗留项，见 `docs/analysis/open-questions.md`）
- `jcy_protocol` 补全 HTTP body 加密发送能力

## [0.1.0] - 2026-09-29

首个完整分析版本。

### 新增

- 逆向文档站 `docs/`：crypto 5 篇、api 5 篇、analysis 4 篇（docsify）
- `research/deliverables/client/gg_client.py`：Python 离线客户端，监控/信令双通道解密经真机验证
- `research/artifacts/blutter_research/`：blutter Dart 结构产物（pp.txt 对象池 2.6 MB、objs.txt、Frida 模板）
- `research/deliverables/demo/index.html`：hls.js 离线播放验证页
- `research/`：分析脚本 104 个（Dart hook、加密层 hook、FFI、认证链路、构建与扫描工具）
- `src/`：`jcy_protocol` 可安装协议库 + 10 项单元测试（含真机向量）
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
