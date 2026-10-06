# 变更日志

本文件记录本项目的显著变更。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循语义化版本。

## [未发布]

### 新增

- **`authentication` 头算法完全破解**：`CUSTOM_B64( E( CUSTOM_B64( S ) ) )`，
  服务端实测 HTTP 200；交付 `research/deliverables/authgen.py`
  （详见 `docs/algorithm-auth.md`、`research/reports/VERIFICATION.txt` 第四阶段 [G1]–[G8]）
- **`src/jcy_protocol/auth.py`**：算法的**纯逻辑实现**（字母表编解码、输入串构造、
  body 拆分、头拼装）+ `EBackend` 协议；零大文件依赖，可独立测试
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
