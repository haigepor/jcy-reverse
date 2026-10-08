# decompiler-explorer 项目分析 + `libcore.so`「模拟结果」核查

> 分析时间：2026-10-08
> 仓库：https://github.com/decompiler-explorer/decompiler-explorer （MIT，公开实例 dogbolt.org）
> 本地源码：`research/tools/de-comp/`（经 codeload 下载 master 分支 tar.gz，3.47 MB）
> 核查对象：用户提供的 `libcore.so` 模拟分析结果

---

## 第一部分：`libcore.so` 模拟结果核查（**存在问题，先看这个**）

### 1.1 逐字段核对

实测数据来自 `research/artifacts/libcore.so`（直接解析 ELF，非推测）。

| 报告字段 | 报告值 | 实测值 | 判定 |
|---|---|---|---|
| 文件大小 | 6679.08 KB | 6839376 B = **6679.08 KB** | ✅ 正确 |
| MIME 类型 | application/octet-stream | ELF64/AArch64，按 MIME 规则即 octet-stream | ✅ 正确（但无信息量） |
| 导出符号 | `JNI_OnLoad` | **libcore.so 中不存在**（`JNI_OnLoad` 在 `libloader.so` @ `0x2a6210`） | ❌ **错误** |
| 导出符号 | `Java_com_example_decrypt` | **全部 7 个 native 库中均不存在**；libcore.so 的 `Java_*` 符号数 = **0** | ❌ **错误** |
| 检测到加密 | OLLVM 控制流平坦化 | 与项目既有结论一致（OLLVM） | ✅ 正确 |
| 依赖库 | `liblog.so`, `libandroid.so` | 实测 `DT_NEEDED` = `libz.so`, `liblog.so`, `libm.so`, `libdl.so`, `libc.so` | ⚠️ **部分错误**（无 `libandroid.so`；漏 4 个） |

### 1.2 结论

**这份「模拟结果」的「导出符号」与「依赖库」两项不可信，属于模板化 / 推测性输出。**

- 文件大小正确是因为它只是读了一下文件长度；MIME 是通用兜底值；OLLVM 是这类工具的常见套话（虽然本例恰好命中）。
- 真正需要解析 ELF 结构才能得出的两项（符号表、`.dynamic`）**都错了**。

### 1.3 错误来源推测（假设，非结论）

libcore.so **静态链接了完整 BoringSSL**，符号表里有 **42 个含 `decrypt` 的符号**：

```
EVP_PKEY_decrypt, EVP_DecryptInit, EVP_DecryptUpdate, EVP_DecryptFinal(_ex),
AES_decrypt, AES_set_decrypt_key, vpaes_decrypt, aes_v8_decrypt,
RSA_private_decrypt, RSA_public_decrypt, SM4_decrypt, SEED_decrypt, ARIA/CAST/Camellia/BF/RC2/DES_decrypt3,
CRYPTO_gcm128_decrypt, CRYPTO_ccm128_decrypt, CRYPTO_cbc128_decrypt, CRYPTO_ocb128_decrypt, ...
```

一个「看到 `decrypt` 关键字就猜」的分析器，很可能据此编造出一个 JNI 导出名。而 `Java_com_example_decrypt` 里的 **`com.example` 正是 Android 教程的标准包名** —— 这是典型的幻觉特征（真实 App 的包名是 `app.video.guoguo`）。

### 1.4 本项目两个 native 库的真实画像（供后续使用）

| 项目 | `libcore.so` | `libloader.so` |
|---|---|---|
| 大小 | 6,839,376 B（6679.08 KB） | 6,221,896 B（6076.07 KB） |
| 格式 | ELF64 / AArch64 | ELF64 / AArch64 |
| 节表 | 27 节，`.dynsym` 277,776 B | — |
| 唯一符号 / 已定义函数 | 11574 / **9878** | 8402 / 7011 |
| 未定义导入 | 240 | — |
| `JNI_OnLoad` | **无** | `0x2a6210`（size 88） |
| `call` | `0x307a38`（size **32384**） | `0x2a3bac`（size 5552） |
| `init` | `0x2fdc24`（size 116） | 无 |
| `reload` | 无 | `0x2a5d04`（size 1216） |
| `Java_*` | **0 个** | 2 个 |
| `DT_NEEDED` | libz, liblog, libm, libdl, libc | 同上 |
| PT_LOAD / PT_DYNAMIC | 3 / 1 | — |

`libloader.so` 的 2 个 JNI 导出：

```
Java_app_video_guoguo_GApplication_init          0x2a6268  size 356
Java_app_video_guoguo_SplashActivity_load        0x2a1f40  size 1088
```

**这解释了架构分工**：JNI 入口全部在 `libloader.so`（加载器 / 热更新 `reload`），
`libcore.so` 是**纯算法内核**，通过 Dart FFI 的 `call` 导出被调用 ——
所以它**本来就不该有 `Java_*` 导出**。这也反向印证了报告的错误。

> 更正：此前记录 `init` 为 `0x2fd7e4`，实测应为 **`0x2fdc24`**。

---

## 第二部分：decompiler-explorer 项目分析

### 2.1 它是什么

- **dogbolt.org 的开源实现**，官方定位一句话：*"the same thing as Compiler Explorer, but in reverse"*。
- 输入一个可执行文件 → 并行跑 **13 个反编译器** → 浏览器里并排对比输出。
- 定位是**「反编译器效果对比平台」**，**不是脱壳 / 解密 / 加固分析工具**。

### 2.2 技术架构

```
                    ┌──────────────┐
  浏览器 ──────────▶│  traefik v3.6│ (80/443, ACME, 请求体限流)
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐    ┌────────────┐
                    │ explorer     │───▶│ postgres14 │
                    │ Django 4.2   │    └────────────┘
                    │ gunicorn ×4  │───▶┌────────────┐
                    └──────┬───────┘    │ memcached  │
                           │            └────────────┘
        POST /api/decompilation_requests/claim/   ▲
                           │                      │ X-AUTH-TOKEN
        ┌──────────────────┴──────────────────────┴───┐
        │  runner 容器 × 13（各自一个反编译器）        │
        │  runner_generic.py: 注册/心跳/领任务/超时    │
        │  二进制经 stdin 管道送入，非文件参数          │
        └─────────────────────────────────────────────┘
```

关键实现点（读源码得出）：

- **分布式任务队列**：runner 主动轮询领任务，不是 explorer 推。好处是可水平扩展（`--replicas N`）。
- **通用 runner 外壳** `runners/decompiler/runner_generic.py`（247 行）：
  - 注册：先按 `(name, version, revision, url)` 找已有实例，找不到才注册
  - 心跳：独立线程每 10 s 打 `/health_check/`
  - 隔离：每个任务用 `tempfile.TemporaryDirectory()`，`preexec_fn` 设 `RLIMIT_AS`
  - 超时：`timeout -s 9`（SIGKILL）+ Python 侧 `subprocess.run(timeout=)`
  - 重试：指数退避，上限 30 s
- **每个反编译器一个 `decompile_<name>.py`**，强制实现 3 个查询参数：`--name` / `--url` / `--version`
  （`runner_generic` 启动时用 `subprocess.check_output` 调它们拿元信息）
- **二进制走 stdin**：`bash -c "set -o monitor ; <script> < /dev/stdin"` —— 便于沙箱化，避免路径注入
- 前端是 **Django 模板**（`templates/explorer`：index / faq / queue）+ 静态资源，非 SPA
- 构建编排：`scripts/dce.py`（`init` / `build` / `start` / `stop`，支持 `--with-<x>` / `--without-<x>` 选反编译器）

### 2.3 支持的 13 个反编译器

| 反编译器 | 版本 | 获取方式 | 需私有 license | ARM64 支持 |
|---|---|---|---|---|
| **Hex-Rays** | IDA 7.7 | 私有 | ✅ 需 IDA + EULA + `efd64` | ✅ 最强 |
| **Binary Ninja** | 6.0.10601 | 私有 | ✅ 需 `license.dat` | ✅ 强 |
| **Ghidra** | 12.1.2 | 公开 wget | ❌ | ✅ 强 |
| **angr** | 10.0.1.post1 | 公开 pip | ❌ | ✅ 支持 |
| **rev.ng** | master（滚动） | 公开 install.sh | ❌ | ✅（QEMU 系，含 ARM64） |
| **RetDec** | v5.0 | 公开 | ❌ | ⚠️ 弱 |
| **Relyze** | 滚动 | 私有（Wine + innoextract） | ✅ | ⚠️ 部分 |
| **Dewolf** | v2026-04-01 | 公开 git | ❌ | ⚠️ 主要 x86 |
| **Kuna** | 滚动 | 公开（Rust 构建） | ❌ | ⚠️ 研究型 |
| **Reko** | 0.12.4 | 公开（需 .NET 9 SDK + 8 Runtime） | ❌ | ⚠️ 主要 x86 |
| **Boomerang** | v0.5.2 | 公开 | ❌ | ⚠️ 主要 x86 |
| **RecStudio** | 滚动 | 公开（需 i386 32 位库） | ❌ | ⚠️ 主要 x86 |
| **Snowman** | 滚动 | 公开（cmake 构建） | ❌ | ⚠️ 主要 x86 |

> runner 镜像统一 `--platform=linux/amd64`。**架构支持完全取决于反编译器自身**，DCE 不做任何转换。

### 2.4 部署与运行

```bash
# 前置：python>=3.8, pipenv, docker, docker-compose
pipenv install
python scripts/dce.py init                       # 生成 secrets / 目录
python scripts/dce.py build                      # 只构建有 license 的反编译器
python scripts/dce.py --without-reko build       # 排除某个
python scripts/dce.py start                      # dev，UI 在 80/443

# 生产
python scripts/dce.py start --prod --replicas 2 --acme-email=you@example.com
# 生产 + S3 存储
python scripts/dce.py start --prod --s3 --s3-bucket=X --s3-endpoint=Y --s3-region=Z

# 只起前端（不含任何反编译器）
pipenv run python manage.py migrate
pipenv run python manage.py runserver 0.0.0.0:8000

# 单独起一个反编译器容器
export EXPLORER_URL=http://172.17.0.1:8000
docker-compose up binja --build --force-recreate --remove-orphans
```

### 2.5 关键限制

| 限制 | 值（源码实测） | 对本项目的影响 |
|---|---|---|
| **上传大小** | traefik `maxRequestBodyBytes=${MAX_REQUEST_SIZE:-**2000000**}`（2 MB） | **libcore.so 6.8 MB 直接超限**，必须调大 `MAX_REQUEST_SIZE` |
| 单文件超时 | `DECOMPILER_TIMEOUT=120` s，featured 样本 `900` s | 6.8 MB × OLLVM 必然超时 |
| 内存限额 | `DECOMPILER_MEM_LIMIT_HARD=10 GB` | 尚可 |
| 设计目标 | README 明言 *"compare ... on **small executables**"* | 不适配大 SO |
| 反编译粒度 | **整个二进制**，无法指定函数 | 我们要的是少数几个函数 |
| 部署成本 | Docker + Postgres + memcached + traefik + 13 个镜像 | 高；多数反编译器还需私有 license |

### 2.6 对本项目（囧次元）的适用性判定

**直接部署使用：不推荐。** 三条硬理由：

1. **体积 / 超时**：6.8 MB OLLVM 二进制喂给 13 个反编译器，大多数会超时或 OOM；默认 2 MB 上传限制直接拦住。
2. **粒度不匹配**：我们需要的是 `E` 密码核心（`0x2cd8b0` 一带）、`init`（`0x2fdc24`）、`call`（`0x307a38`）等**少数函数**，而 DCE 只能整文件。
3. **OLLVM 是这类反编译器的共同克星**：把同一份控制流平坦化的代码喂给 13 个工具，得到 13 份都难读的伪代码，横向对比的边际收益很低。相比之下，项目现有的 **C 转译引擎（V24，ARM64→C 1:1 复刻）+ Unicorn 模拟** 路线对 OLLVM 的适配度更高。

**真正值得复用的三样东西**：

1. **无头调用范式**（最高价值）——
   - `decompile_ghidra.py`：`analyzeHeadless <proj> temp -import <bin> -postScript DecompilerExplorer.java <out>`，并手动注入 JDK 到 `PATH`
   - `decompile_hexrays.py`：`idat -A -a -S<batch.py> -L<log> <bin>`，配合 `efd64`
   - `decompile_angr.py` / `decompile_retdec.py` / `decompile_revnng.py` 同理
   这些是「如何在 CI/无头环境批量驱动反编译器」的现成答案，可直接照搬到本项目的工具链里。

2. **函数级切片 + 横向对比的思路** ——
   把 `libcore.so` 的目标函数按 `st_value`/`st_size` 切成小块（例如 `0x2cd8b0` 约 1.5 KB），
   转成裸 ARM64 blob 再喂给 Ghidra / angr / rev.ng。这样**同时绕过体积限制与超时限制**，
   还能拿到多份伪代码互相印证 OLLVM 平坦化后的真实语义。

3. **`runner_generic.py` 的工程模式** ——
   超时（`timeout -s 9`）/ 内存限额（`RLIMIT_AS`）/ 临时目录隔离 / stdin 管道 /
   指数退避重试，是一套很好的「批量处理不可信二进制」沙箱模板。

### 2.7 推荐落地做法

不部署整个 DCE，而是取其方法论：

1. 按 §2.6-2 从 `libcore.so` 提取目标函数切片（用项目现有 ELF 解析代码即可，`st_value` / `st_size` 都有）
2. 本地装 Ghidra headless（公开、免费、ARM64 支持好），照 `decompile_ghidra.py` 的写法驱动
3. 若要横向对比，参考 `decompile_*.py` 的 `--name/--url/--version` 约定写一个轻量批量脚本
4. 对比结果与项目已有的 C 转译引擎（V24）逐位验证结论交叉核对

---

## 第三部分：未执行项 / 证据缺口

| 项 | 状态 | 说明 |
|---|---|---|
| 实际部署 decompiler-explorer | **未执行** | 需 Docker + Postgres + memcached + traefik + 13 个镜像；且 Hex-Rays / Binary Ninja / Relyze 需私有 license |
| 在 dogbolt.org 上实测上传 libcore.so | **未执行** | 需浏览器交互；且公开实例的 `MAX_REQUEST_SIZE` 未知 |
| 验证 rev.ng / Kuna 对 ARM64 + OLLVM 的实际效果 | **未执行** | 仅依据 Dockerfile 与官方文档推断 |
| 「报告错误来源」的归因 | **假设** | §1.3 是合理推断，非已验证结论 |
| `libcore2.so` / `libcore_runtime.so` 与 `libcore.so` 的差异 | **未展开** | 三个库符号规模接近，疑似同源不同版本（热更新产物），本轮未比对 |
