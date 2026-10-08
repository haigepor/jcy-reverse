# 安卓客户端（jcy-app）

> 源码：`src/app/`　工程说明：[`src/app/README.md`](../src/app/README.md)
> 性能基准：`research/reports/V31_performance_benchmark.md`
> `init` 真值取证：`research/reports/V30_init_json_groundtruth.md`

**状态：已端到端跑通（2026-10-08）** —— 首页 / 频道 / 搜索 / 播放全链路可用，
加解密由 `libcore.so` 原生完成，速度与官方 App 同源。

---

## 一、为什么这样做

官方 App 是 **Flutter / Dart AOT**。要在安卓上达到同样的加解密速度，
唯一必要的条件是：**让同一份 `libcore.so` 跑在同一个进程里**。

> **决定解密速度的不是 UI 框架，而是 `libcore.so` 跑在哪。**
> 只要调用同一份 `libcore.so`，native 加解密就是逐字节、同速度的。

因此本项目选择 **复用 `src/web` 的 React 前端**（零重写），
用 **Capacitor 7** 做容器，用 **Kotlin + JNI(C)** 直接 `dlopen` `libcore.so`。
把 Flutter 重写成 Dart 与「复用 React」的目标直接冲突，且对性能毫无收益。

| 层 | 选型 | 理由 |
|---|---|---|
| UI | React 19 + Vite（复用 `src/web`） | 已有完整页面、ArtPlayer/HLS 播放器、61 个 shadcn 组件 |
| 容器 | Capacitor 7 | 标准 Gradle 工程，可直接加 JNI |
| native 桥 | Kotlin + JNI(C) | `dlopen` + `dlsym` 调 `libcore.so` 的 `init` / `call` |
| 网络 | Kotlin + OkHttp | 规避 Android 9+ 明文 HTTP 限制与 WebView CORS |

**为什么安卓上不需要 shim**：`libcore.so` 依赖的 bionic 符号
（`__android_log_print` / `__system_property_get` / `__sF` / `__errno` …）
在安卓系统里原生存在，直接可解析。PC 侧要自己实现整套密码学，
正是因为那里没有 `libcore.so`。

---

## 二、架构与数据流

```
┌─ Android App (app.video.guoguo) ───────────────────────────────────┐
│                                                                     │
│  WebView（页面源 http://localhost）                                 │
│   └─ React 前端（src/web 构建产物，VITE_API_BASE 指向本机桥）        │
│        │  fetch("http://127.0.0.1:8792/api/…")                      │
│        ▼                                                            │
│  Kotlin 层                                                          │
│   ├─ JcyBridgeServer.kt  ← NanoHTTPD 本机桥（127.0.0.1:8792）        │
│   │     路由与 Python 桥完全一致：/api /resolve /stream /health       │
│   │                            /debug /diag /probe                  │
│   ├─ JcyApi.kt           ← 主 API 客户端（信封搬运 + 播放解析）      │
│   ├─ JcyCorePlugin.kt    ← 备用直连通道（Capacitor 插件）            │
│   ├─ JcyCore.kt          ← libcore.so 的 Kotlin 门面                 │
│   ├─ Diag.kt             ← 诊断总线（三条出口）                      │
│   └─ OkHttp              ← 明文 HTTP 请求 / Range 流代理             │
│        │                                                            │
│        │  JNI                                                        │
│        ▼                                                            │
│  C 层（jcy_core_jni.c → libjcy_core.so）                            │
│   └─ libcore.so（6,839,376 B，sha256 26727c7b…，与官方逐字节一致）   │
│        ├─ init(json)             初始化（裸 JSON，**同步**）         │
│        ├─ call(b64, cb)          请求加密 / 响应解密                 │
│        └─ 回调 cb(result, ctx)   返回必须是合法 JSON                 │
└─────────────────────────────────────────────────────────────────────┘
```

**为什么用本机 HTTP 桥而不是纯插件**：前端已按 `/api`、`/resolve`、`/stream`
三个路由写好，本机桥用**同一套路由契约**接管后业务代码一行不改；
且 `/stream` 需要真实 URL 给 ArtPlayer（Range 转发 + UA/Referer 注入），
只有真 HTTP 服务能提供。

---

## 三、JNI 契约（改代码前必读）

### 3.1 `init(json)` —— 裸 JSON，不加密

字段集固定为 6 个，**无 `action` 键**：

```json
{"app_id":"4150439554430529",
 "device_id":"16613a7076284a15bc723d018bcd67e1",
 "code_version":"3.0.0.8",
 "app_version":"1.5.8.0",
 "files_path":"/data/user/0/app.video.guoguo/files",
 "tcp":"43.145.33.254:8191"}
```

两个**曾导致 `call` 永久挂死**的字段：

| 字段 | 错误值 | 正确值 | 说明 |
|---|---|---|---|
| `tcp` | `43.145.33.254:27990` | **`43.145.33.254:8191`** | 27990 是 HTTP **业务 API** 端口；8191 是 libcore **内部 server 通道**端口。传错 → libcore 连不上自己的 server → `call` 永不返回 |
| `files_path` | `<dataDir>/app_flutter/files` | **`<dataDir>/files`** | libcore 在该目录读写运行期状态，路径不对内部 server 起不来 |

真值来源：用自研内存扫描器（`research/tools/memfind.c`）直接读官方 App
`com.tudou.tool` 运行内存里传给 libcore 的原始 JSON。

> **`init` 是同步语义**：`g_init()` 返回即会话态就绪，回调只是可选通知
> （三轮冷启动实测回调 0 次）。因此**不要等待回调**，详见 §四。

### 3.2 `call(b64, cb)` —— AES 包装

入参 = `base64( AES-128-CBC-PKCS7( json ) )`

```
key = "qPwClBj7j7ZQraSm"      iv = "p3JdVQl3q7WQJIgG"
```

这两个密钥**只存在于 `libapp.so`**（Dart 侧），`libcore.so` 里任何字节序都搜不到
—— 说明 AES 包装是 Dart 做的，native 负责解开。安卓侧由 Kotlin 复刻这一步。

已知 action：`check` / `clear_key` / `get_app_info` / `get_host_config` /
`get_record` / `get_version` / `get_abi` / `api_encrypt` / `api_decrypt` /
`get_registries`。

**`api_encrypt` 是每个请求的前置**：它的返回值里同时带着请求头
（`ts` / `authentication` / `x-version` / `tcs` / `nonce`）与加密后的 body，
所以客户端不需要单独实现 `authentication` 算法。即便是 GET 也要先过它。

### 3.3 回调 ABI —— 两个反直觉点

```c
const char *cb(const char *result, void *ctx);
```

**① 参数顺序是 `(result, ctx)`，不是 `(ctx, result)`。**

Dart 侧闭包声明为 `NativeFunction<(dynamic, Pointer<Utf8>) => Void>`，
静态看上去像 `(ctx, result)` —— 据此实现会让真机**立刻 SIGABRT**：

```
input is not valid Modified UTF-8: illegal continuation byte 0x3
```

真机 logcat 实证：

```
callback #1: a0=0x7617e6825400(b64=1,len~96)  a1=0x400020ac8eac(b64=0,len~0)
```

`a0` 是 96 B 纯 base64（**载荷**），`a1` 是 libcore BSS 里的固定句柄地址。

**现行实现不假设顺序**：`jcy_callback()` 对两个参数各做一次只读探测
（`probe_b64`，判断是否纯 base64 字符集），**谁像 base64 谁就是 result**，
以兼容未来 ABI 变化。

**② 返回值必须是明文 JSON。**

Dart 侧 `dartCallback` 收尾是 `jsonEncode({"code":200})` → `toNativeUtf8` → ret。
返回野指针会直接打崩 native。注意 `0x190` 是压缩指针模式的 Smi，
真实值 = `imm>>1` = **200**（早期写成 400 是错的）。

**③ 转 `jstring` 前必须校验 ASCII。**

`NewStringUTF` 收到非法 Modified UTF-8 会 `SIGABRT` 整个进程。
`safe_new_string()` 逐字节校验，非纯可打印 ASCII 就退化成空串 + 记日志，
让 Kotlin 侧走「解包失败」分支，而不是崩进程。

### 3.4 其它两条硬约束

- **`init` 的 JSON 缓冲必须长期有效**：init 入口 thunk 第一条就是
  `str x0, [全局]`，把入参指针存进全局。C 侧 `strdup` 到堆上且永不释放。
- **回调 typedef 必须声明为 `(void*, void*)`**：clang 会对不兼容函数指针报 error。

---

## 四、启动顺序与性能

`MainActivity.startBridge()` 在**同一个后台线程**里按此顺序执行：

```
① 起 HTTP 桥（NanoHTTPD，127.0.0.1:8792）   ~50 ms
② JcyCore.load()   dlopen libcore.so        ~100–180 ms
③ JcyCore.init()   裸 JSON，**不等待回调**   ~1–5 ms
④ 自检 GET /app/config（8 s 短超时）
```

### 4.1 桥必须排在 init 前面

WebView 在 `onCreate` 后就挂载，React Query 立刻发首批 `/api` 请求。
旧顺序（load → init → 起桥）下桥要等 init 结束才监听，那段时间全部
`ECONNREFUSED`；React Query 的 5 次指数退避重试（0.8+1.6+3.2+6.0 s ≈ 11.6 s）
耗尽后**界面永久停在骨架屏且不再自愈**。

现在桥在 ~1.15 s 内监听，前端第一批请求就能拿到 200。

### 4.2 init 不等待回调

init 是同步语义，等待纯属浪费。实测代价（优化前）：

```
41.945  前端发出 GET /api/banners/0
41.945 → 44.799   等 g_call_lock（被 init 占着）  = 2854 ms   ← 纯浪费
44.799 → 45.115   native api_encrypt 实际执行      =  316 ms
45.119  call(api_encrypt) ok：3112 ms
```

即 **init 的 3 秒被 1:1 转嫁成首屏延迟**。

**配套加固**：`g_armed` 武装位（只在 `result_reset()` → `result_take()` 之间为 1）。
窗口外的迟到回调只记日志、不落结果，防止污染紧随其后的首次 `call`。

### 4.3 性能基准

| 指标 | 数值 |
|---|---|
| 冷启动 → 首帧显示 | **+1.62 s** |
| 冷启动 → 首个业务响应（`code=20000`） | **+2.47 s** |
| 冷启动 → 首屏全量数据（8 接口） | **+4.38 s** |
| 热态单接口端到端 | **p50 ≈ 100 ms / p95 ≈ 130 ms** |

优化前后（去掉 init 空等）：

| 指标 | 优化前 | 优化后 | 变化 |
|---|---|---|---|
| `init` 阻塞 | 3000 ms | **2.7 ms** | **−99.9%** |
| 首个 `code=20000` | +6146 ms | **+2473 ms** | **−60%** |
| 首屏全量 | +7988 ms | **+4380 ms** | **−45%** |
| 热态长尾 | 0.3–0.87 s 尖峰 | p95 0.13 s | 消除 |

热态单接口 p50 ≈ 100 ms 这条链路包含：
桥 HTTP → `api_encrypt`(native) → HTTPS 到 `43.145.33.254` → `api_decrypt`(native) → HTTP 响应。

---

## 五、本机桥路由

与 `src/web/server/main.py` **行为等价**，否则会出现「浏览器正常、装机后白屏」。

| 路由 | 说明 |
|---|---|
| `GET\|POST /api/<path>` | `/app/` 前缀 + query 透传；GET 缓存 30 s，`config/channel/banners/sign_rule/vip_price` 300 s |
| `POST /resolve` | 播放解析；缓存 60 s；命中时续直链白名单 TTL |
| `GET\|HEAD /stream` | Range 转发；**仅 HEAD** 注入 `bytes=0-0`；UA/Referer 注入；域名白名单 |
| `GET /health` | `{ok, bridge, core_loaded, core_ready, port}` —— 前端 `BridgeGate` 靠它决定何时挂载路由 |
| `GET /debug` | 全量诊断（走 3 s 短超时，不阻塞请求线程池） |
| `GET /diag` | 诊断总线快照 |
| `GET /probe` | 逐 action 探测（8 个 action、单项 4 s 超时、30 s 缓存、并发去重） |

> **NanoHTTPD 只有 ~4 个请求线程**。一次挂死的 native 调用会钉住
> `g_call_lock` 并耗干线程池 —— 所以所有诊断路径都必须走短超时。

直链白名单：`zshtys888.com` / `xajtl.com` + resolve 动态登记（6 h，cap 512）。

---

## 六、构建与自检

```bash
# 1) 提取 libcore.so（从原版 APK，只需一次）
bash src/app/scripts/extract_so.sh

# 2) 构建 React 前端 → src/app/www
bash src/app/scripts/build_web.sh

# 3) 同步到安卓工程（NODE_OPTIONS= 用于绕开沙箱的 safe-delete 钩子）
cd src/app && NODE_OPTIONS= npx cap sync android

# 4) 编译 APK
cd src/app/android && NODE_OPTIONS= ./gradlew assembleDebug
# 产物：src/app/android/app/build/outputs/apk/debug/app-debug.apk
```

**装机自检**（雷电 14 实测命令）：

```bash
# 看启动链路
./ld.exe "logcat -d | grep -aE 'JcyCore|JcyBridge|code=20000'"
# 桥健康
curl -s http://127.0.0.1:8792/health
# 逐 action 探测
curl -s -m 40 http://127.0.0.1:8792/probe
# 端到端
curl -s "http://127.0.0.1:8792/api/config"
```

> ⚠ 测热态接口耗时前**必须先 `am start`**：`pm install -r` 会杀掉 App，
> 此时 curl 全量到「连接被拒绝」（~0.6 ms 假值），看着像"快了 100 倍"。

---

## 七、已知限制

| 项 | 现状 | 影响 |
|---|---|---|
| `check` 返回 `errCode 10032` | libcore 该版本语义 | 不影响业务（`api_encrypt` 正常） |
| `get_app_info` / `get_host_config` / `get_registries` 返回 `code:404` | 该版本 libcore 未实现 | `tcp` 只能硬编码 8191，无法运行时动态获取 |
| `init` 的 `tcp` 写死 | `JcyCore.DEFAULT_TCP` | 服务端换 IP/端口需改代码重编 |
| 4 个 `video/list` 并发串行化 | NanoHTTPD 4 线程 + native 全局锁 | 首屏最慢一条 ~1.7 s；可考虑降首屏请求数 |
| `api_encrypt` 冷态首次 0.3–2 s | libcore 内部 server 首次建连 | 不可避免（官方 App 同样要付这份成本） |

---

## 八、相关文档

- [`src/app/README.md`](../src/app/README.md) —— 工程说明、目录结构、构建步骤
- [`frontend.md`](frontend.md) —— Web 前端架构与播放器设计
- [`structure.md`](structure.md) —— 目录职责与数据流
- [`crypto/http-body.md`](crypto/http-body.md) —— HTTP body 加密结构（RSA-2048 + AES）
- [`algorithm-auth.md`](algorithm-auth.md) —— `authentication` 头算法（Python 侧参考实现）
- `research/reports/V30_init_json_groundtruth.md` —— `init` 真值取证与回调 ABI 纠正
- `research/reports/V31_performance_benchmark.md` —— 性能基准与复现脚本
