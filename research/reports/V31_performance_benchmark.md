# V31 — 性能基准测试（优化前后对比 + 官方 App 对照）

> 日期：2026-10-08　设备：雷电 14 / Android 14 / x86_64 + Houdini 翻译 arm64
> 被测：`app.video.guoguo`（Capacitor + React + JNI→libcore.so，debug 构建）
> 对照：`com.tudou.tool`（官方 App，Flutter AOT）
> 方法：设备内 `sh` 脚本 + logcat 时间戳解析，3 轮冷启动取均值

---

## 一、结论速览

| 指标 | 优化前 | 优化后 | 变化 |
|------|--------|--------|------|
| **首个业务成功响应（code=20000）** | 6146 ms | **2473 ms** | **−60%** |
| **首屏全量数据就绪** | 7988 ms | **4380 ms** | **−45%** |
| **首帧显示（ActivityTaskManager Displayed）** | — | **1618 ms** | — |
| **`init` 阻塞** | 3000 ms | **2.7 ms** | **−99.9%** |
| **热态单接口端到端** | 98–870 ms（长尾严重） | **~100 ms（p95 0.13 s）** | 长尾消除 |

**与官方 App 对照（同一模拟器、同为冷启动）**

| | 首帧/首屏 | 首个真实数据 |
|---|---|---|
| 官方 App（Flutter） | Displayed MainActivity **+5299 ms** | 无（显示 `404: Not Found`） |
| 我们的 App | Displayed **+1618 ms** | **+2473 ms** |

> 注：官方 App 的 `SplashActivity` 在 +1181 ms 显示，随后 +5299 ms 才显示 `MainActivity`。
> 该 +5.3 s 可能含其启动页的固有停留，不宜直接等同于"渲染耗时"。
> 但官方 App 在本环境下**业务链路是坏的**（404），因此它不是一个干净的"已知良好"基准。

---

## 二、优化内容：去掉 `init` 的 3 秒空等

### 2.1 问题

`INIT_TIMEOUT_MS = 3000` 让 `nativeInit` 在 `g_init()` 返回后再等 3 秒回调。
但实测 **3 轮 × 0 次回调**（累计回调 0 次），Dart 侧 `FFIUtils.init` 本就忽略返回值、
不等待 —— init 是**同步**语义。

代价：`g_call_lock` 被 init 占住 3 秒，而前端首批请求在这之前就已到达。

优化前第 1 轮实测：

```
41.945  前端发出 GET /api/banners/0
41.945 → 44.799   等 g_call_lock（被 init 占着）   = 2854 ms   ← 纯浪费
44.799 → 45.115   native api_encrypt 实际执行       =  316 ms
45.119  call(api_encrypt) ok：3112 ms
```

即 **init 的 3 秒被 1:1 转嫁成首屏延迟**。

### 2.2 改动

`src/app/android/app/src/main/cpp/jcy_core_jni.c`：

```c
#define INIT_TIMEOUT_MS 0     // 0 = 不等待；g_init() 返回即视为会话态就绪
```

`nativeInit` 中 `timeout_ms <= 0` 时跳过 `result_wait()`，并新增日志：

```
init 同步返回：耗时 N ms，本次回调 M 次（累计 K 次）—— 不等待，立即交还调用锁
```

### 2.3 配套加固：「武装位」防止迟到回调污染

不再等待意味着：万一某机型 init **真的**异步回调，其迟到结果会写进
`g_result/g_done`，污染紧随其后的首次 `call`。

新增 `g_armed`：只在 `result_reset()` → `result_take()` 之间为 1。
窗口外的回调**只记日志、不落结果**（回调仍返回合法 JSON `{"code":200}`，
这是 native 侧的要求，不能省）。

```c
int armed = g_armed;
if (armed) { free(g_result); g_result = strdup(result); g_done = 1; signal(g_cond); }
LOGI("callback #%d: … %s", armed ? "" : "（窗口外，已丢弃）");
```

---

## 三、优化后实测

### 3.1 冷启动 3 轮（t0 = `ActivityManager: Start proc`）

| 里程碑 | 第1轮 | 第2轮 | 第3轮 | 均值 |
|--------|-------|-------|-------|------|
| 桥监听 | +1259 | +1093 | +1104 | **+1152** |
| init 完成 | +1728 (5 ms) | +1393 (2 ms) | +1453 (1 ms) | **+1525** |
| 前端首批请求 | +2501 | +1694 | +1795 | **+1997** |
| **首个 code=20000** | +2853 | +2255 | +2310 | **+2473** |
| **首屏全量** | +4760 | +4166 | +4213 | **+4380** |
| Displayed 首帧 | +1891 | +1437 | +1526 | **+1618** |

`init` 从 3000 ms → **1/2/5 ms**。

### 3.2 冷启动各接口端到端耗时

| 接口 | 第1轮 | 第2轮 | 第3轮 |
|------|-------|-------|-------|
| `/app/config` | 1157 ms | 760 ms | 800 ms |
| `/app/banners/0` | 561 ms | 634 ms | 591 ms |
| `/app/channel` | 351 ms | 719 ms | 678 ms |
| `/app/video/list` ×4 | 601–1874 ms | 495–1663 ms | 716–1687 ms |

（4 个 video/list 并发，受 NanoHTTPD 4 请求线程 + native 串行锁约束，
最慢的一条 ~1.7 s）

### 3.3 热态单接口端到端（App 运行中，curl 打本地桥，各 10 次）

| 接口 | min | p50 | max |
|------|-----|-----|-----|
| `/app/config` | 0.0974 | **0.1052** | 0.1165 |
| `/app/banners/0` | 0.0909 | **0.1000** | 0.1282 |
| `/app/channel?top-level=true` | 0.0961 | **0.1086** | 0.1445 |
| `/app/video/list?channel=3` | 0.0896 | **0.0985** | 0.1533 |
| `/app/video/list?channel=26` | 0.0945 | **0.1027** | 0.1096 |

（单位：秒）

**p50 ≈ 100 ms，p95 ≈ 0.13 s，抖动极小。** 这条链路包含：
桥 HTTP → `api_encrypt`(native) → HTTPS 到 `43.145.33.254` → `api_decrypt`(native) → HTTP 响应。

优化前的同一测试有 0.3 / 0.40 / 0.87 s 的长尾尖峰（与 diag 泵、自检争抢
`g_call_lock` 有关），现已消除。

### 3.4 native 层纯耗时（logcat `call 完成`）

| 调用 | 冷态首次 | 热态 |
|------|----------|------|
| `api_encrypt`（88 B 入参） | 302 / 1998 / 316 ms | 4–20 ms |
| `api_decrypt`（3–30 KB 入参） | 27–102 ms | 30–490 ms（随 body 体积近线性） |

`api_encrypt` 的冷态首次开销（~0.3–2 s）来自 libcore 内部 server 的首次建连，
**不可避免**（官方 App 同样要付这份成本）。

---

## 四、残余优化空间（未实施）

| 项 | 预估收益 | 说明 |
|----|----------|------|
| 进程启动 → 桥监听（~1.15 s） | 中 | 主要是 WebView/Chromium 子进程冷启（+0.74 s）+ Capacitor 插件注册 |
| 4 个 `video/list` 并发串行化 | 中 | NanoHTTPD 仅 4 个请求线程 + native 全局锁；可考虑在 native 侧做请求队列或把首屏请求数从 4 降到 1–2 |
| `api_encrypt` 冷态建连（0.3–2 s） | 低 | 可在 init 后立即预热一次，但前端请求到达时机与之重叠，净收益有限 |
| WebView 首帧（+1.6 s） | 低 | Capacitor 架构固有 |

---

## 五、复现方式

```bash
# 设备内脚本（宿主机共享目录 C:\Users\haige\Documents\leidian14\Pictures）
sh /sdcard/Pictures/perf_test.sh      # A: 热态接口耗时 + B: 3 轮冷启动时间线
sh /sdcard/Pictures/perf_hot.sh       # 仅热态（要求 App 已运行）
cat /data/local/tmp/perf_out.txt
```

> ⚠ 注意：`perf_test.sh` 的 A 段要求 App **已在运行**。若刚 `pm install -r` 过，
> App 已被杀，A 段会全部量到「连接被拒绝」（~0.6 ms 的假值）。先 `am start` 再测。
