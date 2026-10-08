# V30 — libcore `init` 真值获取 + 回调 ABI 纠正（端到端打通）

> 日期：2026-10-08　设备：雷电 14（Android 14 / x86_64 / Houdini 翻译 arm64）
> 结论：**APK 端到端跑通**，`/app/banners`、`/app/config`、`/app/channel`、
> `/app/video/list` 全部 `code=20000`，首页渲染出真实番剧数据。

---

## 一、问题现象

上一版 APK 不闪退，但**数据加载不出来 / 接口请求不成功**，界面永久停在骨架屏。

经两轮定位，实际是**两个独立缺陷叠加**：

| 编号 | 缺陷 | 症状 | 状态 |
|------|------|------|------|
| A | 桥启动顺序错误（load→init→起桥） | React Query 5 次退避重试在 ~11.6 s 内耗尽，桥 t=20 s 才监听 → 永久骨架屏 | 已修 |
| B | `init` 参数错 + 回调 ABI 判反 | `libcore.call()` 永不返回 / 回调触发后进程 SIGABRT | 已修 |

---

## 二、Bug B 根因 1：`init` 的 `tcp` 与 `files_path` 都传错了

### 2.1 获取真值的方法

`libcore.so` 自身字符串全混淆（`strings` 检索 `tcp`/`files_path`/`app_id` 均为 0 命中），
`libcore` 的 BSS 里也没有 JSON 明文指针可循。

最终用**自研进程内存扫描器**直接从官方 App（`com.tudou.tool`，uid 10079）运行内存里
把原文抠出来：

- `research/tools/memfind.c` —— 在目标进程全 `r--/rw-` 区间做字节模式搜索，
  命中后打印命中地址 + 前后 256 B 上下文；
- 交叉编译：`$TC/x86_64-linux-android21-clang -O2 -Wall memfind.c -o memfind`
  （`TC=C:/Android/Sdk/ndk/27.0.12077973/toolchains/llvm/prebuilt/windows-x86_64/bin`）；
- 推送后在 guest 内以 root 执行：
  `/data/local/tmp/bin_memfind $(pidof com.tudou.tool) '"files_path"' 256`

### 2.2 官方 App 的真实 init JSON

```json
{"app_id":"4150439554430529",
 "device_id":"f56b8cc9a0b24a3996efe200e9d93bc8",
 "code_version":"3.0.0.8",
 "app_version":"1.5.8.0",
 "files_path":"/data/user/0/com.tudou.tool/files",
 "tcp":"43.145.33.254:8191"}
```

### 2.3 我们此前传错的两处

| 字段 | 我们旧值 | 官方真值 | 后果 |
|------|----------|----------|------|
| `tcp` | `43.145.33.254:27990` | **`43.145.33.254:8191`** | 27990 是 HTTP **业务 API** 端口（抓包链路里那个）；8191 才是 libcore 内部 server 通道的端口。传错 → libcore 连不上自己的 server → `call` 阻塞 |
| `files_path` | `<dataDir>/app_flutter/files` | **`<dataDir>/files`** | libcore 在该目录读写运行期状态；路径不对 → 内部 server 起不来 |

> **记忆点**：`init.tcp`（8191）与业务 HTTP API（27990）是**两个不同的端口**，
> 别把抓包看到的 27990 填进 init。

---

## 三、Bug B 根因 2：回调参数顺序被静态分析判反了

### 3.1 曾经的错误结论

`libapp.so:0x715af8` 的 Dart 闭包声明是
`NativeFunction<(dynamic, Pointer<Utf8>) => Void>`，
据此**静态推断**为 `cb(ctx, result)` —— x0 = ctx、x1 = result。

按此实现后，`libcore.call()` 首次真正回调时**进程立刻 SIGABRT**：

```
input is not valid Modified UTF-8: illegal continuation byte 0x3
```

原因是把 `ctx` 句柄当字符串交给了 `NewStringUTF`。

### 3.2 真机实证（推翻静态推断）

修复 init 参数后，libcore 首次真正回调，logcat 直接给出答案：

```
callback #1: a0=0x7617e6825400(b64=1,len~96)  a1=0x400020ac8eac(b64=0,len~0)
```

- `a0` = 96 B 纯 base64 字符 → **这才是 result**
- `a1` = libcore BSS 里的固定地址，非 base64 → 不透明句柄

即真签名是 **`cb(result, ctx)`**，与 Dart 侧声明方向相反。

### 3.3 修复策略：不假设顺序

`jcy_callback()` 对两个参数各做一次只读探测（`probe_b64`），
**谁像 base64 谁就是 result**，兼容未来 ABI 变化：

```c
if (b0 && !b1)      { result = a0; which = "x0"; }
else if (b1 && !b0) { result = a1; which = "x1"; }
else if (b0 && b1)  { result = a0; which = "both->x0"; }
```

配套加固（防止再次 abort 整个进程）：

1. `safe_new_string()` —— 转 `jstring` 前逐字节校验，只有纯可打印 ASCII 才原样返回，
   否则退化成空串 + 记日志，让 Kotlin 侧走「解包失败」分支而不是崩进程；
2. 回调 typedef 如实声明为两个 `void*`（静态层面无法定死）；
3. `g_cb_reply` 固定为 `{"code":200}`（`0x190` 是 Smi，真实值 200 而非 400）。

---

## 四、修复后的实测证据

### 4.1 启动链路（logcat，PID 9079）

```
08:53:20.158  [FACT] bridge_port = 8792          ← 桥 20 ms 内监听
08:53:20.159  [FACT] boot_bridge = ok
08:53:20.732  libcore.so 已加载: call=0x400020b07a38 init=0x400020afdc24 (153 ms)
08:53:20.734  init 入参(208 B): {"app_id":"4150439554430529",…,"files_path":"/data/user/0/app.video.guoguo/files","tcp":"43.145.33.254:8191"}
08:53:21.463  GET /api/channel
08:53:21.467  GET /api/banners/0                 ← 前端第一批请求拿到 200
08:53:24.113  callback #1: 取 x0 | a0=…(b64=1,len~96)
08:53:24.114  call 完成：耗时 379 ms，回调结果 896 B     ← 不再挂死
08:53:24.117  call(api_encrypt) ok：明文键 [action, code, payload]
```

### 4.2 全接口业务码

| 接口 | 结果 |
|------|------|
| `GET /app/banners/0` | HTTP 200，5873 B，**code=20000**（2894 ms 冷态） |
| `GET /app/config` | HTTP 200，2905 B，**code=20000**（754 ms） |
| `GET /app/channel?top-level=true` | HTTP 200，3889 B，**code=20000**（3004 ms） |
| `GET /app/video/list?channel=26` | **code=20000**（802 ms） |
| `GET /app/video/list?channel=3` | **code=20000**（411 ms） |
| `GET /app/video/list?channel=1` | **code=20000**（1188 ms） |
| `GET /app/video/list?channel=2` | **code=20000**（1449 ms） |

`selftest_config_code = 20000`，`message = 操作成功!`。

无 SIGABRT、无 `call 超时`、无 `Long monitor contention` 长尾（仅 0.2–0.9 s 的正常排队）。

### 4.3 诊断通道 `/probe`（修复后）

```json
{"loaded":true,"core_ready":true,"per_action_timeout_ms":4000,
 "actions":[
   {"action":"check","ok":true,"ms":41,"result":"{\"code\":200,\"payload\":{\"errCode\":[10032]}}"},
   {"action":"get_version","ok":true,"ms":5,"result":"…{\"version\":51}"},
   {"action":"get_abi","ok":true,"ms":2,"result":"…{\"abi\":\"arm64-v8a\"}"},
   {"action":"api_encrypt","ok":true,"ms":12,"result":"…{\"authentication\":\"WEat8arVE4/F9AmY…\"}"},
   …]}
```

8 个 action 全部毫秒级返回，不再出现此前「首个 `/probe` 被挂死的 `api_encrypt`
钉住 `g_call_lock`，后续 40 次轮询全部 429」的现象。

### 4.4 界面

截图 `research/tmp_device/shot_ok.jpg`：搜索栏、五个分类页签
（推荐/日漫/國漫/動漫電影/其他動漫）、JOJO 横幅轮播、「推荐·日漫」视频卡片
全部渲染出真实数据。

---

## 五、改动清单

| 文件 | 改动 |
|------|------|
| `src/app/android/app/src/main/cpp/jcy_core_jni.c` | 回调 typedef 改 `(void*, void*)`；`jcy_callback()` 双探针自动判序；新增 `safe_new_string()` 非 ASCII 防护；`INIT_TIMEOUT_MS` 20000→3000；新增 `nativeCallTimeout` 导出；文件头注释纠正参数顺序结论 |
| `src/app/android/app/src/main/java/app/video/guoguo/JcyCore.kt` | `DEFAULT_TCP` 27990→**8191**；`init()` 字段集与顺序对齐官方原文；新增 `callRawTimeout()`；`nativeCallTimeout` 外部声明 |
| `src/app/android/app/src/main/java/app/video/guoguo/MainActivity.kt` | `filesPath` 改 `<dataDir>/files`；启动顺序改为**先起桥后 init**；自检 `/app/config` 走 8 s 短超时 |
| `src/app/android/app/src/main/java/app/video/guoguo/JcyBridgeServer.kt` | 新增 `/probe` 路由（8 action、4 s 单项超时、30 s 缓存、并发去重）；`/health` 报 `core_loaded/core_ready/port`；`/debug` 改走短超时 |
| `src/web/src/components/bridge-gate.tsx` | 新增：桥 `/health` 就绪前不挂载路由，消除冷启动空窗 |
| `src/web/src/main.tsx` | React Query 重试策略放宽（`failureCount < 30`，退避封顶 3 s） |

---

## 六、残留 / 未执行

- `check` 返回 `errCode 10032`（未初始化），但 `api_encrypt` 正常工作，
  说明 10032 只影响 `check` 这个自检 action，不影响业务链路。**未深挖**。
- `get_app_info` / `get_host_config` / `get_registries` 返回 `code:404`
  （该 libcore 版本未实现这些 action）。因此 `tcp` 仍需硬编码 8191。
- 引擎侧（`decrypt_e.py` / `jcy_fuse24.dll`）本次未改动，未重跑 `verify_cprop.py`。
