# V28 — Capacitor 壳 JNI 崩溃定案（`nlohmann::json parse_error.101`）

> 触发：真机（Redmi/diting, Android 15）运行 Capacitor 壳时进程 `abort`，
> tombstone 显示 `terminating due to uncaught exception of type
> nlohmann::json_abi_v3_12_0::detail::parse_error:
> [json.exception.parse_error.101] parse error at line 1, column 1:
> syntax error while parsing value - invalid literal; last read: '<U+0002>'`
> libcore.so BuildId `d79879632ff25f33d3b4c4fc012e5d25666986bd`。

---

## 0. 一句话结论

**崩溃点不在密码学、不在协议、也不在 Dart 层**：是我们自己写的 JNI 桥
`src/app/android/app/src/main/cpp/jcy_core_jni.c` **把 native 回调的参数顺序写反了**，
于是把一个 **C++ 对象指针**当成 JSON 字符串回传给 `libcore.so`；
libcore 拿它去 `nlohmann::json::parse()`，读到对象头字节 `0x02` 而非 `{`，
抛 `parse_error.101`；该 C++ 异常跨越 JNI 边界无人捕获 →
`std::terminate` → `abort()`。

同一份桥里还并存另外三处缺陷（详见 §4），本轮一并修正。

---

## 1. 判据：`<U+0002>` 意味着输入不是 JSON

`nlohmann` 的 `get_token_string()` 对不可打印字节输出 `<U+XXXX>`。
`last read: '<U+0002>'` + `line 1, column 1` 唯一含义是：

> **交给 `json::parse()` 的那段内存，第 0 个字节是 `0x02`。**

任何以 `{`（0x7B）开头的字符串都不可能产生这条消息。
所以问题一定是「**某处把二进制/指针当字符串传给了 JSON 解析器**」，
而不是「JSON 内容写错了」。

---

## 2. 崩溃帧归属（本地二进制与 tombstone 逐位同一）

本地 `research/artifacts/libcore.so` sha256 `26727c7b68308d3055860a71aa0c217380319ba22bc99cfb425c12e3d4e84f17`，
6839376 B，BuildId 与 tombstone 一致 → 可直接静态定位。

用 `llvm-readelf --dyn-syms` 取 9878 条导出 FUNC，对每个崩溃 PC 求「最近前置符号」：

| tombstone PC | 最近符号 | 偏移 |
|---|---|---|
| `0x328b80` | `call` @0x307a38 | +0x21148 ← **`__cxa_throw` 的直接调用点** |
| `0x327f10` | `call` | +0x204d8 |
| `0x31e6c4` | `call` | +0x16c8c |
| `0x2ff780` | `init` @0x2fdc24 | +0x1b5c |
| `0x2fed08` | `init` | +0x10e4 |
| `0x2ffb74` | `init` | +0x1f50 |
| `0x2fe5f0` | `init` | +0x9cc ← **最外层 libcore 帧** |
| `0x60ccac` | `__cxa_throw` @0x60cc2c | +0x80 |
| `0x5f3a18 / 0x5f3b5c / 0x5f4268` | libc++abi 的 terminate/typeid 族 | — |

说明：`init`(0x2fdc24) 与 `call`(0x307a38) 之间 **40468 B 没有任何导出符号**，
这一段是大量**静态函数**，符号化时会被归到 `init` 名下。
但反向检查确认这不是「随便归的」：

* `init` @0x2fdc24 只有 **116 B**，是一个 OLLVM thunk（见 §3.1）；
* `call` 函数体里确实有对 init 区静态函数的调用（`bl 0x2fe114` / `bl 0x2ff9a8`），
  所以「init 区」既是 init 的实现、也被 call 复用。

⇒ 崩溃**入口**在 init 区，**抛出点**在 call 区的共享 helper 里。
两条路径（init / call）都必须修，见 §4。

---

## 3. Dart 侧取证（`libapp.so`，从 `assets/apk/base.apk` 提取）

`libapp.so` 12321696 B，`.text` @0x4a0000，blutter 给出的地址即文件偏移，
可用 `llvm-objdump -D --section=.text` 直接反汇编
（注意：不加 `-D` 时 llvm-objdump 只输出字节列，不出助记符）。

### 3.1 `init` 是 OLLVM thunk，且**保存入参指针**

```
2fdc24: stp  x29, x30, [sp, #-0x20]!
2fdc30: mov  x8, #0xccd0 ; movk x8,#0x8f1c,lsl16 ; ...   // 拼 64 位偏移
2fdc34: adrp x19, 0x67c000 ; add x19, x19, #0x7b8
2fdc50: ldr  x9, [x19]
2fdc5c: str  x0, [x9, x8]        // ★ 把入参指针写进全局
2fdc6c: blr  x8                  // 进入真实实现
2fdc94: br   x0                  // 尾调用
```

**`str x0, [全局]` 是关键**：native **持有**这个指针，不保证在本次调用内用完。

### 3.2 `init` 传的是**裸 JSON**，没有 AES

`FFIUtils.init` @0x747600。反查其引用的对象池条目（`blutter_out/pp.txt`）：

| 池偏移 | 内容 | 用途 |
|---|---|---|
| `pp+0x380` | `Obj!Utf8Encoder` | utf8 编码 |
| `pp+0x7140` | `Obj!MallocAllocator` | **malloc** 分配 native 缓冲 |
| `pp+0xb10` | `Obj!JsonCodec` | `json.encode` |
| `pp+0xcf8` | `TypeArguments: <String, dynamic>` | Map 字面量 |

收尾序列（0x7478c8–0x7478e8）为
`jsonEncode(map)` → `0x6eefb4`（= `utf8.encode` + `MallocAllocator.allocate(len+1)` + 拷贝，
即 `toNativeUtf8()`）→ `blr`。

**全程没有 `Encrypter` / `AESMode`。** 所以「init 传裸 JSON」的判断是对的。

### 3.3 `init` 的 Map 键（精确）

`pp+0xb6e0` `"app_id"`、`pp+0xc960` `"tcp"`、`pp+0xc970` `"device_id"`、
`pp+0xc978` `"files_path"`、`pp+0x8fd0` `"code_version"`、`pp+0x6fc0` `"app_version"`。
**没有 `action` 键**（init 不是 call 的 action）。

### 3.4 AES 密钥只在 `libapp.so`，`libcore.so` 里没有

```
libapp.so  : qPwClBj7j7ZQraSm @0x114405   p3JdVQl3q7WQJIgG @0x126c56
             kFGTbLlOzFHQCIKp @0x4733f    F3q22XoM8l6T2Ydc @0xf9221
libcore.so : 全部 NOT FOUND（原序 / u64 小端 / u32 小端 均无）
```

⇒ AES-CBC 包装是 **Dart 侧**做的（`call` 路径），native 只负责解。
另外 `api_encrypt` / `api_decrypt` / `clear_key` / `app_id` / `device_id` / `files_path`
等**动作串与字段名在 `libcore.so` 里同样不存在**（字符串被混淆），
但 `nlohmann` 的 typeinfo 名（`8nlohmann` / `parse_error` / `json_abi_v3_12_0`）
存在于 `0x1e1d96` 附近，与自研 base64 字母表 `0x1e1c74` 同区。

### 3.5 回调签名：`(ctx, result)` —— **我们的顺序写反了**

`dartCallback` @0x715844（0x144 B）里：

```
715874: ldr  x2, [x2, #0x838]   // pp+0x1b838 = "qPwClBj7j7ZQraSm"  ← AES key
71587c: bl   0x715210           // 造 Key 对象
71588c: ldr  x2, [x2, #0x840]   // pp+0x1b840 = "p3JdVQl3q7WQJIgG"  ← AES iv
715894: bl   0x715210           // 造 IV 对象
7158a4: ldr  x3, [x27, #0x7010] // Obj!AESMode
7158d4: bl   0x715988           // ★ 解密
7158f4: bl   0x4f8680           // jsonDecode
...
71593c: ldr x16, [x16, #0x88]   // pp+0x9088 = "code"
715948: mov x16, #0x190         // 400
715958: bl   0x4b8bd4           // Map 字面量 → {"code":400}
715968: bl   0xa29e10           // jsonEncode
715970: bl   0x6eefb4           // String → Pointer<Utf8>（malloc）
715974: ret                     // ★ 返回值是给 native 的 JSON 串
```

⇒ 回调契约：**入参 = `base64(AES(json))`，返回值 = 明文 JSON 串**。

参数顺序由 `0x715af8`（dartCallback 调用的第一个 helper）**开头第一条指令**钉死：

```
715af8: stp  x29, x30, [x15, #-0x10]!
715b04: mov  x0, x1              // ★ 把**第二个**参数当主体
715b08: stur x1, [x29, #-0x8]
715b1c: bl   0x715bfc            // 转 Dart String
715b24: ldur x30, [x29, #-0x8]   // = 原 x1
715b30: bl   0x4f441c            // utf8 解码（Pointer<Utf8> → Uint8List）
```

**Dart 只用 x1 当 `Pointer<Utf8>`。** 而我们的桥声明成
`const char *(*)(const char *result, void *ctx)` —— 把 x0 当字符串、x1 当 ctx，
**正好反了**。

---

## 4. 缺陷清单与修正

| # | 等级 | 缺陷 | 修正 |
|---|---|---|---|
| 1 | **P0** | 回调签名 `(result, ctx)` 应为 `(ctx, result)` | `typedef const char *(*jcy_cb_fn)(void *ctx, const char *result);` |
| 2 | **P0** | 回调返回入参指针；native 会把它当 JSON 解析 → `parse_error.101` → abort | 固定返回 `{"code":400}`（与 Dart `dartCallback` 同位置完全一致） |
| 3 | **P0** | `init` 用 `GetStringUTFChars` + `ReleaseStringUTFChars`，缓冲在 `g_init` 返回后失效；而 native 把该指针存进全局、Dart 侧也 malloc-不-free | `strdup` 到堆上并保留到进程结束；`nativeUnload` 也**不释放** |
| 4 | P1 | `JcyCore.init()` 里 `appId ?: resolveAppId()` 会先发一次 native `call`，顺序颠倒（native 会话态由 init 建立） | 直接取 `APPID_HEADER`；`resolveAppId()` 仅留作 init 之后使用 |
| 5 | P1 | `init` 只传 1 个参数；Dart 侧 `FFIUtils.init` 在 FFI 调用前压了 `[jsonPtr, closure(#ffiClosure2)]` | `init` 一律多传回调（AAPCS64 下多余参数被忽略，少传则可能被当野指针调用） |
| 6 | P1 | `call` 的入参 JNI 缓冲同样随调用结束失效 | 同样 `strdup` 到堆上再传 |
| 7 | P2 | 崩溃现场无任何日志，只能靠 tombstone 猜 | 回调与 call/init 全程加 logcat（tag `JcyCore`），打印回调次数、结果长度、b64 形状、`ctx` 形状 |

### 4.1 关键代码

```c
// 真签名：x0 = ctx（不透明），x1 = result（base64(AES(json))）
typedef const char *(*jcy_cb_fn)(void *ctx, const char *result);

// Dart 侧同位置固定回 {"code":400}；返回野指针会直接触发 nlohmann parse_error → abort
static const char g_cb_reply[] = "{\"code\":400}";

static const char *jcy_callback(void *ctx, const char *result) {
    int len = -1, ok = probe_b64(result, &len);
    ... 存 g_result / 置 g_done / signal ...
    return g_cb_reply;          // ★ 不再 return result
}
```

```c
// init：json 缓冲必须长期有效（libcore 0x2fdc24 首条指令 str x0,[全局]）
free(g_init_json);
g_init_json = json ? strdup(json) : NULL;
if (json) (*env)->ReleaseStringUTFChars(env, jjson, json);
g_init(g_init_json, jcy_callback);
```

---

## 5. 真机复验方法

```bash
# 装新包后，只看我们自己的 tag
adb logcat -c
adb logcat -s JcyCore JcyBridge

# 期望看到（顺序固定）
#   I JcyCore: libcore.so 已加载: handle=... call=... init=...
#   I JcyCore: init 入参(NNN B): {"app_id":"4150439554430529","tcp":...}
#   I JcyCore: call 入参 MMM B: ...
#   I JcyCore: callback #1: result=0x...(len~N,b64=1) ctx=0x...(ctxb64=0,len~K) -> reply {"code":400}
#   I JcyCore: call 完成，回调结果 X B
```

判据：

* `callback #n` 里 **`b64=1`**（result 是 base64）且 **`ctxb64=0`** → 参数顺序正确；
  若出现 `b64=0` 并伴随 `参数顺序可能仍不对` 的 ERROR → 顺序判断需回退重估。
* 不再出现 `abort` / `parse_error`。
* `call 完成` 后，桥侧 `curl -s http://127.0.0.1:8792/debug` 应能看到
  `probe_config_code == 20000`。

---

## 6. 未执行 / 判据缺口

* **未在真机复验**（本轮只做到「改完 + 重编 APK」；tombstone 未提供 JNI 帧，
  无法 100% 排除崩溃发生在 libcore 自建线程而非 `nativeInit/nativeCall` 调用栈上）。
* **未还原 `init` 的真实实现**（0x2fdc24–0x307a38 共 40468 B 全静态、OLLVM 展平，
  其中 0x2fe114 / 0x2ff9a8 被 `call` 复用，init/call 边界未切分）。
* **未确定 `{"code":400}` 的语义**（只知它是 App 在回调处固定返回的值；
  native 是否据此分支未证）。
* 未验证 `getHostConfig()["tcp"]` 的真实取值 —— 目前仍硬编码
  `43.145.33.254:27990`（见 `docs/api/overview.md:151` 的遗留疑点）。
