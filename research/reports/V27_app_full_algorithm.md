# V27 — App 完整算法（FFI/传输层定案）+ S_b 生成器现状 + 提速路线

> 承接 V26。用户诉求：「已能解密响应，但速度不行 → 逆向 App 分析出**完整算法**」。
> 本报告给出**本轮新验证**的结论，全部标注证据；未执行项明确写「未执行」。
> 一句话：**算法外壳已完整（含新发现的 AES-CBC 传输层）；唯一未还原的是逐块 tweak
> S_b 的闭式，本轮又排除了「哈希/HMAC/RC4 类 keystream」这一整片假设空间。**

---

## 0. 结论摘要

| 项 | 状态 |
|---|---|
| Dart→native 调用面 | **已定案**：`libcore.init(json)` + `libcore.call(json, cb)`，JSON 动作协议 |
| 传输层封装 | **新发现**：标准 **AES-128-CBC + PKCS7 + base64**，密钥/IV 硬编码 |
| 动作清单 | **新发现**：`check` / `api_encrypt` / `api_decrypt` / `clear_key` / `init` / `getRecord` / `getCoreVersion` / `getAbi`（+ libloader `reload`） |
| `api_decrypt` 入参 | **新发现**：`data` = **整个响应 body**（含 RSA 段），native 自行完成 RSA+P1 两段解密 |
| 密码本体 E | 已定案：`E(x)=T(SR(SB(AES9(T(x)^rk0))))^C(K)`（V13–V15，逐位复核） |
| 分块模式 | 已定案：`x_b=pt_b^ct_{b-1}^S_b`，`ct_b=E(x_b)^(S_{b+1}^S_1)`（不变式 63/63） |
| **S_b 闭式** | **仍未还原**（本轮新增排除：哈希/HMAC/RC4 全族） |
| 解密耗时瓶颈 | **标定占 99.9%**（1.0–1.4 ms/块；纯解密 0.144 ms/323 块） |
| 引擎覆盖 | **仅含 0x304eb0 可达代码** → 直接调 `call`/`api_decrypt` 需重做 PC 覆盖 |

---

## 1. App 完整调用链（本轮定案）

### 1.1 Dart FFI 面（blutter `asm/guoguo/utils/ffi_utils.dart`）

```
loadCore()   : dlopen(getCore() ?: "libcore.so") → lookup("call")
init(json)   : lookup("init")    签名 NativeFunction<(dynamic, Pointer<Utf8>) => Void>
call(json,cb): lookup("call")    签名 NativeFunction<(dynamic, Pointer<Utf8>,
                                     Pointer<NativeFunction<(dynamic, Pointer<Utf8>)
                                       => Pointer<Utf8>>>) => Void>
```

**关键：`call` 的返回类型是 `Void`，结果只经回调返回**（`#ffiCallback0` →
`dartCallback` → `completer.complete(result)`）。证据：`loadCore` @0xcd3a68 的
TypeArguments 字面量 + `__call` @0x5afbe0 处 ClosureCall 后立即取 `completer`。

### 1.2 传输层 = 标准 AES-128-CBC（新）

`__call`（`_rawCall` 的实际执行体，@0x5afa54）逐条读出：

```dart
key = "qPwClBj7j7ZQraSm"        // 16B
iv  = "p3JdVQl3q7WQJIgG"        // 16B
enc = Encrypter(AES(Key.fromUtf8(key), mode))       // package:encrypt → 默认 CBC+PKCS7
b64 = base64.encode(enc.encrypt(json, iv: iv))
native_call(b64.toNativeUtf8(), ffiCallback0)       // 结果经回调
```

`_loaderCall`（libloader 通道）用另一对硬编码密钥：

```dart
key = "kFGTbLlOzFHQCIKp"   iv = "F3q22XoM8l6T2Ydc"
```

**含义**：native `call` 的第一步是 `base64 → AES-128-CBC 解密`，返回前再 `AES-CBC
加密 → base64`。即 **libcore.so 内含一份标准 AES-CBC**，与外层自研密码 E 无关。

### 1.3 动作清单（ffi_utils.dart 全文提取）

| 动作 | 载荷 | 调用方 |
|---|---|---|
| `check` | `{"action":"check"}` | `FFIUtils.check` |
| `init` | `{app_id, device_id, tcp, path…}` | `FFIUtils.init`（启动一次） |
| `api_encrypt` | `{"action":"api_encrypt","payload":{"data":…}}` | `apiEncrypt` |
| `api_decrypt` | `{"action":"api_decrypt","payload":{"data":…,"path":…}}` | `apiDecrypt` |
| `clear_key` | `{"action":"clear_key"}` | `clearKey` |

### 1.4 `api_decrypt` 的真实入参（新）

`g_http_client.dart` @0xbd76f8–0xbd77b8：

```dart
body = utf8.decode(response.bodyBytes)
if body[0] != '{':                 // 非明文才解密
    for (retry in 0..1):
        if retry: await clearKey()
        plain = await apiDecrypt(body, path)   // x1 = 整个 body, x2 = 请求 path
        if plain[0] == '{': break
```

→ **`data` 是整段响应 body**（`<P0_b64>.<P1_b64>`），**native 内部自己解 RSA(P0) 取
K16resp、再解 P1**。所以「native 是否持有 RSA 私钥」不再存疑：`init` 之后 native 拥有
完整密钥状态；`clear_key` 是显式重置入口。

> 这解释了为什么单纯 `api_decrypt(P1)` 无法离线复现 —— native 需要 `init` 建立的会话态。

---

## 2. 加密块循环的数据流（本轮动态实测）

用 Unicorn 在 `0x2d7440`（循环体）/`0x2d9ad4`/`0x2d9ed0`/`0x2da1c8`/`0x2da498`/
`0x2da6c4` 打点（脚本 `research/tmp_probe_loop.py`），K=`00112233…eeff`、2 块明文：

```
0x2d7440  x8 = sp+0x78   x1 = x29-0x48(上下文)   w2 = 块号
  bl 0x2d9ad4  EXTRACT(out=sp+0x78, ctx, b)
  bl 0x2d9ed0  XOR(·, sp+0x78, x29-0x78)
  bl 0x2da1c8  REORDER(out=sp+0x60, sp+0x78)
  bl 0x2da498  DRIVER(x0=表, x1=sp+0x60, x2=sp+0x90)
  bl 0x2da6c4  OUT(out=sp+0x48, sp+0x60)
```

实测到的实参（与真值 `tmp_gt_const.json` 对齐后）：

| 观测 | 值 | 判定 |
|---|---|---|
| DRIVER 的 `x1` 解析（2 级间接） | `ffbb7733eeaa6622dd995511cc884400` | = `T(iv)` = `T(x_0)` ✓ |
| 下一块 DRIVER 的 `x1` | `535bf4348c8e8ebf229c4d319f889857` | = `T(x_1)` ✓（`T⁻¹` = `538c229f5b8e9c88f48e4d9834bf3157`） |
| XOR 的 `x2`（`x29-0x78` 向量）块 0 | `ffeeddccbbaa99887766554433221100` | = `iv` = `x_0` |
| XOR 的 `x2` 块 1 | `538c229f5b8e9c88f48e4d9834bf3157` | = `x_1` ✓ |
| DRIVER 的 `x0` | `0x400025089640`（描述符）→ 表首 `637c777b ca82c97d b7fd9326 04c723c3` | 以 **AES S-box 头 `637c777b` 起始的 KSA 打乱表**，**跨块不变** |
| DRIVER 的 `x2` | `00112233 c0393478 f67e87c2 789ca46c` | = 轮密钥 0..3 的**首字** `w0,w4,w8,w12`（已逐字核对 `w0=00112233`、`w4=c0393478`、`w8=f67e87c2`） |
| `x8` 恒为 `0x5eed5eedcafef00d` | | OLLVM 栈 canary |

**结论（本轮最重要的一条）**：`x29-0x78` 是**链接状态**，第 b 块时存放 `x_b`；
`EXTRACT` 只收到 `(out, ctx, 块号)`——**签名里没有明文**，因此它要么是纯 (K, 块号) 函数
（＝S_b 生成器），要么它通过 `ctx` 间接推进明文流。**这是下一步唯一需要判定的分叉。**

> 注：本轮尝试用「同 K、两种明文跑管线比对 EXTRACT 返回后的 16 字节」来判定，
> 但明文注入钩子（`OFF_AFTER_A1`）在直连 `e.call` 时未生效（两次 body 完全相同），
> **该实验无效，判据未取得**（见 §7 未执行项）。

---

## 3. S_b 生成器：本轮新增排除

在既有负结果（V26 §4 表）之外，本轮**首次**覆盖「哈希/HMAC/RC4 类 keystream」整片空间
（脚本 `research/tmp_sb_hash.py`，样本 N=64，K=`00112233445566778899aabbccddeeff`）：

| 家族 | 覆盖 | 结果 |
|---|---|---|
| `H(K‖ctr)` / `H(ctr‖K)` / `H(K‖IV‖ctr)` / `H(IV‖K‖ctr)` | H ∈ {md5, sha1, sha256, sha512, sha3_256, blake2s, blake2b} × 12 种 ctr 编码 | 全否 |
| `HMAC_H(K, ctr)` / `HMAC_H(ctr, K)` | 同上 7×12 | 全否 |
| 递推 `s←H(s)` / `H(K‖s)` / `H(s‖K)` / `H(IV‖s)` / `H(s‖IV)` | 7 哈希 × 4 种子(K/IV/0/K^IV) × 5 形式 | 全否 |
| 迭代哈希 `s←H^b(K)` | 7 哈希 | 全否 |
| **RC4** | key ∈ {K, IV, K‖IV, IV‖K, K^IV} × drop ∈ {0,256,512,1024,3072} | 全否 |
| `S_1 ^ H(K‖ctr)` | 7×12 | 全否 |

**累计已排除**：AES-ECB/CTR/OFB 类（11+ 编码）、`E(·)`/`F(·)`/`F⁻¹(·)` 链、
`rk[i]` 关系、GF(2) 线性、固定点、哈希/HMAC/RC4 全族。

**剩余唯一有结构线索的方向**：`EXTRACT` 的 `(ctx, 块号)` 签名（§2）。
`ctx` 在 `x29-0x48`，即 `SP0-0x188`；用 `engine_run` 在管线跑完后直接重入 `0x2d9ad4`
**失败**（`unmapped 0x400025200000`）——管线返回后该栈帧已被复用，ctx 失效。

---

## 4. 性能实测（本轮复测，C 引擎 V24 / 639 块镜像）

```
nblk=1   7.9 ms   4   10.3 ms   16  17.8 ms   64  55.0 ms
     128 116.2 ms  323 337.9 ms  639 878.9 ms      → 1.0–1.4 ms/块
同 K 二次标定（缓存命中） : 0.0068 ms
decrypt_blocks(323 块)   : 0.144 ms      ← 纯求逆主循环
真实样本端到端（标定+解密）:
  nblk=3   6.4 ms   nblk=11  12.8 ms   nblk=120 106.6 ms
  nblk=268 317.4 ms （全部 json=True，明文正确）
```

⇒ **标定 ≈ 99.9%**。且 `tmp_pairs.json` 的 10 个 K16 全互不相同（各出现 1 次）
⇒ **按 K 缓存永不命中，跨请求复用不可能**。

### 引擎覆盖范围（本轮新发现，决定提速路线）

`gen_engine.py` 的 PC 覆盖来自 `reports/pc_cover_all.txt` + `pc_cover_multi.txt`
（＝`0x304eb0` 管线跑出来的 PC 集合）。实测 `jcy_engine_fuse.c` 中：

* `L_307xxx` 标签 **0 个**；`0x30xxxx` 段只覆盖 `0x304eb0–0x30536c`。
* 因此 `engine_run(0x307a38)` 直接 `BADPC 0x400024d07a38`（`JT[__o]==0`）。

**这解释了为什么「原生调 `call`」不能直接做：不是 ABI 问题，是引擎里根本没有那段代码。**

---

## 5. 提速路线（按可行性重排）

### 5.1 首选：重做 PC 覆盖 → 引擎内置完整 API（含解密）

```
1) 在 Unicorn（emu_v14）里从 0x307a38 起跑：
     x0 = base64(AES-CBC-PKCS7(json, "qPwClBj7j7ZQraJM"…见 §1.2, iv))
     x1 = 回调桩（写 x1 到固定地址后 ret）
   采集 PC 覆盖 + 验证回调拿到的结果 JSON 与 Python 侧一致。
2) 把新 PC 并入 reports/pc_cover_*.txt。
3) python research/gen_engine.py --fuse --cprop   →  build_fuse.sh --O2 fuse25
4) ctypes 加 jcy_api_call(json) 导出（回调桩用 engine_write 写 ret 指令即可）。
```
成功后解密从「1.0–1.4 ms/块 标定」→ **单次原生调用**，预计 323 块 ≈ 5–20 ms。

### 5.2 次选：设备侧直接调 native（无需引擎）

`libcore.so` 是普通 ARM64 库且导出 `call`/`init`。在 LDPlayer 上以 Frida
（本项目只允许 attach）注入后直接 `init(json)` → `call(json, cb)`，绕开全部仿真。
代价：桥要依赖设备在线。

### 5.3 立即可用（不需还原生成器）

* 只解密需要的块（`blocks=N`，已支持）；
* 桥层已对 GET 有 30 s TTL 缓存；可扩展到「端点+参数 → 明文」的持久缓存
  （实测 source/urls 跨请求 100% 稳定）；
* 引擎常驻 + 同 K 复用（已实现）。

### 5.4 已判定无价值

* 引擎 hub 直化（V24 实测 ≈10% 指令）——收益远低于 5.1。

---

## 6. 复现命令

```bash
# 性能复测
./.venv/Scripts/python.exe research/tmp_speed_now.py

# 块循环动态实参（Unicorn，~1–2 min）
MSYS_NO_PATHCONV=1 ./.venv/Scripts/python.exe research/tmp_probe_loop.py

# 哈希/HMAC/RC4 大电池（N=64）
./.venv/Scripts/python.exe research/tmp_sb_hash.py

# 静态调用图 / S-box 引用
./.venv/Scripts/python.exe research/tmp_blrange.py 0x2d7440 0x2d7600
./.venv/Scripts/python.exe research/tmp_callers.py 0x2d7440 0x2d9ad4 0x2da498
./.venv/Scripts/python.exe research/tmp_sboxref.py

# 引擎侧探针（重链接仅 ~1.4 s，无需重编引擎）
cd research/engine_c
gcc -O2 -w -o jcy_probe.exe jcy_fuse24.o jcy_fuse24_post.o probe_api.c   # 任意入口驱动
gcc -O2 -w -o jcy_dump.exe  jcy_fuse24.o jcy_fuse24_post.o probe_dump.c  # 跑管线后 dump 内存
gcc -O2 -w -o jcy_ext.exe   jcy_fuse24.o jcy_fuse24_post.o probe_ext.c   # 直接重入 EXTRACT
```

---

## 7. 未执行项 / 判据缺口

* **未取得「EXTRACT 是否与明文无关」的判据**：本轮 `tmp_probe_ext.py` 的明文注入
  （依赖 `OFF_AFTER_A1` 钩子 + `sess._cur[0]`）在直连 `e.call` 时未生效，两次运行
  body 完全相同 → 实验无效。**下一步须先修好注入，再重跑该判定。**
* **未从 `0x307a38` 起跑 Unicorn**（§5.1 第 1 步）。
* **未重做 PC 覆盖 / 未重编引擎**（§5.1 第 2–3 步）。
* **未在设备上以 Frida 调 `libcore.call`**（§5.2）。
* **未还原 `0x2ceb00` / `0x2e6cb8` 的语义**（两者被加密链与解密链共同调用，
  形态为 JSON/字符串与 GOT 间接调用，OLLVM 展平后无法线性阅读）。
* 未反编译 `libloader.so` 的 `reload` 热更新协议。
