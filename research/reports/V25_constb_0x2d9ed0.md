# V25 — `0x2d9ed0` 逆向结论与 App 自研加解密全链路

- 目标文件：`assets/apk/base.apk` → `lib/arm64-v8a/libcore.so`（ELF64 AArch64，ET_DYN，运行时基址 `0x400024a00000`）
- 关键偏移：`0x2d9ed0`（本次任务焦点）、块循环 `0x2d7440`、调用点 `0x2d7458`、轮驱动 `0x2da498`
- 结论一句话：**`0x2d9ed0` 不是「有状态 NEON 常量生成器」，它是一个被 OLLVM 展平 + MBA 混淆 + SIMD 位选择包装的 16 字节逐字节异或 `B[i] ^= A[i]`。** `CONST_b` 由调用方在块循环里生成，经 `memmove` 灌入状态操作数 `A`。
- 证据等级：静态（capstone/pyelftools）+ 动态（Unicorn 指令级打点）双路互证，关键等式 4/4 断言 PASS。

---

## 1. 环境与分析思路

### 1.1 设备与环境（Windows + 雷电 14）

| 项            | 值                                                                                       |
| ------------ | --------------------------------------------------------------------------------------- |
| adb          | `C:/leidian/LDPlayer14/adb.exe`（Git Bash 需 `export PATH="/c/leidian/LDPlayer14:$PATH"`） |
| 设备连接         | `adb connect 127.0.0.1:5555`                                                            |
| App 包名 / 进程名 | `app.video.guoguo` / 中文进程名 `囧次元`                                                        |
| ABI          | `arm64-v8a`                                                                             |
| 模拟器运行时       | `.venv/Scripts/python.exe`（frida 17.8.2、unicorn 2.1.4、capstone、pyelftools）              |

**Windows 沙箱坑（必须遵守）**：所有设备/HTTP 命令加 `MSYS_NO_PATHCONV=1`，否则 `/app/...` 会被 MSYS 改写成 `C:/.../app/...` 导致 404；后台进程随 bash 回合结束被回收，需用受管后台任务或 `.bat`（纯 ASCII + CRLF）常驻。

### 1.2 取包与验证（按序执行）

```bash
export PATH="/c/leidian/LDPlayer14:$PATH"
MSYS_NO_PATHCONV=1 adb connect 127.0.0.1:5555
MSYS_NO_PATHCONV=1 adb shell getprop ro.product.cpu.abi          # -> arm64-v8a
MSYS_NO_PATHCONV=1 adb shell pm path app.video.guoguo            # -> /data/app/.../base.apk
MSYS_NO_PATHCONV=1 adb pull <上一步路径> assets/apk/base.apk
# 解出 so 并验证
python -c "import zipfile;z=zipfile.ZipFile('assets/apk/base.apk');z.extract('lib/arm64-v8a/libcore.so','.')"
python -c "
from elftools.elf.elffile import ELFFile
e=ELFFile(open('lib/arm64-v8a/libcore.so','rb'))
print(e.header.e_machine, hex(e.header.e_type))   # EM_AARCH64, 0x3(ET_DYN)
"
```

`base.apk` = 43,041,159 B；`libcore.so` = 6,839,376 B。

### 1.3 抓包链路（明文 HTTP，与 TLS/pinning 无关）

```bash
MSYS_NO_PATHCONV=1 adb reverse tcp:27990 tcp:27990
# 设备侧 iptables REDIRECT 43.145.33.254:27990 -> 127.0.0.1:27990
# 宿主机起 keep-alive 代理（否则 301 被 reset）；旧代理残留先 netstat -ano | grep :27990 清掉
python research/toolchain/mitm_proxy_generic.py     # 落地 captures/proxy_bodies.jsonl
```

### 1.4 注入方案（Frida，**只能 attach 不能 spawn**）

```bash
# 启动 App 后 attach；禁止 spawn（会触发加固自毁）
.venv/Scripts/python.exe -c "import frida;d=frida.get_usb_device();print(d.enumerate_processes())"
frida -U -n 囧次元 -l research/captures/rsa_scan/live_evp_hook.js
```

**分析思路**：静态先定位函数边界与调用点 → 用 **Unicorn 直接模拟 libcore 单函数**（比真机 hook 快、可复现、可对任意 K/明文跑）→ 关键结论回真机 Frida 复核 → 落到请求链路。本次 `0x2d9ed0` 的结论完全由静态 + Unicorn 双路得出，无需真机即可复现。

---

## 2. 静态还原

### 2.1 函数边界

| 项   | 值                                                                          |
| --- | -------------------------------------------------------------------------- |
| 入口  | `0x2d9ed0`（真实序言 `stp x29, x30, [sp, #-0x50]!`；前一函数在 `0x2d9ec8` 以 `ret` 结束） |
| 出口  | `0x2da1c4`（`ldp x29, x30, [sp], #0x50 ; ret`，帧大小与序言一致）                     |
| 大小  | **756 字节 / 189 条指令**                                                       |
| 调用点 | **全 `.text` 仅 `0x2d7458` 一处**（`bl 0x2d9ed0`）                               |

> 校正：`research/neon_constb_disasm.py` 的「向后找最后一个 ret」启发式会把范围误扩到 `0x2da44c`（那是下一个函数的 `ret`，帧 `0x80` ≠ 本函数 `0x50`）。以序言/尾声帧匹配为准，正确范围是 `0x2d9ed0–0x2da1c4`。

### 2.2 指令构成（`0x2d9ed0–0x2da1c4`）

| 类别                         | 条数     | 占比       |
| -------------------------- | ------ | -------- |
| 整数/位运算（MBA 布尔汤）            | 131    | 69.3%    |
| 内存访问（ldr/ldrb/str/strb…）   | 29     | 15.3%    |
| **NEON/向量**                | **11** | **5.8%** |
| `adrp` 常量基址                | 6      | 3.2%     |
| 间接跳转（`br`/`blr`，OLLVM CFF） | 6      | 3.2%     |
| 直接跳转                       | 6      | 3.2%     |

OLLVM 控制流平坦化：派发经 `adrp x22, #0x671000`（跳转表基址 `0x671630`）+ `ldr xN,[x22,#k] ; ldr xM,[xN,idx] ; add xM,xM,off ; br/blr xM`。

### 2.3 NEON 寄存器使用（全部 11 条）

```
0x2da000  dup  v0.2s, w9        ; 把 ~b（b 的高位字节）广播
0x2da020  dup  v2.2s, w25       ; 把第一个源字节广播
0x2da02c  and  v0.8b, v0.8b, v1.8b
0x2da04c  and  v1.8b, v2.8b, v1.8b
0x2da05c  orr  v0.8b, v1.8b, v0.8b
0x2da070  and  v2.8b, v0.8b, v2.8b
0x2da078  eor  v1.8b, v2.8b, v1.8b
0x2da0bc  eor  v0.8b, v0.8b, v2.8b
0x2da0d8  orr  v0.8b, v1.8b, v0.8b
0x2da0ec  dup  v1.2s, v0.s[1]
0x2da124  and  v0.8b, v0.8b, v1.8b
```

`v1` 来自 `ldr d1, [x10, #0xa88]`（`adrp x10,#0x1df000` 的 rodata 掩码）。这一串 `and/orr/eor` 是**把 `A[i]^B[i]` 用位选择恒等式写出来的混淆形态**（真值表等价于单条 `eor`），不构成任何独立密码学常量——只是 OLLVM 的 SIMD 化布尔汤。除这 11 条外，本函数**没有**任何真正的向量常量生成逻辑。

### 2.4 关键寄存器 / 变量 / 常量来源

| 寄存器           | 语义                                            |
| ------------- | --------------------------------------------- |
| `x19` / `x20` | 两个输入数组的基址（经访问器 `blr x8` 取元素指针）                |
| `x21`         | 循环下标 `i`（`sxtw x21, w23`）                     |
| `x0`          | **访问器返回值 = `base + i`**（元素地址，非基址）             |
| `w25` / `w11` | 两路读入的字节（`ldrb w25,[x0]` / `ldrb w11,[x0]`）    |
| `w8`          | 结果字节（`strb w8,[x0]`）                          |
| `x22`         | `adrp #0x671000` → 间接跳转表基址 `0x671630`（CFF 派发） |
| `x10` / `x12` | `adrp #0x1df000` → rodata 混淆掩码（`+0xa88` 等）    |
| `x29`/`sp`    | 帧指针，帧 0x50                                    |

**常量来源结论**：本函数引用的「常量」只有两类——(a) CFF 派发表的**代码指针**；(b) rodata 的**混淆位掩码**。二者都**不是**密码学常量。**`CONST_b` 不在本函数内生成。**

### 2.5 `CONST_b` 闭式与状态更新规则

实测证明本函数是纯 XOR，故 `CONST_b` 由**调用方**生成：

```
块循环 0x2d7440：
  0x2d744c  bl 0x2d9ad4     ; extract：按块号取 16B 明文块（blockidx*16，尾部 0x55 填充）
  0x2d7458  bl 0x2d9ed0     ; ★ XOR：B ^= A        -> B 即 x_b
  0x2d7464  bl 0x2da1c8     ; reorder（4×4 重排）
  0x2d7474  bl 0x2da498     ; 轮驱动 = E 主体（10 轮 AES 形 SPN，11 个轮密钥）
  0x2d7480  bl 0x2da6c4     ; 输出/链式重排
```

状态操作数 `A` 的更新（动态实证）：

- `A` 缓冲位于 `0x50001220`，**由 `memmove(dst=A, src=<计算值>, 16)` 灌入**（libc 桩，宿主侧写入）；
- 源值由 **`0x2da818` 的 `strb w27,[x0]`** 产生，索引 `w9 = w23 + (w25<<2)` → **4×4 转置式写序**；
- 数值 = `ct_{b-1} ^ CONST_b`（见 §3 交叉验证）。

**状态更新规则（等价闭式）**：

```
x_b      = pt_b ^ ct_{b-1} ^ CONST_b          (b=0 时 ct_{-1} := iv)
ct_b     = E(x_b) ^ Cb_b
Cb_b     = CONST_{b+1} ^ CONST_1              (b>=0, CONST_0 = Cb_0 = 0)
⇒ X_0   = pt_0 ^ iv
  X_{b+1} = pt_{b+1} ^ E(X_b) ^ CONST_1
```

`CONST_b` 本身**仍是 (K,b) 的高熵函数**（`E⁻¹(CONST_b)` 无结构、GF(2) 秩≈样本数、强依赖 K、不可预计算），其**闭式尚未还原**——但本任务的定位已纠正：**要逆的是块循环里的 `0x2da818`/状态生成路径与密钥调度，而不是 `0x2d9ed0`**。

### 2.6 输出取值方式（伪代码）

```c
// 0x2d9ed0 —— 16 字节逐字节异或（就地写回 B）
void xor16(const uint8_t *A, uint8_t *B) {   // x19/x20 之一 = A（只读），另一 = B（读+写）
    for (int i = 0; i < 16; i++) {
        uint8_t a = A[i];                    // ldrb w25,[accessor(x19,i)]
        uint8_t b = B[i];                    // ldrb w11,[accessor(x20,i)]
        B[i] = a ^ b;                        // strb w8,[accessor(x20,i)]   (MBA+SIMD 混淆)
    }
}
```

调用点 `0x2d7458` 的实参：`x1 = sp+0x78`，`x2 = x29-0x78`；结果就地写回其中一路，随后交给 `0x2da1c8` 重排。

---

## 3. 动态验证

### 3.1 我实际做的（Unicorn 指令级打点，可复现）

在三个字节访问点装 `UC_HOOK_CODE`，跑一次 2 块加密：

| 打点         | 指令              | 作用    |
| ---------- | --------------- | ----- |
| `0x2d9fc4` | `ldrb w25,[x0]` | 读入源 1 |
| `0x2d9fe8` | `ldrb w11,[x0]` | 读入源 2 |
| `0x2da188` | `strb w8,[x0]`  | 写回结果  |

脚本：`research/tmp_neon_semantics.py`、`tmp_neon_groups.py`、`tmp_neon_addr.py`、`tmp_allwrites.py`、`tmp_stublog.py`、`tmp_src_trace.py`。

**结果**（K=`00112233445566778899aabbccddeeff`，pt=`deadbeefcafebabe0102030405060708`）：

```
call#0  A=00*16                               B=deadbeefcafebabe0102030405060708   out=A^B=pt块0
call#1  A=5d2b64c1326d4be8acb621be56b040f6    B=10*16 (PKCS7)                      out=A^B
校验 out[i] == A[i] ^ B[i] :  32/32 全部成立
```

地址规律：`R1` 恒在 `0x50001220+i`（状态 A），`R2`/`W` 同址（明文块 B，就地写回）。

### 3.2 交叉验证（4/4 断言 PASS，脚本 `research/verify_constb.py`）

```
ct          = afeda85f4a06fb1a3358da8ede2653d9 8f4d08d6d72d878a65a19f89399efd7e
ct0         = afeda85f4a06fb1a3358da8ede2653d9
A(call#1)   = 5d2b64c1326d4be8acb621be56b040f6
A ^ ct0     = f2c6cc9e786bb0f29feefb308896132f  == CONST[1] ✔

CONST[0] = 00000000000000000000000000000000
CONST[1] = f2c6cc9e786bb0f29feefb308896132f
CONST[2] = 2cc71e1575989111d62d781601562dff
CONST[3] = 7bb736e66da49c7435ae32f6d2309322
Cb[1]    = de01d28b0df321e349c3832689c03ed0
Cb[2]    = 8971fa7815cf2c86aa40c9c65aa6800d
Cb[3]    = ff5a3b08db498be1a224fd3dd7184e46
C(K)     = c4db93d2a8ef7048bb560286cea1d394

[PASS] A(call#1) == ct0 ^ CONST[1]
[PASS] CONST[0] == 0
[PASS] Cb[b] == CONST[b+1] ^ CONST[1]   (b=0..2)
[PASS] 不变式自检 invariant_ok
```

### 3.3 真机 Frida 复核方案（如要在设备上直接看 I/O/状态/密钥）

```javascript
// hook_state.js —— attach 到 囧次元（禁止 spawn）
const base = Module.findBaseAddress('libcore.so');
const XOR  = base.add(0x2d9ed0);          // 16B XOR
const EXTR = base.add(0x2d9ad4);          // 块提取
const STATE= base.add(0x2da818);          // 状态写入(strb)

// 1) dump 输入/状态/输出
Interceptor.attach(XOR, {
  onEnter(a){ this.A = a[0]; this.B = a[1];
    send({t:'xor', A: hexdump(this.A,{length:16}), B: hexdump(this.B,{length:16}) }); },
  onLeave(r){ send({t:'xor-out', B: hexdump(this.B,{length:16}) }); }
});
// 2) dump 状态写入 PC
Interceptor.attach(STATE, { onEnter(a){
  send({t:'state', dst:a[0], v: hexdump(a[0],{length:16}) }); } });
// 3) dump 密钥调度（KSA）与 rodata 掩码
const KSA = base.add(0x2cd8b0);
Interceptor.attach(KSA, { onEnter(a){ send({t:'ksa', key: hexdump(a[0],{length:16}) }); } });
// 4) 需要精确内存读写时序时用 MemoryAccessMonitor / Stalker.follow
```

```bash
frida -U -n 囧次元 -l hook_state.js
```

> Magisk 无需参与：`attach` 即可，且 `libcore.so` 是明文加载的自研库（非加固 so），Frida 直接可读。

### 3.4 关键常量表

| 名称                                | 值                                                                  | 来源                    |
| --------------------------------- | ------------------------------------------------------------------ | --------------------- |
| 自定义 base64 字母表                    | `5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj` | rodata `0x1e1c74`     |
| auth 头 key                        | `ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv`                                 | `0x688130`            |
| auth 头 iv                         | `WonrnVkxeIxDcFbv`                                                 | `0x688148`            |
| `CONST_0 / Cb_0`                  | `0`                                                                | 模型定义                  |
| `CONST_1..3` / `Cb_1..3` / `C(K)` | 见 §3.2                                                             | `decrypt_e.calibrate` |

---

## 4. 请求链路

### 4.1 字段来源与请求形态

| 字段               | 值 / 来源                                                                                        |
| ---------------- | --------------------------------------------------------------------------------------------- |
| 主机               | `43.145.33.254:27990`（**明文 HTTP**）                                                            |
| `appid`          | `4150439554430529`（常量）                                                                        |
| `ts`             | 毫秒时间戳（`Date.now()`）                                                                           |
| `nonce`          | 8 位随机数字串                                                                                      |
| `tcs`            | `2`                                                                                           |
| `x-version`      | `2020-09-17`                                                                                  |
| `user-agent`     | `Dart/3.6 (dart:io)`                                                                          |
| `authentication` | `CUSTOM_B64( E( CUSTOM_B64( S ) ) )`，`S = "3.0.0.8-{ts}-Android-1.5.8.0-{device_fp}-default"` |
| body             | `<P0_b64>.<P1_b64>`（`.` 分隔的两段自定义 base64）                                                      |

### 4.2 签名（`authentication`）生成

```
S      = "3.0.0.8-{ts}-Android-1.5.8.0-{device_fp}-default"
A1     = CUSTOM_B64(S)
E_out  = E(key=ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv, iv=WonrnVkxeIxDcFbv, PKCS7(A1))   # 112B
auth   = CUSTOM_B64(E_out)                                                          # 152 字符
```

`E` 即 §2 的自研分组密码（管线入口 `0x304eb0`，A1 `0x304fb4` / E `0x3050f8` / AUTH `0x3051b4`）。`E` 未还原为纯 Python，工程上用 **C 转译引擎 `research/engine_c/jcy_fuse24.dll`**（`research/c_engine.py` ctypes 绑定）或 Unicorn 预言机 `EOracle` 计算。

### 4.3 请求加密 / 响应解密

```
# 请求
K16      = 16 字节 RAND
P0       = RSA-2048_PKCS1v1.5(server_pub_2048_live.pem, K16)          # 256B
P1       = E(key=K16, iv=reverse(K16), PKCS7(json))                    # 长度 = ceil((len+1)/16)*16
body     = CUSTOM_B64(P0) + "." + CUSTOM_B64(P1)

# 响应（HTTP 恒 200，业务码在 JSON body）
K16resp  = RSA_priv_decrypt(priv_from_go.pem, resp_P0)                 # 256B 密文 -> 16B 密钥
plain    = E_decrypt(P1=resp_P1, key=K16resp, iv=reverse(K16resp))     # GET/POST 同规则
```

**注意**：`K16resp` 每次响应全新 → 标定缓存跨请求永不命中，每请求需一次全长标定（这是响应解密的主要耗时项）。


### 4.4 可复现 Python（核心片段）

```python
from research.deliverables.jcy_client import JcyClient          # 已封装持久连接 + c_engine 加密
from research.deliverables.decrypt_e import decrypt             # 标定法离线解密 P1

c = JcyClient()                                   # 内部：authgen 取签 + RSA + c_engine
rr = c.request("POST", "/app/config/video", json_body={...})   # rr 含 "p1b"(密文) / "k16b"(响应K16)
plain = decrypt(rr["p1b"], rr["k16b"])            # 首块起标定，blocks=N 可只解前 N 块
```

### 4.5 端点事实（实测 35 接口）

- `/app/config/{channel,video}` 是 **POST**；`/app/danmu` 必带 `part`（明文 JSON）；`/app/upgrade` 仅 POST、不校验 auth、恒定 64B 桩；`/app/video/play` 参数放 **query**、body `{}`。
- **GET 端点不能带 body**（会返回 `40000`）。
- 游客态受限(`50008`)：`/app/users/info`、`/app/task/task`、`/app/history`。
- 错误码：`800131`/`300103`=P1 解不开/网络错；`30000 解码异常:authentication is empty`=本地取签服务没起；`is error`=签名过期/变量未替换。

---

## 5. 输出格式：分阶段结论 / 对照 / 置信度

### 5.1 分阶段结论

| 阶段           | 结论                                                                                 | 状态            |
| ------------ | ---------------------------------------------------------------------------------- | ------------- |
| 定位           | `0x2d9ed0` 是独立函数，入口 `0x2d9ed0`、出口 `0x2da1c4`、756B/189 条，全 `.text` 唯一调用点 `0x2d7458` | ✅ 证实          |
| 语义           | 16 字节逐字节异或 `B[i] ^= A[i]`（就地）                                                      | ✅ 动态 32/32 证实 |
| 混淆           | OLLVM CFF（6 间接跳转，表 `0x671630`）+ MBA（69.3%）+ SIMD 位选择（11 条 NEON）                    | ✅ 证实          |
| 常量           | 本函数内**无**密码学常量；引用仅 CFF 代码指针 + rodata 混淆掩码                                          | ✅ 证实          |
| 状态           | 操作数 `A = ct_{b-1} ^ CONST_b`；由 `memmove` 从 `0x2da818` 转置写序的结果灌入                    | ✅ 证实          |
| `CONST_b` 闭式 | **未还原**（高熵、强依赖 K）；但**正确攻击面已从 `0x2d9ed0` 转移到块循环/密钥调度**                              | ⚠️ 部分         |

### 5.2 与常见「NEON 常量生成器」模式的对照

| 常见模式                               | 本函数是否命中 | 判据                                              |
| ---------------------------------- | ------- | ----------------------------------------------- |
| AES 轮常量 RCON 生成（`movi`/`tbl` + 位移） | ❌       | 无 `movi`，仅 3 条 `dup`，无轮常量表访问                    |
| CRC/多项式表生成（`tbl`/`tbx` 256B）       | ❌       | 无 `tbl/tbx`，无 256B 表写入                          |
| 置换/字节代换 S 盒构造                      | ❌       | 无 `tbl`；输出恒等于输入两两异或                             |
| 计数器/PRNG（状态机 + 移位反馈）               | ❌       | 无状态寄存器跨调用保持，纯组合逻辑                               |
| **位选择恒等式混淆（MBA+SIMD）**             | ✅       | `and/orr/eor` 序列真值表 == 单条 `eor`，32/32 输出 == A^B |

> 因此「有状态 NEON 生成器」这一先验不成立：`0x2d9ed0` 既不生成常量、也不保持状态，它是**消费**状态的 XOR 合并器。

### 5.3 阻塞点与替代方案

| 阻塞               | 现状                        | 替代方案                                                                                                          |
| ---------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `CONST_b` 闭式未还原  | 静态不可判定（高熵、依赖 K）           | **标定法**：`decrypt_e.calibrate(K, nblk)` 一次算出 `CONST_b/Cb_b`，同 K 复用、跨请求因 `K16resp` 新鲜需重标定；或直接调 `jcy_fuse24.dll` |
| `E` 未还原为纯 Python | 非标准 AES（自定义 S 盒 + 256B 表） | C 转译引擎（`c_engine.encrypt` 与 Unicorn 逐位等价，5.7ms vs 104.6ms）或 Unicorn 预言机                                       |
| 真机无法 spawn       | 加固自毁                      | 只 attach；或 Unicorn 离线跑（本次主路径）                                                                                 |

### 5.4 置信度

| 结论                             | 置信度      | 依据                       |
| ------------------------------ | -------- | ------------------------ |
| `0x2d9ed0` = 16B XOR           | **0.98** | 32/32 动态 + 静态指令语义一致      |
| 函数边界 `0x2d9ed0–0x2da1c4`       | **0.97** | 序言/尾声帧匹配 + 唯一调用点         |
| `A = ct_{b-1} ^ CONST_b`       | **0.95** | `A^ct0 == CONST[1]` 精确相等 |
| `Cb_b = CONST_{b+1} ^ CONST_1` | **0.99** | 不变式 3/3 + 全接口回归          |
| `CONST_b` 闭式                   | **0.0**  | 未还原（负结果）                 |
| 请求链路字段/算法                      | **0.97** | 真机回归 35 接口通过             |

### 5.5 复现脚本清单

| 脚本                                                                           | 用途                                |
| ---------------------------------------------------------------------------- | --------------------------------- |
| `research/neon_constb_disasm.py`                                             | 静态定位/分类/反汇编 `0x2d9ed0`            |
| `research/tmp_neon_semantics.py` / `tmp_neon_groups.py` / `tmp_neon_addr.py` | 逐字节 I/O 打点与分组重建                   |
| `research/tmp_allwrites.py` / `tmp_stublog.py` / `tmp_src_trace.py`          | 状态缓冲写入者定位（memmove 桩 → `0x2da818`） |
| `research/verify_constb.py`                                                  | `A^ct0 == CONST[1]` 等 4 项断言（PASS） |
| `research/deliverables/decrypt_e.py`                                         | 标定法 P1 解密                         |
| `research/deliverables/c_engine.py` + `engine_c/jcy_fuse24.dll`              | 高性能 `E` 引擎                        |

---

### 附：本次纠正的旧结论

- 旧记录 `e_structure_notes.md` 把 `0x2d9ed0` 标为「NEON 合并」——**现已指令级证实为 16B XOR**，与「NEON 生成器」的假设一并作废。
- 旧「负结果」条目「必须逆 `0x2d9ed0`（有状态 NEON + `0x671630` + OLLVM）才能得 CONST_b 闭式」——**前提错误**：`0x2d9ed0` 不含常量生成；正确攻击面是块循环 `0x2d7440` 的状态生成路径（`0x2da818`）与密钥调度。
