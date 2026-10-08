# `authentication` 逆向全记录：思路、推理与每一步操作

> 本文是 `authentication` 头算法的**完整逆向过程记录**，逐阶段写明
> 「观察到什么 → 推出什么假设 → 怎么验证 → 结果如何（含被证伪的假设）」。
> 结论性说明见 [`algorithm-auth.md`](algorithm-auth.md)；验证原始记录见
> [`../research/reports/VERIFICATION.txt`](../research/reports/VERIFICATION.txt)。

---

## 阶段 0 · 起点与已知条件

**已知**（来自前期工作）：

1. App 是 Flutter / Dart AOT，业务加密在原生库 `libcore.so`（arm64）里。
2. 每个 HTTP 请求带 `authentication` 头，152 字符，base64 形态，112 字节解码后
   前 15 字节恒定、第 16 字节只在 `0x9c–0x9f` 之间变化。
3. 该头与 `ts` 强绑定：改 `ts` 立即 `403501`，`ts` 过旧 `403502`。
4. 环境是 x86_64 雷电模拟器 + Houdini 翻译层。

**关键限制**：Houdini 下 frida 看不到 ARM64 模块，`Interceptor` 对 ARM64 代码无效。
所以**动态 hook 路线封死**，只能走 Unicorn 离线模拟。

**第一条推理**：既然 hook 不到，就必须让 libcore.so 在 Unicorn 里"活"起来。
于是有了 `emu_v11.py`：以真机基址 `0x400024a00000` 映射 libcore.so，
再灌入从设备 `/proc/pid/mem` 读出的运行时数据段镜像 —— 这样全局态（单例、常量、
`std::string`）才是完全初始化的。

---

## 阶段 1 · 定位生成管线

**操作**：静态扫描 `bl` 指令找调用关系，再用运行时追踪确认。

```
0x305d94  auth 顶层生成器（被 0x30affc 唯一调用）
0x306548  → 0x304eb0  auth 编码管线（被 0x306548 唯一调用）
0x304eb0 内部：
    0x304fb4  bl 0x2dbf9c   → 产出 A1
    0x3050f8  bl 0x2d6f78   → 产出 BODY
    0x3051b4  bl 0x2dbf9c   → 产出 AUTH
```

**推理**：A 被调用两次、中间夹一个 E，形状就是
`AUTH = A( E( A( S ) ) )`。长度也对得上：
`78 --b64--> 104 --E--> 112 --b64--> 152`。

**验证**：`0x304eb0` 的 x0 在 `0x304fb4` 处是一个含 78 字节数据的对象 —— 与
"输入串 78 字节"吻合。追踪确认 `0x2dbf9c` 内层循环 `x21 += 3`、每轮产出 4 字节，
即 3→4 的分组编码，**base64 特征**。

---

## 阶段 2 · 卡点一：vsnprintf 拼出的输入串是垃圾

**现象**：`0x306478` 处调用 `__vsnprintf_chk`，但模拟器桩把它当普通寄存器读参，
拼出 `\xd0\xfc\x1ep-1881079065-Android-...(null)-(null)` —— 明显错误。

**推理**：AAPCS64 里变参函数的实参不在寄存器里直接可读，而是通过
`__va_list = {__stack, __gr_top, __vr_top, int __gr_offs, int __vr_offs}`
结构 + 一个"读到哪里"的游标。桩必须**真实展开 va_list**。

**修复**：实现 `VaList` 类与 `_fmt_va`：

```python
class VaList:
    """AAPCS64 __va_list: {__stack, __gr_top, __vr_top, int __gr_offs, int __vr_offs}"""
    def gp(self):
        if self.gr_offs < 0:                      # 还有寄存器参数
            a = (self.gr_top + self.gr_offs) & MASK
            self.gr_offs += 8
            return self.e.rd_u64(a)
        v = self.e.rd_u64(self.stack); self.stack += 8   # 溢出到栈
        return v
```

**结果**（决定性突破）：

```
fmt = "%s-%ld-Android-%s-%s-%s"
args = "3.0.0.8", ts, "1.5.8.0", "16613a7076284a15bc723d018bcd67e1", "default"
→ "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default"
```

**教训**：模拟变参函数时，"猜寄存器"永远错，必须按 ABI 展开 va_list。

---

## 阶段 3 · 卡点二：A 编码器在模拟环境里产出垃圾

**现象**：A1 的输出长度正确（104），但内容是 `\x00\x00\x00\x00\x00\x005\x00\x00f...`。
E 的输出因此也是垃圾。

**排查过程**：

| 观察 | 推理 |
|---|---|
| A1 长度 = 104 = base64(78) | A 是 base64，长度逻辑正确 |
| `extract(obj, idx)` 每次返回 24 字节、内容是单个 ASCII 数字 + 大量 0 | 取元素逻辑"看起来对" |
| 逐条比对 extract 输出与输入字节 | idx=3/6/12/… 时**完全正确**（如 0x33='3'、0x2E='.'），只有少数错 | 编码器大部分正确，少数步骤错 |
| 字母表指针 `0x737e41dc2a40` 在 `regions_all` 里 | 内存是全的 |

**关键决策（本阶段最重要的方法论）**：既然 A 的行为已被独立确认是 base64
（长度 + 3→4 循环 + 字母表），那就**不要再修模拟器里的 A**，而是：

> **在 A 返回处（`0x304fb8`）直接把正确结果写回输出向量，让下游 E 拿到正确输入。**

```python
def on_code(uc, address, size, ud):
    if address == DEV_BASE + 0x304fb8:            # A1 返回处
        x29 = uc.reg_read(UC_R_X29)
        b, en, _ = struct.unpack("<QQQ", e.rd(x29 - 0x38, 24))
        if en - b == len(a1):                     # 长度 104 匹配
            e.wr(b, a1)                           # 强制覆写
```

**结果**：E 立刻产出了与真实抓包**逐字节一致**的 `O[0:32]`：

```
emulator E.out[16:48] = 2b3ef9d5b6c78fd91e33fb5136486918f70e50af61d497be95acdd0fd7ffae85
真机抓包   O[0:32]    = 2b3ef9d5b6c78fd91e33fb5136486918f70e50af61d497be95acdd0fd7ffae85   ✅
```

**这一步同时确认了三件事**：
1. `A = CUSTOM_B64`（用自定义字母表的 base64）**正确**；
2. `E` 的输出**就是** body；
3. 管线顺序 `A → E → A` 正确。

> **方法论提炼**：当某个环节无法在模拟器中正确运行时，只要它的语义已被独立确认，
> 就"短路"它 —— 把已知正确的结果注入，把验证火力集中到未知环节。这比继续修
> 一个有 bug 的模拟器高效得多。

---

## 阶段 4 · 判定 E 的分组模式：CBC

**目标**：确定 E 是 ECB / CBC / CFB / CTR / 流密码中的哪一种。

**思路**：利用 **CBC 的链接性质**做判定，无需知道密钥。

CBC 下 `ct[i] = E_k(P[i] ⊕ ct[i-1])`。因此若构造两个明文，使
`P'[i] ⊕ ct'[i-1] == P[i] ⊕ ct[i-1]`，则必有 `ct'[i] == ct[i]`。

**实验设计**（通过 `probe_D.py` 的 `A1HEX` 自由指定明文）：

```
run1: P  = A1                        → ct0
run2: P  = A1, P[16:32] ⊕= d         → ct1      （得到新的 ct1[0]）
run3: P  = run2 的 P, 但
        P[32:48] ⊕= ct0[16:32] ⊕ ct1[16:32]
```

**预测**：若为 CBC，`run3.ct[32:48]` 应**等于** `ct0[32:48]`。

**实测**：

```
run1 ct0..3: 23754ae9… | 2b3ef9d5… | f70e50af… | c5d33b3d…
run2 ct0..3: 23754ae9… | fbdb63e3… | 50eb3f1f… | 55750c03…
run3 ct0..3: 23754ae9… | fbdb63e3… | f70e50af… | c5d33b3d…
                            ↑ run3.ct[2] == run1.ct[2]  ✅
```

对 i=1、i=2 均成立 ⇒ **CBC 确认**。

**同时排除了**：ECB（改 P[0] 不会影响 ct[1]）、CTR/OFB（改 P[0] 只会影响 ct[0]）。

---

## 阶段 5 · 提取 key / iv 并验证其影响

**定位**：管线入口 `0x304eb0` 的 x1 / x2 分别是两个字符串对象。

```
x1 = 0x688130 → 长字符串对象 {cap=0x31, len=32, ptr=0x737de0fc2ce0}
     data = "ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"
x2 = 0x688148 → 短字符串对象 {size<<1 = 0x20 → len=16, 内联 data}
     data = "WonrnVkxeIxDcFbv"
```

**字符串对象布局**（本项目 libc++ 变体）：

- 短串：`{ (size<<1) | flag, data[23] }`，`flag=0`
- 长串：`{ cap|1, size, data_ptr }`

**验证"它们确实参与运算"**：受控实验改 key / iv，看输出是否变化。

```
KEY 不变            → head16 = 23754ae9d0cbe749f5441e769b45143e
KEY 改成 32 个 'A'  → head16 = a7ee00c6f9720c82671d6bce99172dbd   ← 变了 ⇒ key 参与
IV  改成 16 个 0x00 → head16 = 53e25e8d4ff5d4a009924d6cce836db6   ← 变了 ⇒ iv 参与
```

---

## 阶段 6 · 排除标准密码（大规模否证）

**假设 A：标准 AES**。穷举：

- 模式：CBC / ECB / CFB / CFB8 / OFB / CTR / OPENPGP
- 方向：enc / dec
- key 候选 10 组：`KEY(32)`、`KEY[:16]`、`KEY[16:]`、`IV`、`md5(KEY)`、`sha256(KEY)`、
  `base64decode(KEY)`、`md5(IV)`、`KEY+IV`、`IV+KEY`
- iv 候选 5 组
- 明文候选 6 组

→ **0 命中**。

**假设 B：恒定 IV**。若 E 是 CBC 且 IV 固定，则对任意样本
`D_k(ct0) ⊕ P0` 应恒等于 IV。对 543 条语料检验 → 所有候选密钥下都**不恒定**。

**假设 C：SM4**（国产分组密码，中文 App 常见）。自实现 SM4 并用
GB/T 32907-2016 标准向量自检通过后，同样穷举 → **0 命中**。

**假设 D：哈希构造**（md5/sha1/sha256/sha512/sha3/blake2 的各种组合、
9 种 key 的 HMAC/拼接）→ **0 命中**。

> **方法论**：先做"排除性实验"把大空间砍掉，比直接猜算法高效。
> 每次否证都记入 `VERIFICATION.txt` 的负结果清单，避免重复劳动。

---

## 阶段 7 · 定位密码核心：S-box 读取监视

**思路**：任何分组密码都会反复读它的 S 盒。于是 hook `UC_HOOK_MEM_READ`
到候选 S-box 的地址区间，看**谁在什么时候读**。

**libcore.so 中搜到的密码学常量**：

| 常量 | 文件偏移 |
|---|---|
| AES S-box `637c777b…` | `0x1dfc00`, `0x1dfd10` |
| AES 逆 S-box `52096ad5…` | `0x1e03b0`, `0x1ea5d8` |
| AES Td0 `a56363c6…` | `0x1e8db0` |
| SM4 S-box `d690e9fe…` | `0x20b630` |

**监视结果**（在 E 执行期间）：

```
AES_S    读次数=32   引用PC: 0x2cd8e8 … 0x2cd95c
AES_INV  —— 0 次
AES_Td0  —— 0 次
SM4_S    —— 0 次
```

⇒ 密码**只用 AES 的 S-box**，且只在 `0x2cd8b0` 一处读（仅 32 次 = 拷贝 256 字节）。

---

## 阶段 8 · 反汇编 `0x2cd8b0`：密钥相关 S 盒

反汇编后读出的算法（两段）：

```c
// 第 1 段：拷贝 AES S-box，并把 key 按字节循环铺开
for (i = 0; i < 256; i++) {
    dst[i]  = aes_sbox[i];
    buf2[i] = key[i % key_len];
}

// 第 2 段：RC4 式 KSA（以 AES S-box 为初始置换）
j = 0;
for (i = 0; i < 256; i++) {
    j = (j + dst[i] + buf2[i]) & 0xff;
    swap(dst[i], dst[j]);
}
```

**实测调用**（`probe_ksa.py`）：

```
KSA #0: dest=0x701efc18  key = singleton+0x18 → 64 字节自定义字母表
KSA #1: dest=0x701efc48  key = 32 字节 key 串 "ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"
```

⇒ 有**两张**密钥相关表，分别由「字母表」和「key」生成。

---

## 阶段 9 · AES 结构证据 与 假设证伪

**新证据**：`0x2d2f0c` 的代码是

```asm
mov  w8, #0x1b
eor  w0, w8, w1, lsl #1
ret
```

这正是 **AES 的 `xtime`**（GF(2⁸) 乘 2，归约多项式 `0x1b`）。
且 `0x2d2fe4` 是一段 GF(2⁸) 乘法累加循环，实参常量全是
`2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x11b, 3, 6, 0xc, 0x18, 0x30, 0x60, 0xc0, 0x19b…`
—— 典型的 MixColumns 系数。

**新假设**：E = AES 结构（标准轮函数）+ 自定义 S 盒。

**验证**（`try_custom_aes.py`，自实现参数化 AES 并用 `pycryptodome` 对标准参数自检通过）：

| 维度 | 候选 |
|---|---|
| S 盒 | AES / KSA(sbox,KEY32) / KSA(sbox,ALPHA64) / KSA(KSA(sbox,ALPHA),KEY32) / KSA(KSA(sbox,KEY32),ALPHA) |
| 密钥 | KEY32 / KEY32[:16] / KEY32[16:] / KEY32[:24] / IV16 / md5 / sha256 |
| IV | IV16 / 0¹⁶ / KEY32[:16] / KEY32[16:] |

→ 140 种组合，**0 命中**。

**结论**：E 使用了 AES 的**域运算与 S-box 素材**，但轮结构（或密钥扩展、或轮序）
被改过。**尚未还原为纯 Python**，这是当前唯一的实质缺口。

---

## 阶段 10 · 语料核验 与 device_fp 差异定位

**全量核验**（485 个唯一 ts）：`O[0:32]` **485/485 全部命中**，`ct0` 485/485。

**但 `O[32:96]` 对不上**。分块定位：

```
ct0 (body[ 0: 16]) 一致
ct1 (body[16: 32]) 一致
ct2 (body[32: 48]) 一致   ← 以上覆盖明文 A1[0:48] = input[0:36]
ct3 (body[48: 64]) 不一致 ← 覆盖明文 A1[48:64] = input[36:48]
```

**推理**：

- `input[0:36]` = `"3.0.0.8-<ts>-Android-1.5.8."`（与指纹无关）
- `input[36:48]` = `app_version[6] + "-" + device_fp[0:10]`（含指纹）

⇒ 语料抓取于 **2026-09-29 13:23**，设备内存镜像导出于 **2026-09-30 15:18**，
**属不同 App 实例、`device_fp` 不同**。这解释了为什么 `O[0:32]`（服务端真正校验的部分）
能完全对齐，而依赖指纹的 `O[32:96]` 不能。

**旁证**：枚举 `app_version[6] = 0..9` 等 12 种候选，无一能复现语料 `ct3`
⇒ 差异确实来自指纹而非版本号。

---

## 阶段 11 · 服务端实测（最终判据）

| 用例 | 结果 |
|---|---|
| `GET /app/config`（正例） | **HTTP 200**，2905 字节加密业务数据 |
| `GET /app/banners/0`（正例） | **HTTP 200**，7493 字节 |
| `GET /app/channel?top-level=true`（正例） | **HTTP 200**，3889 字节 |
| 篡改 auth 第 41 字符 | `{"code":403501,"message":"校验客户端签名失败…"}` |
| 空 auth | `{"code":30000,"message":"解码异常:authentication…"}` |
| 有效 auth + `ts` 回退 1 小时 | `{"code":403502,"message":"检测到设备时间异常…"}` |

**重要发现**：该服务端**错误也返回 HTTP 200**，业务码在 JSON body 里；
"成功"的表现是 body 为加密密文（`<P0_b64>.<P1_b64>`）而非明文错误 JSON。
早期文档中"用 HTTP 状态码判断"的说法是错的。

---

## 阶段 12 · 端点能力矩阵与旧结论修正

用**一个**离线生成的 auth 横扫 22 个端点 → **22/22 认证层通过**。

**修正的旧结论**：早期记录称"auth 绑定路径/query"，实测证伪 ——
同一个 auth 可跨 22 个端点使用；旧记录的失败实为**同时改了 `ts`** 或**取了过期 auth**。

**踩坑**：`/app/users/task`、`/app/messagebox/*`、`/app/history*`、`/app/config/*`、
`/app/video/*` 都是 **POST**，用 GET 会得到 404（第一轮矩阵就栽在这里）。

---

## 阶段 13 · 工程化：把依赖压到最小

**动机**：`authgen` 原本加载 813 个区域（424 MB），迁移与启动都重。

**方法**：hook `UC_HOOK_MEM_READ`，统计管线实际读到的区域。

**结果**：

```
被读取的区域: 5 / 817     被读取体积: 28.6 MB / 424.6 MB
   0235.bin  base=0x40002506b000 size=0x1d000    读 535997 次
   0092.bin  base=0x6fc6a000     size=0x140a000  读 285991 次
   0236.bin  base=0x400025088000 size=0x178000   读   2000 次
   0381.bin  base=0x737e41c00000 size=0x400000   读   1560 次  ← 自定义字母表所在区
   0255.bin  base=0x737ddfaf1000 size=0x300000   读   1160 次
```

**验证**：最小集下 `--selftest` 与 `--test-server` 结果与全集**完全一致**。

**收益**：交付依赖 424 MB → 28.6 MB，单次生成 5.7 s → 4.1 s。

---

## 阶段 14 · 脚本工程化

- 把纯逻辑抽到 `src/tools/jcy_protocol/auth.py`（零大文件依赖），
  以 `EBackend` 协议注入 `E`；
- `research/deliverables/authgen.py` 只负责提供 Unicorn 后端与 CLI；
- 新增 `tests/test_auth_pure.py`（纯逻辑，无需模拟器）与
  `tests/test_authgen.py`（端到端回归）。

这样**分层依赖方向保持单向**：`research/` 依赖 `src/`，`src/` 不依赖 `research/`。

---

## 可复用的方法论清单

| 手法 | 适用场景 |
|---|---|
| **va_list 真实展开** | 模拟任何变参 libc 函数（printf 家族） |
| **短路已知环节**（hook 返回处强制覆写中间量） | 某环节在模拟器中不可靠，但其语义已确认 |
| **CBC 链接性质判定** | 无密钥时区分 ECB/CBC/CFB/CTR |
| **参数影响性实验**（改 key/iv 看输出） | 确认某个内存值是否参与运算 |
| **恒定 IV 判据**（`D_k(ct0) ⊕ P0` 是否恒定） | 无需知道 IV 即可验证候选密钥 |
| **S-box 读取监视** | 定位密码原语、判断用了哪种 S 盒 |
| **分块定位差异** | 密文部分匹配时，反推明文哪一段不同 |
| **区域使用统计** | 把模拟器依赖压到最小可运行集 |
| **服务端阴性对照** | 证明"200"确实意味着通过，而非服务端恒返回 200 |

---

## 未解问题与下一步

1. **`E` 的自定义分组密码尚未还原为纯 Python**。已确认：CBC / 16 字节分组 /
   key 32 字节 / iv 16 字节 / 使用 AES 的 `xtime` 与 GF(2⁸) 乘法 / 密钥相关 S 盒
   由 RC4 式 KSA 生成。已证伪：标准 AES 全参数空间、SM4 全参数空间、
   5×7×4 的"自定义 S 盒 + 标准轮"组合。
   **下一步建议**：反汇编 `0x2d2fe4`（GF 乘法累加循环）所在函数，
   直接读出 MixColumns 矩阵与轮序；或 hook `0x2cd8b0` 的返回点，
   在表被覆盖前抓取 256 字节表内容，再据此复现轮函数。
2. **请求体 `P0.P1` 加密链路未打通**，导致需要 body 的 POST 只能过认证层。
   缺服务器 RSA 公钥与会话密钥封装规则。
3. **响应内容离线不可读**，需客户端私钥（运行时生成、未内嵌）。
   可在 App 运行态用 `decrypt_v5/mem_plaintext.py` 取明文。
