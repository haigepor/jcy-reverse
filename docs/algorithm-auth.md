# authentication 头算法：原理与用法

> 本文是 `authentication` 请求头生成算法的**权威说明**。
> 对应交付脚本：[`research/deliverables/authgen.py`](../research/deliverables/authgen.py)；
> 验证记录：[`research/reports/VERIFICATION.txt`](../research/reports/VERIFICATION.txt) 第四阶段 [G1]–[G8]。

---

## 一、算法总览

```
authentication = CUSTOM_B64( E( CUSTOM_B64( S ) ) )
```

| 步骤 | 输入 | 输出 | 说明 |
|---|---|---|---|
| ① 构造输入串 | `ts`（毫秒时间戳） | `S`（78 字节） | 见 §2.1 |
| ② 内层编码 | `S` | `A1`（104 字节） | 标准 base64 → 自定义字母表重映射 |
| ③ 分组加密 | `A1` | `BODY`（112 字节） | CBC 模式，16 字节分组 |
| ④ 外层编码 | `BODY` | `authentication`（152 字符） | 同 ② |

长度关系：`78 --b64--> 104 --E--> 112 --b64--> 152`

---

## 二、输入与输出

### 2.1 输入串 `S`

由 `libcore.so` 的 `__vsnprintf_chk`（vaddr `0x306a3c`，调用点 `0x306478`）拼出，
格式为 `%s-%ld-Android-%s-%s-%s`：

```
S = "{code_version}-{ts}-Android-{app_version}-{device_fp}-{client_appid}"
  = "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default"
```

| 字段 | 取值 | 来源 |
|---|---|---|
| `code_version` | `3.0.0.8` | libcore.so 常量 |
| `ts` | 毫秒时间戳 | 请求头 `ts`，两者必须一致 |
| `app_version` | `1.5.8.0` | APK versionName |
| `device_fp` | 32 位十六进制 | 设备指纹（**随安装实例变化**） |
| `client_appid` | `default` | libcore.so 常量 |

### 2.2 自定义 base64 字母表

```
5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj
```

标准字母表 `A–Za–z0–9+/` 的第 i 个字符 → 上表第 i 个字符。
位于 `libcore.so` 数据段：singleton（vaddr `0x400025089640`）+0x18 指向的向量
`{0x737e41dc2a40, 0x737e41dc2a80, 0x737e41dc2a80}`，即设备内存 `0x737e41dc2a40` 处的 64 字节。

> 编码函数即 libcore 的 `A`（vaddr `0x2dc524`，包装 `0x2dbf9c`）。
> 它以 3 字节为单位取输入、输出 4 字符，行为与 base64 完全一致。

### 2.3 分组密码 `E`

| 项 | 值 |
|---|---|
| 调用点 | vaddr `0x3050f8` → 函数 `0x2d6f78` |
| 模式 | **CBC**（已用链接性质实验证明，见 §4.2） |
| 分组 | 16 字节 |
| 填充 | 明文 104 字节 → 补齐至 112 字节 |
| 输出 | 112 字节密文（**不含 IV**） |
| key | `ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv`（32 字节，libcore vaddr `0x688130`） |
| iv | `WonrnVkxeIxDcFbv`（16 字节，libcore vaddr `0x688148`） |

**它不是标准 AES，也不是 SM4**（见 §4.3）。它是 libcore.so 内的自定义实现：
以 AES S-box 为初值、用 key 做 RC4 式 KSA 生成密钥相关的 256 字节 S 盒
（函数 vaddr `0x2cd8b0`），再配合私有轮函数。

### 2.4 输出 `BODY` 结构

```
BODY[  0: 16] = ct0       恒定 23754ae9d0cbe749f5441e769b45143e
BODY[ 16: 48] = O[0:32]   服务端实际校验的部分，只依赖 ts
BODY[ 48:112] = O[32:96]  依赖 device_fp 等
```

---

## 三、调用链（libcore.so vaddr）

```
0x305d94  auth 顶层生成器（被 0x30affc 调用）
   └─ 0x306a3c  __vsnprintf_chk 拼接 S
0x306548  调用点
   └─ 0x304eb0  auth 编码管线（x0=S, x1=&key_str, x2=&iv_str）
        ├─ 0x304fb4  bl 0x2dbf9c   A1   = A(S)        （A = CUSTOM_B64 编码器）
        ├─ 0x3050f8  bl 0x2d6f78   BODY = E(A1)       （CBC 分组密码）
        └─ 0x3051b4  bl 0x2dbf9c   AUTH = A(BODY)
```

---

## 四、判定依据（为什么是现在这个结论）

### 4.1 A 是 base64
`A` 的输出长度 = `4 × ceil(len/3)`：78 → 104、112 → 152，且内层循环
`x21 += 3`（`0x2dc894`），每轮输出 4 字节。字母表取自 singleton 成员。

### 4.2 E 是 CBC
受控实验（通过 Unicorn 执行原函数，自由指定明文块）：

```
run1: P = A1                    → ct0
run2: P[16:32] ⊕= d             → ct1
run3: P[32:48] ⊕= ct0[16:32] ⊕ ct1[16:32]
结果: run3.ct[32:48] == ct0[32:48]   ✅ 逐字节相等
```

即 `ct[i] = E_k(P[i] ⊕ ct[i-1])`，对 i=1、i=2 均成立 ⇒ CBC。

### 4.3 E 不是标准 AES / SM4
| 检验 | 结果 |
|---|---|
| AES 全模式（CBC/ECB/CFB/OFB/CTR/CFB8/OPENPGP）× enc/dec × 10 组 key 候选 × 5 组 iv 候选 × 6 组明文候选 | 0 命中 |
| 恒定 IV 判据（543 条语料要求 `D_k(ct0) ⊕ P0` 恒定） | 全部候选不恒定 |
| SM4（自实现，已过 GB/T 32907-2016 标准向量） | 0 命中 |
| 哈希构造（md5/sha1/sha256/sha512/sha3/blake2 × 9 组 key 的 HMAC/拼接） | 0 命中 |
| **AES 结构 + 自定义 S 盒**（5 种 S 盒 × 7 种密钥 × 4 种 IV = 140 组合） | 0 命中 |
| 运行时 S-box 读取监视 | AES S-box `0x1dfc00` 被读 32 次；inv-S-box / Td0 / SM4 S-box 均 0 次 |
| `0x2cd8b0` 反汇编 | 拷 AES S-box 到栈 + 以 (dest, key) 做 RC4 式 KSA（`j=(j+dst[i]+key[i%len])&0xff; swap`） |

⇒ 自定义分组密码。为求结果精确，`authgen` **直接以 Unicorn 执行 libcore.so 原函数**，
不做算法近似。

### 4.4 E 已知的结构线索（供后续还原）
- `0x2d2f0c` 的代码是 `w0 = 0x1b ^ (w1 << 1)`，即 **AES 的 `xtime`**（GF(2⁸)×2）
- `0x2d2fe4` 是 GF(2⁸) 乘法累加循环，实参常量为 `2,4,8,…,0x11b,3,6,0xc,…`（MixColumns 系数）
- `0x2cd8b0` 被调用两次，分别以**自定义字母表（64B）**和**key（32B）**为 KSA 密钥，
  生成两张密钥相关的 256 字节表
- 结论：E 使用了 AES 的**域运算与 S-box 素材**，但轮结构 / 密钥扩展 / 轮序被改过

---

## 五、用法

### 5.1 命令行

```bash
# 回归自检（对固化真机向量）
./.venv/Scripts/python.exe research/deliverables/authgen.py --selftest

# 生成（默认当前时间）
./.venv/Scripts/python.exe research/deliverables/authgen.py

# 指定 ts（毫秒）
./.venv/Scripts/python.exe research/deliverables/authgen.py --ts 1790755350520

# 生成并打真实服务器
./.venv/Scripts/python.exe research/deliverables/authgen.py --test-server
./.venv/Scripts/python.exe research/deliverables/authgen.py --test-server --path /app/banners/0

# 指定 device_fp（默认取当前设备镜像中的值）
./.venv/Scripts/python.exe research/deliverables/authgen.py --fp 16613a7076284a15bc723d018bcd67e1
```

### 5.2 Python API

```python
import sys
sys.path.insert(0, "research/deliverables")
import authgen as AG

ts   = 1790755350520
auth = AG.gen(ts)              # → 152 字符的 authentication 头
body = AG.custom_b64d(auth)    # → 112 字节 BODY
assert body[:16].hex() == "23754ae9d0cbe749f5441e769b45143e"

# 直接打服务器
status, reason, data = AG.probe_server(ts, auth, nonce="12345678", path="/app/config")
```

### 5.3 关键常量

| 常量 | 值 |
|---|---|
| `ALPHABET` | `5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj` |
| `AES_KEY` | `ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv` |
| `AES_IV` | `WonrnVkxeIxDcFbv` |
| `CODE_VERSION` / `APP_VERSION` / `CLIENT_APPID` | `3.0.0.8` / `1.5.8.0` / `default` |
| `APPID_HEADER` | `4150439554430529` |

---

## 六、验证结果

### 6.1 服务端实测（`43.145.33.254:27990`）

| 用例 | 结果 |
|---|---|
| `GET /app/config`（正例） | **HTTP 200**，2905 字节加密业务数据 |
| `GET /app/banners/0`（正例） | **HTTP 200**，7493 字节 |
| `GET /app/channel?top-level=true`（正例） | **HTTP 200**，3889 字节 |
| 篡改 auth 第 41 字符 | `{"code":403501,"message":"校验客户端签名失败…"}` |
| 空 auth | `{"code":30000,"message":"解码异常:authentication…"}` |
| 有效 auth + ts 回退 1 小时 | `{"code":403502,"message":"检测到设备时间异常…"}` |

> ⚠️ 该服务端 **错误也返回 HTTP 200**，业务码在 JSON body 里；
> 「成功」的表现是 body 为加密密文（`<P0_b64>.<P1_b64>`）而非明文错误 JSON。

### 6.2 真实语料

- `ct0` 恒定：543 条 norm 样本 `BODY[0:16]` 全部等于 `23754ae9d0cbe749f5441e769b45143e`
- **`O[0:32]` 全量核验：485/485 唯一 ts 全部 MATCH，0 失败**（耗时 1812.5 s）

### 6.3 关于语料 `O[32:96]` 不一致

语料抓取于 2026-09-29，而设备内存镜像导出于 2026-09-30，**属不同 App 实例、device_fp 不同**。
分块定位证明差异恰好始于 `ct3`（覆盖明文 `A1[48:64]` = `input[36:48]`，含 device_fp）；
`O[0:32]` 只依赖 `input[0:36]`，因此可完全对齐。当前实例的 device_fp 已由服务端 200 实测确认正确。

---

## 七、注意事项

1. **`ts` 必须新鲜**。服务端校验时间窗口，`ts` 回退 1 小时即 `403502`。
   实测窗口约在 2 分钟以内（旧记录：`+120s` 通过、`+300s` 拒绝）。
2. **auth 不绑定路径/query**。同一个 auth 可跨 22 个端点使用（已实测）。
   早期文档中「auth 绑定路径」的结论是错的，其失败实为同时改了 `ts` 或取了过期 auth。
3. **端点方法必须按真机抓包**。`/app/users/task`、`/app/messagebox/*`、`/app/history*`、
   `/app/config/*`、`/app/video/*` 均为 **POST**，用 GET 会得到 404。
4. **响应内容离线不可读**。服务端 P0（256 字节 = RSA-2048）包裹的是给客户端的会话密钥，
   需客户端私钥；该私钥运行时生成、未内嵌于 APK/so。要读明文需在 App 运行态取
   （见 `research/deliverables/decrypt_v5/mem_plaintext.py`）。
5. **需要加密 body 的 POST 只能过认证层**。`play-connect` / `record` / `device-base` 等
   的业务参数需要请求体 `P0.P1` 加密链路（服务器 RSA 公钥 + 会话密钥），该链路尚未打通。
6. **单次生成约 4–6 秒**，瓶颈是 Unicorn 的指令解释开销，而非内存加载。
7. **依赖 Unicorn 与 libcore.so 原函数**。E 尚未还原为纯 Python 等价实现；
   若需迁移到其它环境，必须一并带上 `research/artifacts/`。
8. **服务端错误也返回 HTTP 200**，判定成功要看 body 是密文还是明文错误 JSON。

---

## 八、依赖与工程化（2026-09-30 更新）

### 8.1 分层

| 层 | 文件 | 职责 |
|---|---|---|
| 纯逻辑 | [`src/tools/jcy_protocol/auth.py`](../src/tools/jcy_protocol/auth.py) | 字母表编解码、输入串构造、body 拆分、头拼装；定义 `EBackend` 协议。**零大文件依赖** |
| 后端 + CLI | [`research/deliverables/authgen.py`](../research/deliverables/authgen.py) | 以 Unicorn 执行 libcore.so 实现 `E`，提供命令行 |
| 测试 | `tests/test_auth_pure.py`（纯逻辑）、`tests/test_authgen.py`（端到端） | 回归保障 |

依赖方向保持单向：`research/` 依赖 `src/`，`src/` **不**依赖 `research/`。
未来若把 `E` 还原为纯 Python，只需实现一个满足 `EBackend` 的类即可无缝替换。

### 8.2 最小依赖集

原本需要 813 个设备内存区域（424 MB）。用 `UC_HOOK_MEM_READ` 统计管线**实际读取**
的区域后，只需 **5 个区域 / 28.6 MB**：

| 文件 | 基址 | 大小 |
|---|---|---|
| `0235.bin` | `0x40002506b000` | 0x1d000 |
| `0092.bin` | `0x6fc6a000` | 0x140a000 |
| `0236.bin` | `0x400025088000` | 0x178000 |
| `0381.bin` | `0x737e41c00000` | 0x400000（自定义字母表所在区） |
| `0255.bin` | `0x737ddfaf1000` | 0x300000 |

最小集与全集结果**逐字节一致**（已用 `--selftest` 与 `--test-server` 验证）。
统计脚本：`research/toolchain/probe_regions.py`。

### 8.3 Python API

```python
import sys
sys.path.insert(0, "src"); sys.path.insert(0, "research/deliverables")
from jcy_protocol import auth as A
import authgen

auth = authgen.gen(1790755350520)        # 152 字符
body = A.body_of(auth)                   # 112 字节
parts = A.split_body(body)               # {"ct0","o32","o64","o96"}

# 只用纯逻辑 + 自定义后端（无需 Unicorn）
class MyE:
    def encrypt(self, a1: bytes) -> bytes: ...
header = A.generate(1790755350520, authgen.DEVICE_FP, MyE())
```
