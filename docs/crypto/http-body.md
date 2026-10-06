# HTTP Body 加密 (apiEncrypt / P0.P1)

## 概要

HTTP 业务 API (视频列表/播放/登录等) 的 POST 请求体为**点分两段的 base64**：

```
<P0_b64>.<P1_b64>
```

| 段 | 内容 | 长度特征 |
|---|---|---|
| **P0** | RSA-2048 加密的"随机会话 key + iv" | **恒定 256 字节** (RSA modulus 长度), 每请求不同 |
| **P1** | AES-CBC(会话 key, iv, 业务 JSON) | 变长, 与业务数据量相关 |

服务器流程: 私钥解 P0 → 取得会话 key/iv → 解 P1 → 处理 → **用同一会话 key 加密响应** → 返回。
客户端 `apiDecrypt` 用内存中留存的会话 key 解响应。
错误响应 (鉴权失败/参数错误) 为明文 JSON。

## 调用链 (反汇编实证)

```
业务代码 → HttpClient.post(url, params) @0x213634 (async)
   │
   ▼
HeadersInterceptor._onRequest @0xa3bdc8        (直接 bl 调用, 地址实证)
   ├─ bl 0x716b7c   FFIUtils.clearKey()        # 清除上一请求的会话 key
   ├─ bl 0x7eee0c   FFIUtils.apiEncrypt(params)
   │     ├─ bl 0x715cb0  getRandomString()     # 随机会话 key
   │     ├─ bl 0x715cb0  getRandomString()     # 随机 iv
   │     ├─ AES-CBC(params)                    # → P1
   │     ├─ RSA-2048(key+iv)                   # → P0
   │     └─ return "<P0_b64>.<P1_b64>"
   └─ JsonCodec.encode({"data": <密文>, "authentication": <X-Token>})
```

- HeadersInterceptor 池引用 (pp+0x1dca8..0x1dcd8):
  `"APPID"` / `"ts"` / `"authentication"` / `"Authentication"` / `"x-version"` / `"tcs"` / `"nonce"` / `"data"`
- `api_encrypt` 亦为服务端下发配置标志 ("本 API 是否启用加密", GSignRuleData)

## 随机源 (V11 修正)

~~`getRandomString @0x715cb0` 固定种子、可离线复算~~ **假设已推翻**：
会话 key 由 **libcore native** 在 `api_encrypt` 内经 `RAND_bytes` (0x438d18,
种子源 `/dev/urandom`, init 阶段打开) 生成 —— Unicorn 实测 api_encrypt 恰好触发
一次 `RAND_bytes(buf, 16)`。Dart 侧 Random 与会话密钥无关。

key store: native 全局状态, `pthread_rwlock_*` 保护, 动作 `clear_key` 清空;
`api_decrypt` 在 store 为空时**直接回显不解密** (Unicorn 行为实证)。
emu 内 api_encrypt 信封形状: `{"action":"api_encrypt","payload":{"data":"<params JSON 文本>","path":"..."}}`
— `data` 必须是**字符串**; 传对象 → nlohmann `type_error` 且库内无 catch → 必崩。
emu 内该流程走完 RAND 后因缺服务端 RSA 公钥报 `{"code":400,"payload":{"status":2000}}`。

## 已排除的假设 (不要重复尝试)

| 假设 | 结果 |
|---|---|
| P0/P1 用监控 key qPwC 解 | ✗ (CBC/ECB × 多 IV 组合, printable oracle 0 命中) |
| P0/P1 用信令 key kFGT 解 | ✗ (同上) |
| pp.txt 全部 199 个 16 字符串 × 60 IV 候选 × AES-CBC | ✗ |
| pp.txt 全部候选 × RC4 (P1 非块对齐假设) | ✗ (仅 16B 短样本假阳性) |
| RSA 公钥内嵌 libapp/libcore/libloader/assets | ✗ 未找到 (PEM/DER/b64 全格式) |
| P1 长度 %16==8/12 → 流密码 | RC4 全候选未命中; 具体封装待定 |

P1 长度样本: 24/88/96/432/656/876 (均 %16∈{8,12}) ——**不是 AES-PKCS7 整块**,
推测 P1 b64 串内含额外字段 (长度前缀/签名尾), 或采用非标准分段, 待首装实验定论。

## 响应解密

响应对称使用该请求的会话 key。客户端 `apiDecrypt @0x607518` (async, Future<Map>)。

真机 hex 转储捕获的响应密文样本 (完整 b64, POST /app/video/record):

```
0zmWw/GSuunH9fjrFm0w7rA7APsTryskXva/9K+ZBW120qVXT2eFtR3EZNM4/KGx4nVeRv64ABb/
i80E7hG168gPkJffvuRqvGbh5MB8a/Ushlt9e1rSOZ/+jFoQbyPW93AEDQpUvTF2BHYZxWHEXDIWP
StMhUMVsJOON41lEp+vPRyf4RnxSXMTshU5egIg7fMBJoJ6R2P0JudqwnoHgXLlnDIZWXI+wZtjqX
bTljIIOR8S4jFyuijXIjHwcIBePH5sPzMkEjUDEHSJYQ/lfryFsk5y/jW4H+YoQPLEOpjf...
```

明文 JSON 结构 (来自调用侧类型签名 `Future<Map>` 与 GResponse.from 字段映射):

```json
{"code":200, "data": {...}, "message": "..."}
```

错误响应为明文 (未加密):

```json
{"code":403501,"message":"校验客户端签名失败，请重启app尝试"}
{"code":403502,"message":"检测到设备时间异常，请调整到正确时间后重新打开 App尝试"}
{"code":30000,"message":"解码异常:authentication is empty"}
```

## 抓取/解密方法

```bash
# 1. hook apiDecrypt.enter, dump x1 (密文字符串对象) 1600B hex
# 2. python 端解析: tags@0-3, len(Smi)@8-11, data@16..16+len
# 3. 会话 key 获取: hook getRandomString leave 或运行时内存扫描 (待定)
```

---

## 第三阶段复核 (2026-09-29) —— 响应体结构与可用解密路径

### 响应体同样是 `<P0_b64>.<P1_b64>`

对 17 个唯一端点 / 41 条真实响应做结构断言（脚本 `research/deliverables/decrypt_v5/chan3_http.py`）：

| 断言 | 结果 |
|---|---|
| P0 长度 | **恒 256 字节**（RSA-2048 输出）；唯一例外是 `/app/channel/` 的 301 重定向（P0=35B 明文 HTML） |
| P0 唯一性 | 16 条响应的 P0 前 8 字节**互不相同** |
| P1 长度 | 16 个端点全部为 16 的倍数（48B–7200B） |
| body 形态 | 恒为 `<P0_b64>.<P1_b64>` 点分两段 |
| GET 请求 | `req_body_len = 0`（无 body，仅靠 `authentication` 头） |

⇒ P0 = `RSA-2048(app 公钥)(session key ‖ iv)`，**服务端逐请求换新会话密钥**。
app 侧私钥由 `apiDecrypt @0x607518` 使用；该私钥为**运行时生成、未内嵌**
（`shared_prefs` / `files` 与 libapp/libcore/libloader/assets 全格式搜索无果）。
~~以上"运行时生成"存疑~~ V11 更正：响应 P0 可用 `priv_from_go.pem` **静态**解封
（134/134），见文末 V11 定论；该私钥来源为 Go 侧实现。

### 会话密钥离线恢复：未达成（负结果）

- 用 MON/SIG 两条通道密钥 × 4 种 IV 解 `authentication` 的 96B 密文 → 全部失败；
- 内存滑动窗口暴力搜 AES 会话 key（宿主 `libcrypto.so` 的 `AES_set_decrypt_key`/`AES_decrypt`
  经 frida NativeFunction 调用，判据 = IV=0 解密后第 2 块全可打印且末块 PKCS7 合法）
  → 吞吐仅 **~110 KB/s**，锚点邻域 16MB 扫描 0 命中；全量 1.4GB 推算需 ~3.5 小时，不具可行性。

### 可用路径：内存取明文（已验证）

`research/deliverables/decrypt_v5/mem_plaintext.py` —— frida attach → 扫 `rw-`/`rwx` 匿名区间 → 按明文标记定位
→ 邻域读窗口 → 花括号配平 → hex 回传 → Python UTF-8 解码。

```bash
python research/deliverables/decrypt_v5/run_list.py --limit 20     # 真实列表 total=2142
python research/deliverables/decrypt_v5/run_play.py --extract --verify   # 真实播放直链
```

**前提**：必须在 app 刚完成请求时扫描（空闲后明文串被 GC，早期"0 命中"即此因）。

---

## V11 定论 (2026-10-02) —— 响应解密的完整模型与边界

### 已证实

1. **响应 P0 = RSA-2048 PKCS1-v1.5(pub_from_go, K16)，离线 100% 可解封**
   (`priv_from_go.pem`，134/134)。K16 = 16 字符大写字母数字，**每响应换新**
   （8 条 device-base 响应 K16 互不相同，live 回放亦得新 K16）。
2. ~~**响应 P1 的密钥不是 K16**~~ **【V13/V14 更正】响应 P1 的密钥就是 K16resp 本身**：
   `key = K16resp`、`iv = reverse(K16resp)`，密码为**自研分组密码 E**（不是 AES）。
   本节及下方"负结果"表的整块 AES 网格是**用错密码**做的，全部作废。
   实测：`priv_from_go.pem` 解出 K16resp 后，用 `decrypt_e` 逐块 tweak 求逆，
   35/35 端点解出合法 JSON（见文末 V14）。
3. 请求 P0 = RSA(**服务端**密钥对, key+iv) —— 客户端/离线均不可解（`priv_from_go`
   解请求 P0 = 0/13，PKCS1/OAEP/raw 全试）。
4. 解密器: `research/deliverables/decrypt_response.py`
   - `unwrap`: P0 → K16（离线，100%）;
   - `decrypt --key --iv`: P1 → JSON（key/iv 需 live hook，见下）;
   - `selftest`: 复跑 8 组已证伪 oracle（期望全 0）。

### 负结果 — 历史抓包 (134 条) 离线不可解，不要再试

| 假设 | 判据 | 结果 |
|---|---|---|
| P1 = AES-CBC(K16, iv, JSON) | crib `{"code` 首块 + block2 可打印链 (iv 无关) | 0/134 |
| 同上 (key=K16rev/md5(K16)/md5hex[:16]/sha256[:16]) | 同上 | 0/134 |
| CBC+PKCS7 (iv 无关末块判据) | key=K16 及上述全部变换 | 0/134 (噪声级) |
| CBC+zero/space/X9.23/7816 padding | key=K16 | 0/134 |
| ECB / CTR / CFB / OFB (iv=K16 或 0) | 首块 JSON 判据 | 0/134 |
| P1 = IV‖C 或 C‖IV (IV 前后置) | PKCS7 + 首块 JSON | 0/134 |
| 内存 dump 含会话 key | 3.7M 个可打印 16B 窗口 × 双块可打印 oracle | 0 命中 |
| 镜像内嵌 16/32 字符串是 key/iv ('Ee&AVzdgru^$hX%j' 等) | 全组合 key×iv×模式 | 0 命中 |

### 可行解密路径 (live)

抓**请求**时同步取 key/iv，响应即可解：

```bash
# 方案 A: hook 业务 EVP_EncryptInit_ex (libcore+0x387da4), x3=key, x4=iv
#   区分: 信封层调用 key 恒为 qPwClBj7j7ZQraSm/p3JdVQl3q7WQJIgG → 过滤掉
# 方案 B: hook RAND_bytes (libcore+0x438d18), api_encrypt 恰好产生 16B key;
#   iv 的获取点同理需再定位 (emu 中第二次 RAND 未及触发, 需先补齐服务端公钥)
python research/deliverables/decrypt_response.py decrypt --file resp.txt \
    --key <KEY16> --iv <IV16>
```

emu 复现: `research/toolchain/emu_unwind.py --action api_encrypt --pshape datakey
--clear-first`（已证实 RAND 触发点与信封回写链路；补齐服务端公钥后可全链路跑通
并做 api_encrypt → api_decrypt 双调用闭环）。

---

## V12 收官（2026-10-03）：f(K16) 破解 —— 请求已可伪造

> **本文档上方的"P1 = AES-CBC"模型及全部 AES 网格负结果作废**：密码选错了，
> 业务 P1 用的不是 AES，而是 libcore 自研分组密码 E（与 authentication 头同一算法）。

### 结论

```
请求体 = CUSTOM_B64(P0) . CUSTOM_B64(P1)
  P0 = RSA-2048-PKCS1v1.5(server_pub, K16)          K16 = 客户端 16 字节原生随机
  P1 = CBC-E( key = K16 , iv = reverse(K16) , PKCS7(params) )
响应体同构
  P0 = RSA(pub_from_go, K16resp)                    priv_from_go.pem 可离线解
  P1 = CBC-E(同一会话 key/iv, ...)                   AES 全参数空间 0 命中
```

- **f(K16) = (key = K16, iv = K16[::-1])** —— 设备动态轮就此闭环。
- 密文长度 = `ceil((len(params)+1)/16)*16`（CBC + PKCS#7 恒补满块）。
  实测：`/app/video/device-base` params ≤15B → P1 16B；`/app/video/record` → 96B。

### 证据链

1. **E 加密预言机**（`research/captures/rsa_scan/e_oracle.py`）
   复用 Unicorn 的 auth 编码管线 `0x304eb0`：`fix_long_string(0x688130,key)` /
   `(0x688148,iv)` 注入任意密钥，A1 阶段 hook 覆写明文缓冲区。
   回归自检：pt=104B 时输出首块 == `CT0 = 23754ae9d0cbe749f5441e769b45143e` ✓
   （管线要求明文长度为 4 的倍数，forge 侧用空格补齐，JSON 允许尾随空白。）

2. **服务端网格**（`forge_v6.py`，14 key × 9 iv = 126 组合，K16 每次新随机）
   **唯一命中 `K16|K16rev`**：HTTP 200 + 正常加密响应体；
   其余 125 组全部 `{"code":800131,"message":"通讯失败"}`（P1 解不开）。
   复现 3/3，`forge_v7.py` 端到端：HTTP 200 → 响应 P0 解出 K16resp（如 `V4QW3MAHJ5AQKVW6`）。

3. 静态旁证：E（`0x2d6f78`）仅被 `0x303df0`（业务 P1）与 `0x3050f8`（auth 头）调用，
   与"两者同一算法"一致；KSA `0x2cd8b0` 为间接 `blr` 调用。

### 踩坑记录（重要）

- 宿主机 `HTTP_PROXY/HTTPS_PROXY=127.0.0.1:4816`（沙箱出口）会劫持 urllib，
  发往目标 IP 报 `gaierror`；须用 `http.client` 直连。
- Git Bash 会把 `--path /app/...` 改写成 `C:/.../app/...` → 服务端 404。
  设备/HTTP 命令一律 `MSYS_NO_PATHCONV=1`。
- 宿主机若有**旧代理残留**占用 27990（Windows 允许 SO_REUSEADDR 双绑），
  新代理收不到连接 → 抓包为空。先 `netstat -ano | grep 27990` 清干净。

### 设备侧内存猎取（`live_hunt_loop.py`）

低延迟方案：常驻 frida 会话 + 监听抓包文件，一有响应立刻扫内存（毫秒级），
否则 K16resp / 密文缓冲区数秒内即被回收。已实测定位到：
`K16resp` ASCII 令牌本体、响应 P1 密文缓冲区（`0x7631...` 堆区）。
注意：**frida 在 App 启动早期 attach 会触发 DartWorker SIGSEGV（code 128）**，
须等 App 完全起来（MainActivity 稳定）后再挂。

### 仍缺 / 未达成

- ~~**离线解密响应 P1 需要 E 的逆函数**~~ **【V13 已解决】**：`decrypt_e.py` 用标定法
  实现了 E 的逐块逆，响应 P1 **完全离线可解**（见文末 V13/V14）。
- **逐块 tweak `CONST_b`/`Cb_b` 的闭式公式仍未还原** → 每个 (K, nblk) 需一次
  等长 dummy 标定（≈1.2 s/块）。这是当前唯一的效率瓶颈。
- 历史抓包：请求 P0 用服务端私钥加密、不可解 → 未知 K16req → 仍无法离线解
  （但**响应侧**不受影响，响应用自己的 K16resp）。

---

## V13 收官（2026-10-04）：E 的**逐块 tweak** 结构与离线解密交付物

### 单块结构（确证）

```
E(x) = T( SR( SB( AES9( T(x) ^ rk0 ) ) ) ) ^ C(K)
```
`T` = 4×4 字节转置（row-major ↔ column-major）；`AES9` = 标准 AES-128 前 9 轮；
`rk0..rk9` 为标准 AES 密钥调度；`C(K)` 只依赖 K（一次预言机调用即可定出）。

### 多块结构（本轮修正了 V12 的"纯 CBC"模型）

E 的**分块**加密**不是标准 CBC**。实测（hook 轮驱动 `0x2da498` 读回每块真输入 `x_b`）：

```
块 0 :  x_0 = pt_0 ^ iv                       ct_0 = E(x_0)
块 b :  x_b = pt_b ^ ct_{b-1} ^ CONST_b       ct_b = E(x_b) ^ Cb_b        (b >= 1)
```

- `CONST_b` / `Cb_b` 是**只依赖 (K, b)** 的逐块 tweak：与明文、消息长度**无关**（两两实测）。
- 递推：`CONST_{b+1} = CONST_b ^ Cb_b`（b≥1），即两条序列由单序列决定。
- 代码路径：块循环 `0x2d7440` → `extract(0x2d9ad4)` → **`neon(0x2d9ed0)` 在此把
  `pt_b` 变成 `x_b`** → `reorder(0x2da1c8)` → 轮驱动 `0x2da498`。`0x2d9ed0` 为
  OLLVM 展平 + NEON 位运算（表 `0x400024bdf000+{0xa68,0xa88,0xaf0,0xaf8}`）。

### 负结果（不要重复尝试）

`CONST_b`/`Cb_b` **不是**：任何轮密钥 `rk_j`(j≤44) 或其 `T()`/`F()`/`E()` 变换、
`F`/`E` 的迭代或自 XOR 递推、`E(0/iv/K/counter)` 形式的 CTR keystream、
标准 AES-128 的 CTR keystream、`F(ct_{b-1})`、明文相关项。逐块 tweak 的**闭式
公式尚未还原**（生成式在 OLLVM 化的 `0x2d9ed0` 内，非查表——16B 常量不在内存中）。

### 交付物：`research/deliverables/decrypt_e.py`

```python
from decrypt_e import decrypt
pt = decrypt(P1_bytes, K16_bytes)      # -> 明文 (已去 PKCS#7)
```

**标定法**（因公式未还原）：对同一 K 用 Unicorn 跑一次等长 dummy 加密，
hook 轮驱动读回每块 `x_b`，即得 `CONST_b = x_b ^ dummy_b ^ ct_{b-1}`、
`Cb_b = ct_b ^ F(x_b) ^ C(K)`（仅依赖 (K,b)，故对任意密文成立）。
随后逐块 `x_b = F_inv(ct_b ^ C(K) ^ Cb_b)`、`pt_b = x_b ^ ct_{b-1} ^ CONST_b`。
全流程**离线**（libcore.so + Unicorn，无设备/App/网络）。

- 注意：`EOracle.enc` 的 Unicorn `timeout=120s` 对长消息不够（≈1.3 s/块），
  交付物内改用 `3_000_000_000 µs`。
- 驱动调用数 = `2*(nblk+1)`（每块 2 次，取偶数下标为块输入）。

### 验证（`tmp_pairs.json`）

`RESULT ok=9 bad=0 skip=1` —— 9 个含 K16 的样本全部解出合法 JSON
（含 4274B / 1913B 大样本）；`hit=298` 样本 `p1_hex` 被截断（110B，非 16 倍数）跳过。

---

## V14 收官（2026-10-04）：端到端全链路（请求伪造 + 响应解密），35 接口全绿

### 1. 响应密钥的重大更正（本轮）

V11 曾断言"响应 P1 的密钥不是 K16"，那是**用 AES 做网格**得出的（见 V11 负结果表）。
本轮确证：

```
响应体 <P0_b64>.<P1_b64>
  P0 = RSA-2048-PKCS1v1.5(pub_from_go, K16resp)   --priv_from_go.pem-->  K16resp  (离线, 100%)
  P1 = E( key = K16resp , iv = reverse(K16resp) ) 逐块 tweak 密文
       --decrypt_e 逐块求逆--> 明文 JSON
```

即**响应密钥 = K16resp 本身**（不是请求的 K16req，也不是内存里的会话 key），
密码同为自研分组密码 E。V11 的 AES 网格因此整块作废。

### 2. 端到端交付物：`research/deliverables/jcy_client.py`

```python
from jcy_client import JcyClient
cli = JcyClient()
r = cli.request("GET", "/app/video/list?channel=1&sort=weight&limit=6&page=1")
print(r["json"])        # -> 解密后的真实业务 JSON
```

* 请求头 `authentication` 由 `authgen.py` **本地离线生成**（只与 ts 绑定）；
* POST body = `CUSTOM_B64(RSA(server_pub, K16)) . CUSTOM_B64(E(K16, rev(K16), PKCS7(params)))`；
* 响应自动 `priv_from_go.pem` 解 K16resp + `decrypt_e` 解 P1 → `r["json"]`。
* **全流程离线**，无需设备 / App / frida。

### 3. 一键服务：`authgen_server.py` 新增 `/decrypt`

```bash
./.venv/Scripts/python.exe research/deliverables/authgen_server.py --warmup
# POST /decrypt   body = "<P0_b64>.<P1_b64>"
#  -> {"ok":true,"k16resp":"...","json":{...},"plain":"...","plain_len":N}
```

### 4. 35 接口端到端实测

驱动：`research/tmp_all_endpoints_par.py`（多进程并行，6 worker，可断点续跑）。
逐条结果落盘 `research/tmp_all_endpoints.json`，矩阵见
[`../api/live-matrix.md`](../api/live-matrix.md)。

| 结论 | 说明 |
|---|---|
| 真实业务数据 | 全部认证层通过端点均解出 `{"code":20000,...}` + 真实 data |
| 服务端错误 | 仍返回 HTTP 200，业务码在明文/解密后的 JSON body |
| 404 端点 | `/app/v2/config/host`、`/app/playaddr/v4/client`、`/app/login/smscode` |
| 特例端点 | `/app/upgrade`：大写 `Authentication`、216B 裸二进制 body、非 P0.P1 |
| 301 端点 | `/app/channel/` → 301 跳转，无加密体 |

### 5. 效率瓶颈与提速

逐块标定 ≈ **1.2 s/块**（Unicorn 模拟 ARM64）。大响应（如 search 34KB ≈ 2174 块）
单接口就要 40+ 分钟，故实测驱动改为**多进程并行**（12 核，6 worker → 约 6×）。
根治需还原 `CONST_b`/`Cb_b` 闭式公式（仍未达成）。

> 关键坑：`EOracle.enc` 的 Unicorn `timeout` 单位是 **µs**，长消息必须放大到
> `3_000_000_000`；否则中途 `StopIteration`/捕获不足，报 `captured X < nblk`。

---

## V15 收官（2026-10-04）：**28× 引擎提速** + `Cb_b` 生成规则还原

### 1. 根因：全镜像逐指令 hook（本轮最大发现）

`research/toolchain/v13.py` 的 `Emu3.__init__` 装了

```python
self.uc.hook_add(UC_HOOK_CODE, self._on_code, begin=DEV_BASE, end=DEV_BASE + IMG_SIZE)
```

该 hook 覆盖**整个 8 MB 设备镜像**且每指令回调一次。Unicorn 只要存在
`UC_HOOK_CODE` 就会让 QEMU 对**每个 translation block 插桩**，于是标定被拖到
≈ **0.54 s/块**。实测一次 16 块标定触发 **16 934 383 次** 回调（≈106 万条指令/块，
OLLVM 膨胀所致），而 `_on_code` 只往 `self.trace` 里塞地址——纯诊断用途。

### 2. 修复

`v13.py`：默认**不装**该 hook，改由 `enable_trace()` 显式开启（仅 v13 CLI 诊断
路径 `run_once()` 调用）。`_on_code` 另加 `trace_on` 门控兜底。其余引擎/脚本
（`emu_v14.Emu4`、`emu_unwind.py`、`probe_*.py`、`authgen`、`decrypt_e`）
经 grep 确认**无人读取 `e.trace`**，无回归。

### 3. 实测提速

| 场景 | 修复前 | 修复后 | 提速 |
|---|---|---|---|
| 标定 16 块 | 8.64 s（0.5402 s/块） | 0.31 s（0.0193 s/块） | **28×** |
| 真实信封 `video_list_demo.raw`（P1=8624B / 539 块） | 450.53 s | **9.25 s** | **48.7×** |
| `jcy_fetch.py` 端到端（含取签+发请求+解密） | ~549 s | **9.8 s** | **≈56×** |

明文与基线**逐字节一致**；`decrypt_e.py` 自检 9/9 合法 JSON、0 失败。
`node scripts/validate-structure.mjs` 通过。

### 4. `Cb_b` 生成规则已还原（V13 遗留问题的一半）

实测 22/22 成立（`K = 000102…0e0f`，`tmp_tweak2.py` / `tmp_recur.py`）：

```
Cb_b = CONST_{b+1} ^ CONST_1        (b >= 0；CONST_0 = Cb_0 = 0)
```

即**输出 tweak 完全由输入 tweak 序列决定**，每块只剩一个独立未知量 `CONST_b`。
等价改写（把 tweak 从 CBC 里剥离出来）：

```
X_0   = pt_0 ^ iv
X_{b+1} = pt_{b+1} ^ E(X_b) ^ CONST_1        # X 递推**不含** CONST_b
ct_b  = E(X_b) ^ CONST_{b+1} ^ CONST_1
```

`decrypt_e.calibrate()` 已内置该不变式自检（`EDecryptor.invariant_ok`），
4 组不同 K 全部 `True`。

### 5. 仍未还原：`CONST_b`（负结果汇总，勿重复）

`CONST_b` 是 `(K, b)` 的**高熵函数**，由有状态生成器 `0x2d9ed0`（OLLVM 展平 +
NEON 位运算 + `0x671630` 间接跳转表）产出。以下假设**全部证伪**：

| 假设 | 结果 |
|---|---|
| `CONST_{b+1} = E(CONST_b) [^ 常量]` | 0/22 |
| `CONST_{b+1} = E(CONST_b ^ iv/^CONST_1/^C(K))` | 0/22 |
| `CONST_b = E(块号编码)`（40+ 种编码） | 0 命中 |
| `CONST_b` 与 AES 扩展密钥调度（`rk_{10+b}` 等）相关 | 0 命中 |
| `A_b = E⁻¹(CONST_b)` 呈结构（`A_{b+1} ^ A_b` 恒定 / `A_{b+1}=E(A_b)`） | 22 个不同值，无结构 |
| `CONST_b` 与 K 无关（可预计算表） | `CONST_b(K1)^CONST_b(K2)` 11 个不同值 → 强依赖 K |
| `CONST_b^CONST_1` 是低维 LFSR | GF(2) 秩 62–63/128 ≈ 样本数（随机型） |

**结论**：纯 Python 化 `CONST_b` 必须真正逆出 `0x2d9ed0` 的算法（有状态 NEON
生成器），非公式拟合可解。当前 `0.019 s/块` 的仿真标定已是 Unicorn 执行速度上限
（≈5500 万条指令/秒），继续提速只能靠算法还原或换更快的模拟器。

