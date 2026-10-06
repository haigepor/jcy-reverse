# 囧次元 端到端加解密全链路（完整分析记录）

> 本文汇总 **请求侧 + 响应侧** 的完整加解密链路、算法结构、全部负结果与工具交付物。
> 细粒度时间线见 [http-body.md](../crypto/http-body.md)（V11→V14）、
> [reverse-journal-auth.md](../reverse-journal-auth.md)、[algorithm-auth.md](../algorithm-auth.md)。

## 一、一条请求的完整生命周期

```
                     ┌───────────────── 客户端（离线可复现）─────────────────┐
请求头 authentication = CUSTOM_B64( E_auth( CUSTOM_B64( S ) ) )      ← authgen.py
        S = "3.0.0.8-{ts}-Android-1.5.8.0-{device_fp}-default"
        E_auth 用固定 key/iv：ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv / WonrnVkxeIxDcFbv

POST body = CUSTOM_B64(P0) . CUSTOM_B64(P1)
        K16 = 16B 原生随机
        P0  = RSA-2048-PKCS1v1.5(server_pub, K16)          ← server_pub_2048_live.pem
        P1  = E( key = K16 , iv = reverse(K16) , PKCS7(params) )

                     ┌───────────────── 服务端响应 ─────────────────┐
响应体 = CUSTOM_B64(P0) . CUSTOM_B64(P1)
        P0  = RSA-2048-PKCS1v1.5(pub_from_go, K16resp)     ← priv_from_go.pem 解出 K16resp
        P1  = E( key = K16resp , iv = reverse(K16resp) ) 逐块 tweak 密文
              ← decrypt_e 逐块求逆 → 明文 JSON
```

**要点**：请求密钥 = 客户端自选 K16；响应密钥 = 服务端自选 K16resp。二者**不同**，
且都可用本地材料离线处理（请求侧用 `server_pub` 加密；响应侧用 `priv_from_go.pem` 解密）。

## 二、自研分组密码 E（与 AES 不同）

### 单块

```
E(x) = T( SR( SB( AES9( T(x) ^ rk0 ) ) ) ) ^ C(K)
```

| 记号 | 含义 |
|---|---|
| `T` | 4×4 字节转置（row-major ↔ column-major） |
| `AES9` | 标准 AES-128 的**前 9 轮**（`rk0..rk9`，标准密钥调度） |
| `SR`/`SB` | 标准 AES 的 ShiftRows / SubBytes（S-box 取自 `libcore.so[0x1DFC00]`） |
| `C(K)` | **只依赖 K** 的输出常量；一次 16B 预言机加密即可定出 |

> 不是标准 AES：末尾的 `T(...)` 包裹 + 输出常量 `C(K)` 是自定义部分。
> 全参数空间的 AES/SM4 排除已做过（见负结果）。

### 多块（不是标准 CBC）

```
块 0 :  x_0 = pt_0 ^ iv                       ct_0 = E(x_0)
块 b :  x_b = pt_b ^ ct_{b-1} ^ CONST_b       ct_b = E(x_b) ^ Cb_b      (b ≥ 1)
```

* `CONST_b` / `Cb_b` 是**只依赖 (K, b)** 的逐块 tweak：与明文、消息长度**无关**（实测）。
* 递推：`CONST_{b+1} = CONST_b ^ Cb_b`（b≥1）。
* 代码路径：块循环 `0x2d7440` → `extract(0x2d9ad4)` → **`neon(0x2d9ed0)`（把 `pt_b` 变 `x_b`）**
  → `reorder(0x2da1c8)` → 轮驱动 `0x2da498`。`0x2d9ed0` 为 OLLVM 展平 + NEON 位运算。

## 三、解密算法（`decrypt_e.py`）

```
x_b = F_inv( ct_b ^ C(K) ^ Cb_b )        # F = E 去掉输出常量 C(K)
pt_b = x_b ^ ct_{b-1} ^ CONST_b          # b=0 时 ct_{-1} := iv
末块去 PKCS#7
```

`F_inv` = `T⁻¹ → ISR/ISB → 9 轮逆轮（xr(rk) → IMC → ISR → ISB）→ T⁻¹ → xr(rk0)`。

### 标定法（因为 tweak 闭式公式未还原）

对同一 K 用 Unicorn 执行**一次等长 dummy 加密**，hook 轮驱动 `0x2da498` 读回每块 `x_b`：

```
CONST_b = x_b ^ dummy_b ^ ct_{b-1}
Cb_b    = ct_b ^ F(x_b) ^ C(K)
```

标定量仅依赖 (K, b)，故对**任意**密文成立。全流程离线（`libcore.so` + Unicorn，
无设备 / App / frida）。

## 四、负结果汇总（禁止重复尝试）

| 假设 | 结果 |
|---|---|
| 业务 P1 走 OpenSSL EVP | ✗（api_encrypt 全程业务层 EVP init 零触发） |
| 静态 keystore 对作请求 P1 密钥（forge v5 变体 A–D） | ✗ 全 800131 |
| `f(K16)` = K16 / md5(K16) / md5(hex) / sha256[:16] / sha256[16:] / sha1 / 逆序 / keystore 对 / SBOX 24 块常量 × 33 iv × {CBC,ECB,CTR,CFB,OFB} | ✗ 双 oracle 0 命中 |
| **以上全部用 AES 做** → **整块作废**（密码选错，应为自研 E） | — |
| `K16resp` 作响应 P1 密钥（V11 用 AES 证伪） | ✗ 结论作废，**正确结论：就是 K16resp** |
| 响应 P1 = 朴素 CBC（仅块 0 对） | ✗ 块 1 起乱码 → 必须逐块 tweak |
| `CONST_b`/`Cb_b` = 轮密钥 `rk_j`(j≤44) 或 `T`/`F`/`E` 变换 | ✗ |
| `CONST_b` = `F`/`E` 迭代、自 XOR 递推 | ✗ |
| `CONST_b` = `E(0/iv/K/counter)` 型 CTR keystream | ✗ |
| `CONST_b` = 标准 AES-128 CTR keystream | ✗ |
| `CONST_b` = `F(ct_{b-1})` / 明文相关项 | ✗ |
| `CONST_b(K) = BASE_b ⊕ g(K)`（K 上可分离） | ✗（K 上完全雪崩） |
| E 非对合（`E(E(x)) != x`），不能自解密 | 已证 |
| emu b64 编解码表越界 bug（pc `0x2ce3dc` / `0x2e5b3c`）→ **emu 输出侧 P1b64 不可信** | 输入侧（RSA 输出、K16）仍可信 |
| `/app/upgrade` 用主方案密钥/信封密钥解 | ✗（独立方案，见 §七） |

## 五、交付物

| 文件 | 作用 |
|---|---|
| `research/deliverables/authgen.py` | 离线生成 `authentication` 头（命令行） |
| `research/deliverables/authgen_server.py` | 本地服务：`/auth` `/forge` `/unwrap` **`/decrypt`** `/relay` `/store` `/classify` |
| `research/deliverables/decrypt_e.py` | **`decrypt(P1, K16) -> bytes`**（E 的逐块逆） |
| `research/deliverables/jcy_client.py` | 端到端客户端（请求伪造 + 响应解密） |
| `research/deliverables/apipost_sync.py` | Apipost 库预/后脚本同步 |
| `research/deliverables/gen_matrix.py` | 生成 35 接口实测矩阵文档 |
| `research/tmp_all_endpoints_par.py` | 多进程并行全接口验证驱动 |

## 六、实测结果（2026-10-04）

* 驱动 `tmp_all_endpoints_par.py`（6 worker 并行，12 核）。
* 35 个接口全部真实请求 + 离线解密，矩阵见 [live-matrix.md](../api/live-matrix.md)。
* 成功码是 **20000**（不是 200）；服务端错误也返回 HTTP 200，业务码在 JSON body。
* 游客态受限：`/app/users/info`、`/app/task/task`、`/app/history` → `50008 未登录`。
* 业务参数未补全：`/app/video/device-base`（明文 ≤16B）、`/app/video/play`（P1=656B）、
  `/app/video/play-connect`（P1=432B）→ `40000`（见 §八）。
* 失效路径：`/app/v2/config/host`、`/app/playaddr/v4/client`、`/app/login/smscode` → 404。

### 性能（2026-10-05 实测，V15 优化后）

* 纯 Python 求逆 ≈ **0.0014 s/块**（721 块/秒）；Unicorn 标定 ≈ **0.016~0.026 s/块**
  （v13 时代全镜像逐指令 hook 是 0.54 s/块病根，移除后 28×；真实样本端到端 450.5s → 9.2s）。
* 实测 `/app/video/list`（9.7KB ≈ 440 块，独立子进程全含）：全量 ≈ **11.5s**；前 6 块
  预览 ≈ **0.45s**；`/relay` 一键（伪造+真实请求+**同步全量解密内联返回**，2026-10-05 修复
  GET params 未拼 query 的 bug + 同步阈值提至 768 块）实测 **13.0s 返回完整明文 JSON**；
  >768 块才转后台写 `last_plain.json`（后台实测速率 639 块 17.4s，估算文案已按实测校正）。
* 大响应（search 34KB ≈ 2174 块）全量 ≈ 40~60s。**多进程并行只对多接口批量有效**
  ——单响应的 tweak 链是串行的，无法按块分片。
* **指令剖析定论**：每块 ≈127 万条指令中 ~93% 位于 OLLVM 展平的 tweak 生成器/装配
  机器（`0x2cd000~0x2ef600`），AES9 轮体占比很小。已实测把轮驱动 `0x2da498` 补成
  `ret`（注意必须 `uc.ctl_flush_tb()`，否则 TB 缓存不失效、补丁不生效）后 CONST
  序列**逐字节不变**（⇒ tweak 生成器与轮函数完全解耦，是后续提升闭式的关键前提），
  但总耗时几乎不降 → **skip-rounds 提速路线否决；根治唯一路径 = 还原 `CONST_b` 闭式**。
* `decrypt_e.py` 已加会话堆重建守卫：堆近上限时 `mkstr` 会**静默失败 → 捕获截断、
  标定缺块**（实测 512 块标定曾截断为 257 块），守卫触发即自动重建仿真会话。

### 播放链端到端（2026-10-05，全离线打通）

* 链路 list→detail→play→外链解析器→直链全部离线跑通（无需设备/frida），
  实测分解：forge 取签 0.2s + 一次真实 HTTP ~0.2s + 响应解密（config 2.1s /
  list 7.1s / detail 2.0s / play 5.2s，随块数线性）。
* 解析器（`yh.jx.xajtl.com/vo1v03.php`）响应为**明文 JSON**（code=200），
  AES128-CBC 兜底（key=rdcibneoapyspqlt/iv=fyoofrebaxjwioxn）本轮未触发。
* playAddr 返回两清晰度：1080P H265 MP4（腾讯云，206 状态 + ftyp ✓）与
  4K H265 MP4（toutiaovod，206 + ftyp ✓）；签名盐已更换为 `pzizhsqjjt`。
* 协议细节、直链头规则与复现命令：[video-play.md](../api/video-play.md)；
  Apipost 已建「播放解析器」节点（预脚本内联 md5 现算签名）。

## 七、`/app/upgrade`（独立方案，未解）

| 项 | 值 |
|---|---|
| 方法 | **仅 POST**（GET → 404） |
| 认证 | 大写 `Authentication`，magic `905b5ed3`（主方案为小写 + `23754ae9`） |
| 认证校验 | **不校验**：无 auth / 假 auth / 新鲜 auth 响应一致 |
| 请求体 | 160B（10 块）E 密文，**无 RSA 层**、无 `.` |
| 响应 | 真机 896B（56 块）；伪造请求得恒定 64B 桩 |
| 试解 | 主方案密钥、信封密钥、头派生密钥全部未命中 |

**结论**：`/app/upgrade` 是**独立的第三套方案**（疑似硬编码 key + 另一套 Authentication 算法）。
下一步需在设备侧 hook `api_encrypt`/`api_decrypt` 捕获该端点的 key/iv，或反汇编
magic `905b5ed3` 对应的签名函数。

## 八、未解项 / 后续

1. **`CONST_b`/`Cb_b` 闭式公式**：未还原 → 每 (K, nblk) 需一次标定（≈0.02 s/块，效率瓶颈；
   实测 440 块全量解密 ≈ 8~12s、预览 0.45s）。
2. **`/app/upgrade` 第三套方案**：需设备侧捕获或反汇编。
3. **业务参数补全**：仅剩 `device-base`（真机 body 只 1 块，明文 ≤15B）与 `play-connect`
   （明文 ≈417–431B）—— 请求体不可解（请求 P0 用**服务端**公钥加密，本地无私钥）。
   `play` 已解决：**参数放 query**（`?id=&play=&part=`）、body 用 `{}` → 20000。
4. **`/app/danmu`**：**必须带 `part`（集名）**，响应是**明文 JSON**（非加密信封）。

## 九、复现步骤

```bash
# 1) 取一份新鲜 authentication（约 4 秒）
./.venv/Scripts/python.exe research/deliverables/authgen.py

# 2) 端到端请求任意接口（自动伪造 body + 解密响应）
./.venv/Scripts/python.exe research/deliverables/jcy_client.py \
    GET /app/video/list?channel=1&sort=weight&limit=6&page=1

# 3) 起本地服务，供 Apipost 预/后执行脚本调用
./.venv/Scripts/python.exe research/deliverables/authgen_server.py --warmup

# 4) 全接口并行验证（可断点续跑）
JCY_WORKERS=6 ./.venv/Scripts/python.exe research/tmp_all_endpoints_par.py
```

> 坑：Git Bash 会改写 `/app/...` 路径参数 → 设备 / HTTP 命令一律加 `MSYS_NO_PATHCONV=1`。
