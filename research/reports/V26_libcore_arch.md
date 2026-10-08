# V26 — libcore.so 完整架构与 E 密码链路（为提速定位）

> 目标：用户要求「逆向 App 分析出完整算法」以解决**解密速度**问题。
> 本报告给出本轮**新验证**的架构级结论 + 密码本体规格 + 性能实测 + 剩余未知点的精确坐标。
> 所有结论均标注证据来源；未执行项明确写「未执行」。

---

## 0. 一句话结论

App 的自研密码**不是 Dart 实现，而是原生 `libcore.so` 通过 FFI 以 JSON 动作协议暴露的服务**：
`libcore.call({"action":"api_encrypt"|"api_decrypt","payload":{"data":…}})`。
解密耗时 **99.9% 在「逐块 tweak 标定」**（1.1–1.2 ms/块），密码本体求逆仅 0.14 ms/323 块。
tweak 的闭式生成器仍未知，但本轮已把它**从"整个 libcore"缩小到解密专属代码区 0x2ceb00–0x2e9xxx**。

---

## 1. 原生库与导出符号（新）

APK `assets/apk/base.apk` → `lib/arm64-v8a/`：

| 文件 | 大小 | 作用 |
|---|---|---|
| `libapp.so` | 12.3 MB | Dart AOT 快照（blutter 已分析） |
| `libcore.so` | 6.84 MB | **密码服务本体**（与 `research/artifacts/libcore.so` sha256 完全一致） |
| `libloader.so` | 6.22 MB | 热更新加载器 |
| `libflutter.so` | 10.8 MB | Flutter 引擎 |

`research/artifacts/libcore.so` 与 APK 内文件 **sha256 = 26727c7b68308d3055860a71aa0c2173**，逐字节相同 —— 既有分析对象正确。

导出符号（`.dynsym`，共 11334 个，绝大部分是静态链入的 BoringSSL/protobuf/libc++）：

```
libcore.so    : call   @ 0x00307a38   (STT_FUNC)     ← 唯一业务入口
libloader.so  : reload @ 0x002a5d04
                call   @ 0x002a3bac
                JNI_OnLoad @ 0x002a6210
```

## 2. Dart 侧 FFI 调用链（blutter `asm/guoguo/utils/ffi_utils.dart`）

```
FFIUtils.loadSo()   → dlopen("libloader.so")  → lookup("reload")
FFIUtils.loadCore() → dlopen(getCore() ?: "libcore.so") → lookup("call")
FFIUtils.apiEncrypt(data) → _rawCall(json)   # json = {"action":"api_encrypt","payload":{"data":…}}
FFIUtils.apiDecrypt(data) → _rawCall(json)   # json = {"action":"api_decrypt","payload":{"data":…}}
```

* `getCore()` 从 `getAppInfo()` 读 `libcore.so` 名字 → **库名可被配置覆盖（热更新/多形态）**。
* `getRegistries()` 用 `getRandomString()` 生成随机键值对后走 `_loaderCall`。
* `clearKey()` 存在；`apiDecrypt` 失败时会 `clearKey()` 并**最多重试 2 次**（`g_http_client.dart`）。
* 错误码：`code==400` / `800` 视为异常分支；`code==0x7d2 (2002)` → `KeyErrorException`；其余 `Unknown Err`。
* 调用点：`g_http_client.dart`（响应解密）、`task_page.dart`、`video_page.dart`。

## 3. libcore 内部链路（新，静态定位）

`.text` 范围 `0x2be000–0x612b00`（203,884 条指令）。**函数边界靠 `stp x29,x30,[sp,#-…]!` 序言 + 直接 `bl` 调用图重建**（OLLVM 展平，控制流不可线性读）。

### 3.1 分发器

* `call` @ **0x307a38**：入口，`x0=json指针`，`x1=回调函数指针`；用 GOT 偏移混淆（`adrp #0x67c000; ldr x9,[x19,#0x798]; ldr x8,[x9,<混淆偏移>]; add x8,x8,<混淆偏移>; blr x8`）间接调用。
* 动作名字符串**不在 .so 明文**（`api_encrypt`/`api_decrypt` 计数 = 0），运行时解密写入 `.bss`（分发器引用 `0x689528`，落在 `.bss`）。

### 3.2 加密链

```
api_encrypt handler  0x305d94  (序言定位；含唯一管线调用点 0x306548)
      └─ 管线          0x304eb0   ← 本项目 Unicorn/C 引擎的 OFF_PIPE
           ├─ A1   阶段  0x304fb4
           ├─ E    阶段  0x3050f8  ── bl 0x2d6f78  (块循环)
           └─ AUTH 阶段  0x3051b4
0x2d6f78 (块循环, 41 insn)  ← 调用点仅 0x303df0 / 0x3050f8
      ├─ 0x2d9ad4  extract
      ├─ 0x2d9ed0  16B XOR（函数体 0x2d9ed0–0x2da1c4，756B / 189 insn）
      └─ 0x2da498  轮驱动入口（本项目 x_b 捕获点）
```

### 3.3 解密链（新，关键）

```
api_decrypt handler  0x306b10  (序言定位)
      ├─ 0x2dbf9c  包装(RAII)：构造临时对象 → 0x2dc524 → 0x2dccb8 → 析构
      ├─ 0x2dccb8  小函数：bl 0x2ed380 + runtime 桩
      ├─ 0x312a88  44 路分发器（内部 44 处 bl 0x2cf428）
      └─ 0x3442f8
0x312a88 → 0x2cf428 → {0x2ceb00, 0x2cee50, 0x2cf2b4, 0x2d0fe8, 0x2d13f0, 0x2d19ec, 0x2e7194}
      └─ 核心区 0x2e6xxx–0x2e9xxx：0x2e6cb8 / 0x2e7194 / 0x2e920c / 0x2e945c
```

**决定性事实：解密链完全不经过加密管线 0x304eb0，也不调用加密块循环 0x2d6f78。**
→ App 解密时**不是**「跑一遍加密再求逆」，而是走一条独立实现，因此它必然**自己廉价地算出逐块 tweak**。
→ **tweak 生成器就在 0x2ceb00–0x2e9xxx 这一解密专属区**（本轮最重要的缩小结果）。

## 4. 密码本体规格（沿用并复核）

```
K = K16(16B), iv = reverse(K16)
E(x) = T( SR( SB( AES9( T(x) ^ rk0 ) ) ) ) ^ C(K)
    T   = 4x4 字节转置（对合）
    AES9= 标准 AES-128 前 9 轮；rk0..rk10 = 标准 AES 密钥调度
    C(K)= 只依赖 K 的输出常量（由 iv=0 的单块加密标定）
分块：
    x_0 = pt_0 ^ iv                       ct_0 = E(x_0)
    x_b = pt_b ^ ct_{b-1} ^ S_b           ct_b = E(x_b) ^ (S_{b+1} ^ S_1)
    S_0 = 0,  不变式 Cb_b = S_{b+1} ^ S_1  (实测 63/63 成立)
解密：
    x_b = F_inv(ct_b ^ C(K) ^ Cb_b);  pt_b = x_b ^ ct_{b-1} ^ S_b
```

本轮复核证据：

* **S-box @ 0x1dfc00 = 标准 AES S-box**（256B 逐字节比对 True）。
* **全 `.text` 对 0x1dfc00 的 PC 相对引用只有 20 处，全部落在 0x2cd970–0x2ce17c**，即 `0x2cd8b0` 区。
  → 轮函数**不直接查 S-box**，而是用运行时构建的表（.bss）；该区同时**读轮密钥区**（PC 0x2cdc88，8B 读 × 704 次），
  与「拷贝 S-box + KSA + 生成轮密钥/表」的语义一致 → **0x2cd8b0 ≈ 表/密钥调度构造器**（每次密码调用一次，实测调用 3 次）。
* **S_b 从不以连续字节形式落盘**：全地址 `UC_HOOK_MEM_WRITE` 扫 16B 目标 0 命中；改 4B 粒度扫 S_1/S_2/S_3 的 4 个分段亦 0 命中（仅命中巧合的 `33221100`=IV[3]）。
  → S_b 在寄存器/栈上即时生成并即时 XOR，**不能靠内存快照提取**。
* 0x2d9ed0 的两个实参是**栈上 16 字节缓冲区**（非字符串描述符）：
  第 1 块 `rd(x1,16)` 的两级间接解析结果 = `T(iv)`，与本项目标定口径一致。
* 明文无关性复核：全零明文 vs 伪随机明文，S_b 64/64 完全一致 → 模型成立。

### 已排除的闭式（本轮新增，全部负结果）

| 假设 | 结果 |
|---|---|
| `S_b = AES-ECB(K, ctr)`（BE/LE/8B/文本/`b*16`/`b+1` 等 11 种编码） | 全否 |
| `S_b = AES(K, ctr ^ iv)` / `AES(K, T(ctr))` / `T(AES(K,ctr))` | 全否 |
| `S_b = F(ctr)` / `F(ctr)^IV` / `F_inv(ctr)` / `F(T(iv))` / `E(T(iv))` | 全否 |
| `S_{b+1} = AES(K,S_b)^X` / `AES(S_b ^ ctr)^X` / `F(S_b)^X` | 非常量（30/30 不同） |
| `S_{b+1} = E(S_b^X)` / `E(S_b)^X` / `E(S_b^S_1)` / `E(S_b^IV)` / `S_b^E(S_1)` | 非常量 |
| `S_1 = AES(K,IV)` / `AES(K,K)` / `AES(K,0)` / `F(IV)^C`(=ct0) 等 14 项锚定 | 全否 |
| `S_b` 与 `rk[i]` 异或为常量 | 否 |
| AES 固定点 / 短周期 | 否 |

## 5. 性能实测（本轮，C 引擎 V24，639 块镜像）

标定耗时 vs 块数：

| nblk | 1 | 4 | 16 | 64 | 128 | 323 | 639 |
|---|---|---|---|---|---|---|---|
| ms | 7.3 | 9.1 | 19.4 | 69.2 | 141.0 | **387.7** | 929.6 |
| ms/块 | 7.32 | 2.27 | 1.21 | 1.08 | 1.10 | **1.20** | 1.46 |

* 同 K 二次标定（缓存命中）：**0.0065 ms**。
* 纯解密主循环 `decrypt_blocks(323 块)`：**0.139 ms**。
* 真实样本端到端：11 块 12.1 ms / 120 块 106.2 ms / **268 块 264.2 ms**，全部 `json=True`（明文正确）。

**⇒ 校准占解密总耗时 99.9%。速度问题的唯一瓶颈就是它。**

### K16 是否可跨请求复用？（决定性）

`tmp_pairs.json` 13 样本 / 10 个含 K16：**10 个 K16 全部互不相同**（各出现 1 次）。
⇒ 服务端**每响应生成新 K16** ⇒ 按 K 缓存标定**永远不命中**，闭式生成器（或原生执行）是唯一出路。

## 6. 剩余未知点与精确坐标

| 项 | 状态 |
|---|---|
| tweak 生成器 S_b | **未知闭式**；代码位于解密专属区 **0x2ceb00–0x2e9xxx**（核心 0x2e6cb8/0x2e7194/0x2e920c/0x2e945c） |
| S_b 是否可物化 | 否（寄存器即时生成） |
| 解密是否复用加密管线 | 否（独立实现，见 §3.3） |
| 0x2cd8b0 语义 | 表/密钥调度构造器（S-box 唯一引用区 + 读轮密钥），调用 3 次/次加密 |

## 7. 下一步可执行方案（按性价比）

1. **提取解密区生成器（首选）**：对 `0x2ceb00–0x2e9xxx` 做动态 trace（在引擎里以 `api_decrypt` 等价入口喂已知 `(K16,P1)`），
   把 tweak 生成器还原为纯 Python/C。成功后标定可完全去掉，
   323 块解密从 388 ms → **≈0.14 ms**（该阶段 ~2800×）。
2. **原生执行**：`libcore.so` 是普通 ARM64 原生库且导出 `call`。在设备侧（LDPlayer/真机）以 Frida 或独立 ARM64 桩
   直接调 `call({"action":"api_decrypt",…})`，绕开本项目 C 转译引擎的解释开销。
3. **立即可用的缓解**（不需要还原生成器）：
   - 只解密需要的块（`blocks=N`，已支持）；
   - 按「端点 + 请求签名」缓存**明文**（实测 source/urls 跨请求 100% 稳定）；
   - 引擎常驻 + 同 K 复用（已实现）。

## 8. 复现命令

```bash
# 环境
./.venv/Scripts/python.exe            # capstone 5.0.7 / unicorn / pyelftools 可用

# 真值复现（对拍 probe3 的 CONST[1..5]，不变式 63/63）
research/tmp_gt_const.py

# 明文无关性 + 转移关系电池
research/tmp_const_hypo.py

# AES keystream 大电池
research/tmp_aes_ks.py

# 性能实测
research/tmp_speed_now.py

# 静态定位
research/tmp_callers.py 0x304eb0 0x307a38 0x2cd8b0 0x2d6f78
research/tmp_blrange.py 0x306b10 0x307a38
research/tmp_sboxref.py
research/tmp_calltree.py

# 动态（Unicorn，单次约 1–3 分钟）
research/tmp_chunk16b.py      # 0x2d9ed0 / 0x2da498 实参
research/tmp_rkread.py        # 轮密钥区读取点统计
```

## 9. 未执行项

* 未在真机/LDPlayer 上以 Frida 直接调 `libcore.call`（方案 2 未执行）。
* 未对 `0x2ceb00–0x2e9xxx` 做完整动态 trace（方案 1 未执行，仅完成静态坐标定位）。
* 未反编译 `libloader.so` 的 `reload` 热更新协议。
