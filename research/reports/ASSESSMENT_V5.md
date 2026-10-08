# 能力/缺口评估表 V5

> 生成时间：2026-09-29 01:40（GMT+8）
> 目标：`com.tudou.tool`（囧次元）1.5.8.0 / versionCode 88，Flutter 3.27 + Dart 3.6 AOT，`primaryCpuAbi=arm64-v8a`
> 环境：LDPlayer14 实例 0（`emulator-5554`，Android 14 / API 34，x86_64 + libhoudini），Kitsune Mask 27.2 + Zygisk Next 1.5.0 + LSPosed 2.1.0 + frida-server 17.8.2
> 纪律：本表严格区分【观测】【假设】【已验证】；未执行项标「未执行」并给出下一条可复现命令。

---

## 0. 结论速览

| 项 | 结论 |
|---|---|
| 第四节「App 在雷电上必崩、无法动态分析」 | **不成立，已推翻**。崩溃只在 frida **spawn** 时发生，普通启动完全正常。 |
| 主攻路线 | **R3 + R1 混合**：继续在雷电 14 上做动态分析（**只用 attach，禁用 spawn**），不需要换 arm64 环境。 |
| 抓包 | ✅ 已打通并修复（`adb reverse` + 设备 iptables → PC keep-alive 代理），16 端点 58 请求全部可复现抓取。 |
| 通道 1（监控）/ 通道 2（信令） | ✅ 已破解并可用（`out/client/gg_client.py`）。 |
| 通道 3（HTTP body） | ❌ **核心缺口**，本轮把结构彻底摸清但会话密钥仍未取得。 |
| authentication 生成 | ❌ 未破解；但已证伪「服务器签发」假设（见 §4）。 |

---

## 1. P0 环境健康检查（全部实测通过）

| 检查项 | 命令 | 真实输出 | 判定 |
|---|---|---|---|
| 实例 | `ldconsole.exe list2` | `0,雷电模拟器,…,540,960,240` | ✅ |
| adb | `adb devices` | `emulator-5554  device` | ✅ |
| Magisk | `su -c 'magisk -v'` | `v27.2-kitsune-4:MAGISK:R` | ✅ |
| Root | `su -c 'id'` | `uid=0(root) … context=u:r:magisk:s0` | ✅ |
| 常驻进程 | `ps -A \| grep -E 'zygiskd64\|lspd\|frida-server'` | `lspd 180` / `zygiskd64 406` / `frida-server 2889` | ✅ |
| 模块 | `ls /data/adb/modules/` | `fluttertap hma_oss_zygisk zygisk-assistant zygisk_lsposed zygisksu` | ✅ |
| frida 连通 | `frida.get_device_manager().add_remote_device('127.0.0.1:27042')` | `frida 17.8.2 \| remote procs: 107`，目标 `com.tudou.tool` 可见 | ✅ |
| 目标 → API 连通 | 设备内 `nc 43.145.33.254 27990` | `HTTP/1.1 200 OK` + `{"code":30000,…authentication is empty}` | ✅ |

**环境补装（本轮）**：`.venv` 补装 `frida==17.8.2`（41.9 MB wheel）、`Pillow`、`capstone 5.0.7`；PyPI 走 `127.0.0.1:7897` 代理正常。
注意：系统 Python313 与受管 3.13.12 **均无 frida**，只有项目 `.venv` 有 → 统一用 `./.venv/Scripts/python.exe`。

---

## 2. 资产盘点（3.1 实测）

| 类别 | 路径 | 状态 |
|---|---|---|
| 分析主文档 | `out/API_ANALYSIS.md`（230 行） | ✅ 在 |
| 审计链 | `out/VERIFICATION.txt`（[F1]–[F10]） | ✅ 在，本轮追加 [F11]–[F17] |
| 离线客户端 | `out/client/gg_client.py`（216 行） | ✅ 在，通道 1/2 可用 |
| frida 脚本族 | `out/client/gg_*.js`、`out/gg_*_hook.js`（30+ 个） | ✅ 在 |
| blutter 产物 | `out/blutter_out/`：`pp.txt` 2.66 MB、`objs.txt` 649 KB、`asm/`、`ida_script/` | ✅ 在 |
| reFlutter 产物 | `reflutter_work/`：`dump.dart`、`dump2.dart`、`dump2_parsed.jsonl` | ✅ 在 |
| native 库 | `out/nativelibs/`（17 个 .so） | ✅ 在 |
| RSA 公钥 | `out/RSA_PUBLIC_KEY.pem` = **1024 位**（e=65537） | ⚠️ 非 HTTP body 所用的 2048 位 |
| 密文样本 | `out/ct_samples/`（36 个文件：AUTH/P0/P1/BODY hex） | ✅ 在 |
| auth 样本 | `out/auth_samples.json`（88 条）、`out/auth_full_rows.json`（28 条） | ✅ 在 |
| 旧抓包 | `out/ggcap.pcap`（17.2 MB） | ✅ 在 |
| 工具 | `tools/`：jadx / apktool.jar / blutter / platform-tools / PCAPdroid apk / uber-apk-signer / libgadget.so | ✅ 在 |
| 环境模块包 | `tools/re-env/modules/`（7 个） | ✅ 在 |

### 与任务书 §3.2 描述不符的条目（如实列出）

| 任务书声称 | 实际 | 影响 |
|---|---|---|
| `out/auth_rt7_log.jsonl` 内有 `bn_n/bn_e/bn_d/bn_p/bn_q` | **该文件不存在**；全仓 grep 仅在 `libcore.so_strings.txt` / `libloader.so_strings.txt` 命中 `bn_*`（OpenSSL 符号名字符串，非密钥值） | 任务书 P3.3 的「取 RSA 私钥」路径不可用，已改用其他路径 |
| `out/resp_bodies.tsv`（28 条响应体） | 文件存在但 **0 字节**；`out/resp_map.tsv` 0 行 | 响应样本需重新抓取（本轮已抓） |
| `libcore 内嵌密钥对已 dump` | 磁盘上无任何私钥产物；`out/RSA_PUBLIC_KEY.pem` 为 1024 位公钥 | 见 §5 缺口 |

---

## 3. 第四节复现实验（3 次冷启动 + spawn 对照）

实验脚本：直接 `am force-stop` → `am start -n com.tudou.tool/app.video.guoguo.SplashActivity` → 等 12 s → `pidof` + tombstone 计数。

| 试验 | 启动方式 | 结果 | tombstone |
|---|---|---|---|
| 1 | `am start`（冷启动） | **存活** pid=3890 | 无新增 |
| 2 | `am start`（冷启动） | **存活** pid=4358 | 无新增 |
| 3 | `am start`（冷启动） | **存活** pid=4845 | 无新增 |
| 对照 A | `frida spawn`（`probe_hook.py`） | **崩溃** pid=5907→死 | 无新增（已计入下方） |
| 对照 B | `frida spawn`（`probe_modules.py`） | **崩溃** pid=6015→死 | `tombstone_02` |
| 对照 C | `frida spawn`（第 2 次） | **崩溃** | `tombstone_03` |

**结论（已验证）**：
- 冷启动崩溃率 **0/3**；`frida spawn` 崩溃率 **3/3**。
- 崩溃签名与第四节记录一致：`signal 11 (SIGSEGV), code 128 (SI_KERNEL), fault addr 0x0`，线程 `DartWorker`。
- 进程存活时 52 线程，含 `3×DartWorker`、`1.ui`、`dart:io EventHa`、`Sqflite`；已映射 `libapp.so` / `libcore.so`(/data/data/com.tudou.tool/files/) / `libloader.so` / `libflutter_patched.so` / `libhoudini.so`。
- **首页实拍渲染正常**（推荐/日漫/國漫分栏、海贼王 1180|周日23:30、转生贵族 1|周日23:00更、底部频道/任务/我的）。

**归因修正**：第四节把崩溃归因于「houdini 不能跑 Dart AOT」是**错误**的。真实触发条件是 **ptrace 式 spawn 打断 houdini 转译线程**；`am start` 与 frida **attach** 均正常。

**路线裁决（R1/R2/R3）**：
- R1（换 arm64 真机）：**不需要**，因为 App 在本机可正常运行且可 attach。
- R2（unidbg 模拟 libcore）：保留为**备选**，用于离线复算加密（见 §5 下一步）。
- R3（再试雷电）：**采纳为主路线**，且已验证只需「冷启动 + attach」即可，**禁止 spawn**。

---

## 4. authentication 结构解析（已证伪「服务器签发」）

### 观测

- `authentication` = **112 字节** → base64 **152 字符**。
- 结构：`[0..14]` 15B 恒定魔数 `e8cb1f120ef5a42c59e22a4d00279e`；`[15]` 1B 计数（全局仅 `0x9c/0x9d/0x9e/0x9f` 四种）；`[16..111]` 96B。
- 逐块统计（28 条真实样本）：块 0 全局仅 4 种取值；块 1–4 与 ts 一一对应（25 种）；块 5–6 随 ts+nonce 变化。
- **决定性证据**：`ts=1790519240124` 的两条样本（同 ts、不同 nonce）——前 5 个 AES 块**逐字节相同**，仅末 2 块不同。
- 已知密钥验证：用 `qPwC/p3Jd`（监控）与 `kFGT/F3q2`（信令）对 auth 密文做 CBC/ECB × 全偏移解密，**0 命中**。

### 推断（已验证级）

`authentication` 是**客户端本地生成的 CBC 密文**：
- 服务器签发无法解释「对客户端 nonce 的依赖」；
- 「同 ts 不同 nonce ⇒ 仅末 2 块变化」是 CBC 误差传播的教科书特征（明文差异位于尾部块）。

### 存在至少 3 套独立方案

| 方案魔数 | 载体 | 备注 |
|---|---|---|
| `e8cb1f120ef5a42c59e22a4d00279e` | 主 API（头名 `authentication`） | 96B 密文 |
| `905b5ed37c8cc832…` | `/app/upgrade`（头名 **`Authentication`** 大写） | body 为 **216B 裸二进制**（非 `P0.P1`），响应 1196B base64→896B |
| `e9e3af6adbde3859…` | `/app/v2/config/host` | 已下线端点 |

---

## 5. HTTP body 通道（通道 3）—— 本轮摸清的结构

### 已验证

- **请求体** = `<P0_b64>.<P1_b64>`：P0 恒 **256 字节**（RSA-2048），P1 为 16 的倍数（48B 等），总长如 409 字符。
- **响应体**（先解 HTTP chunked）：`/app/video/list` 解 chunk 后 6065 字节，**同样是 `P0.P1`**：
  - `P0_b64` 344 字符 → **256 字节**（RSA-2048）
  - `P1_b64` 5720 字符 → **4290 字节**（AES）
- ⇒ 双向都需要 RSA-2048：请求 P0 用**服务器公钥**加密会话密钥；响应 P0 用**App 自身公钥**加密，App 持**私钥**解密。
- 错误响应为**明文 JSON**（`{"code":30000,…}`），这是唯一未加密的响应形态。

### 未打通（核心缺口）

| 缺口 | 现状 | 已验证的失败路径 |
|---|---|---|
| HTTP body 会话密钥 | ❌ 未取得 | P0 需服务器私钥，离线不可解 |
| App 内嵌 RSA-2048 私钥 | ❌ 未 dump | 在 `libapp.so`/`libcore.so`/`libloader.so`/`libflutter.so`/`mem_dump.bin`/`base.apk` 中搜索 DER（SPKI/PKCS1/PKCS8）与 PEM 均**未找到真密钥**；`libapp.so` 里的 `-----BEGIN RSA PRIVATE KEY-----` 等仅为 Dart 快照中 pointycastle 的字符串字面量 |
| `out/RSA_PUBLIC_KEY.pem` | ⚠️ 1024 位，与 2048 位方案不符 | 其模数在全部转储与当前进程内存（1682 MB 扫描）中**均未出现** |
| authentication 生成算法 | ❌ 未破解 | 全滑窗 AES 暴力 0 命中（沿用 V4 结论） |

### 已排除的动态方案（本轮实测，勿重复）

| 方案 | 结果 |
|---|---|
| frida 模块表定位 ARM64 库 | ✗ `enumerateModules()` 321 项**不含** libapp/libcore/libloader（仅 `libhoudini.so`），`findModuleByName` 恒 null |
| houdini native bridge trampoline hook | ⚠️ 通道可用（`getTrampoline` hook 生效，拿到 44 个符号的 x86_64 trampoline），但 **Dart FFI 的 guest→guest 调用不经过 trampoline**（`libcore!call` 冷启动 30 s 内 0 次调用） |
| 直接调用 `libcore!call` trampoline | ✗ 单指针调用 fault（houdini 哨兵地址 `0xdead10xx`） |
| 内存扫描找解密后明文 JSON | ✗ 扫 1600 MB（UTF-8/UTF-16 的 `"code"`/`code`/`list`/`name`/`message` 等 10 种模式）**0 命中** |

### 反汇编进展（新增能力）

`out/v5/disasm_call.py`（capstone 5.0.7）已能反汇编 `libcore!call`（vaddr `0x307a38`，size 32384）：

```
0x00307a58: str   x1, [sp, #8]      ← 第 2 参数被保存 ⇒ call 至少双参
0x00307a6c: mov   x20, x0           ← 第 1 参数
0x00307a94: ldr   x8, [x9, x8]      ← 混淆 GOT：x19=0x67c000 页, 偏移 0xd0291782cc74b0e4
0x00307a98: add   x8, x8, x21       ← +0x7ddbbf96e905ad67
0x00307ad0: blr   x8                ← 间接调用（目标运行时才能算出）
```

⇒ `call` 是双参数分发器，内部经**指针混淆 GOT** 调用真实实现。这解释了直调 trampoline 为何 fault，也给出下一步的确定性打法。

---

## 6. 能力/缺口矩阵（3.5 填实）

| 能力 | 现状 | 缺口 / 下一步 |
|---|---|---|
| 静态 Dart 还原 | ✅ `blutter_out/pp.txt` 2.66 MB + `asm/` + `objs.txt` 齐备 | — |
| 静态 native 还原 | ✅ `libcore.so` 11573 个 `.dynsym`；`call`=vaddr `0x307a38`/size 32384；capstone 反汇编链路已建 | `call` 内部混淆 GOT 目标需**运行时**求解 |
| ELF 符号/偏移基线 | ✅ `out/v5/elf_syms.py`（dynsym 解析 + vaddr→file offset） | — |
| 抓包 | ✅ **16 端点 / 58 请求**，链路已修复（keep-alive） | 播放链路端点（`/app/video/play`、`/app/playaddr/v4/client`）尚未触发抓到 |
| 监控通道解密 | ✅ `gg_client.py` 已验证 | — |
| 信令通道解密 | ✅ `gg_client.py` 已验证 | — |
| HTTP body 解密 | ❌ 结构已摸清（双向 RSA-2048 + AES） | 必须拿到 App 内嵌 RSA-2048 **私钥**或会话密钥 |
| authentication 生成 | ❌ 已证伪服务器签发 | 需定位 `libcore!call` 内真实签名分支 |
| 动态 hook（模拟器） | ✅ **attach 可用**；spawn 必崩 | 统一用 attach；禁止 spawn |
| LSPosed / Zygisk 模块 | ✅ 已装并启用（TrustMe / SSLUnpinner scope 到目标） | 对 native 加密**零增益**（明文 HTTP，无 TLS 校验） |

---

## 7. 主攻路线与理由（3 次冷启动实验后裁决）

**裁决：R3（继续雷电）+ 只用 attach，禁用 spawn。**

理由（全部基于 §3 实测）：
1. 冷启动 0/3 崩溃 ⇒ App 本身在 x86_64+houdini 下**可正常运行**，第四节「必崩」结论不成立。
2. frida attach 实测**成功**（F10 记录的 `TimedOutError` 未复现），足以做内存读取与 x86_64 层 hook。
3. frida spawn 3/3 崩溃 ⇒ **唯一需要规避的是 spawn 这一种启动方式**，无需换环境。
4. 换 arm64 真机（R1）成本高、无收益；unidbg（R2）保留为离线复算备选。

**下一步确定性打法（按优先级）**：
1. **运行时求解混淆 GOT**：attach 后读 `[0x67c000+0x798]`，加上常量算出 `call` 的真实 callee 地址，逐个反汇编，定位签名/加解密分支。
2. **ARM64 guest 代码 patch hook**：houdini 惰性翻译 ⇒ 在 `call` 首次执行前改写 guest 代码前 4 条指令为跳转到 host 侧 RWX 页的 ARM64 stub（guest/host 同地址空间），记录 x0/x1 与返回值。这是拿到明文的**最直接**路径。
3. **内存取证（改进版）**：在触发 `/app/video/play` 的瞬间扫描，而非空闲期；同时按「16 字符 alnum」候选集（本轮已收集 272688 个候选）对**新抓的 P1** 做 AES 验证（本轮 6 个样本 0 命中，需扩大样本与候选集）。
4. **unidbg 兜底**：在 PC 侧模拟执行 `libcore.so`，用已知明文调用其加密函数，反推密钥调度。

---

## 8. 验收标准逐条自评

| # | 验收项 | 判据 | 当前状态 | 证据 |
|---|---|---|---|---|
| A1 | 接口清单完整 | 所有端点列出方法/URL/参数/头/请求体/响应体 | **部分达成** | `out/API_MATRIX_V5.md`：16 端点实抓 + `docs/api/endpoints.md` 静态 40+ 端点；播放链路端点未触发抓到 |
| A2 | 三通道加解密可复现 | 三通道各有独立脚本 + 真实密文可解出明文 | **2/3 达成** | 通道 1/2：`out/client/gg_client.py`（已验证）；通道 3：**未打通** |
| A3 | 视频列表打通 | 自写客户端返回 code 成功且含视频条目 | **未达成** | 响应密文已抓（`/app/video/list` 4 条，6078–9982B），但无法解密 |
| A4 | 播放地址打通 | 拿到 m3u8/mp4 直链 | **未达成** | 同上，且播放端点未触发抓到 |
| A5 | 每步可验证 | 每步命令 + 真实输出；未执行写「未执行」 | **达成** | `out/VERIFICATION.txt` [F11]–[F17] |
| A6 | 环境配置就绪 | 第六节清单逐项打勾 | **达成** | §1 + `docs/setup/*.md` |

---

## 9. 抓包链路（本轮打通，可复用）

```bash
# 1) 反向端口：设备 27990 → 宿主 27990
adb reverse tcp:27990 tcp:27990

# 2) 设备侧把目标 API 流量重定向到本地
adb shell "su -c 'iptables -t nat -A OUTPUT -p tcp -d 43.145.33.254 --dport 27990 -j REDIRECT --to-ports 27990'"

# 3) 宿主侧 keep-alive 代理（必须 keep-alive，见下方坑）
./.venv/Scripts/python.exe out/v5/mitm_proxy.py

# 关闭
adb shell "su -c 'iptables -t nat -D OUTPUT -p tcp -d 43.145.33.254 --dport 27990 -j REDIRECT --to-ports 27990'"
adb reverse --remove-all
```

**已修复的坑（会导致 App 报 `300103: 网络错误!`）**：
服务端对 `GET /app/channel/?top-level=true` 返回 `301 → Location: /app/channel?top-level=true`（相对路径）。
Dart HttpClient 默认 keep-alive，会在**同一条 TCP 连接**上继续发重定向请求。
若代理「一事务一关闭」，第二条请求打到已关闭的 socket → RST → 首页拿不到频道列表 → 300103。
修复后实测 `/app/channel?top-level=true → 200 (3901B)`、`/app/video/list × 4 → 200`。

**附带纠正**（相对旧文档）：
- 请求头是 `authentication`（小写，主 API）与 **`Authentication`（大写，`/app/upgrade`）** 两种。
- `appid` 实测为 **`4150439554430529`**（旧文档写 `com.tudou.tool`，实测不对）。
- 响应为 **HTTP chunked**，分析前必须先解 chunk。

---

## 10. 产物索引（本轮新增）

| 文件 | 说明 |
|---|---|
| `out/ASSESSMENT_V5.md` | 本文件 |
| `out/API_MATRIX_V5.md` | 接口全量矩阵（16 端点，实抓） |
| `out/v5/mitm_proxy.py` | keep-alive 抓包代理 |
| `out/v5/proxy_capture.jsonl` / `proxy_bodies.jsonl` | 抓包摘要 / 完整 hex |
| `out/v5/elf_syms.py` | ELF dynsym 解析（导出/偏移） |
| `out/v5/disasm_call.py` | capstone 反汇编 `libcore!call` |
| `out/v5/hook_bridge.js` / `resolve_call.js` | houdini native bridge 探针 |
| `out/v5/scan_plaintext.js` / `scan_keys.js` / `scan_modulus.js` | 内存取证探针 |
| `out/v5/probe_attach.py` / `probe_hook.py` / `probe_modules.py` | attach/spawn 边界实验 |
| `out/v5/shot_coldstart3_small.jpg` / `shot_after_fix_small.jpg` | 冷启动与修复后首页实拍 |
