# 交接文档：解密 HTTP 响应体（获取客户端 RSA 私钥）

> **新会话请先读完本文再动手。** 目标明确：拿到**客户端 RSA 私钥**，
> 从而离线解出服务端响应的明文。
> 本文件路径：`research/reports/handoff/HANDOFF_DECRYPT_RESPONSE.md`
> 生成时间：2026-10-01 00:2x

---

## 一、任务目标（一句话）

服务端响应体是 `<P0_b64>.<P1_b64>`：
- `P0` = RSA-2048 密文（256 字节），包裹**逐请求随机生成的会话密钥/IV**
- `P1` = AES-CBC 密文（该会话密钥加密的业务 JSON）

**要解密，必须有客户端 RSA 私钥**（服务端用它对应的公钥包裹会话密钥）。
本任务 = 找到/导出这把私钥。

---

## 二、当前状态

| 项 | 状态 |
|---|---|
| `authentication` 头算法 | ✅ **完全破解**（`CUSTOM_B64(E(CUSTOM_B64(S)))`），服务端实测通过 |
| 离线取签 | ✅ `research/deliverables/authgen.py` + `authgen_server.py` |
| Apipost 库（35 接口） | ✅ 描述/参数/预执行脚本/后执行脚本全部更新完毕 |
| Apipost 手动调试 | ✅ 可稳定拿到 `200 + 加密业务数据` |
| **响应解密** | ❌ **本任务目标，尚未达成** |

---

## 三、已确认的事实（含证据）

### 3.1 响应结构（实测）

用户从 Apipost 取回的真实响应：

```
8/lwYeMU2WQkczflytmWQKEUqQgJj2kA5nUXkGHVoBobgeeq6JSdFh6z016glwupAZnL5hz0S03WFtBG43B9Tv1b684MF07uPFYwtU15Nk0HS/BgG8TfEoLpKcm3cr8bJjAV/7XLFzTzUdUFv2mz/+htIrS+/SSFdeE8m/ES7D+xHybT72fHeZjsEuqYT9SjlOR6Hs3W/1r+d+XX4GRAau0+EjNPb9Rlc9q6nvrmJ7YEcMZg+R7kwEMByn2SkZFxjPtHPQ9cot4KYsYV7TUB0dA7mexhsqshJP0gUBsIx0/b7gcQP6i3D9FL84vgH8S1NwaqMO9HgvdsS5If4rOFGy==.<P1...>
```

- P0 段 base64 长度 **344** → 解码 **256 字节 = RSA-2048 输出** ✓
- 分隔符是 `.`，与请求体同构

### 3.2 P0 逐请求不同（关键判据）

```
[1] /app/config    P0前40=Q0jhEBc+dQm6DZtH7SvzrLOtD0CMklxwxKabRJQ7
[2] /app/config    P0前40=O5/huXERuvYv97YzE8l2EeR21CY3RV4QO/50HTbm
[3] /app/banners/0 P0前40=Az/m9xxTqkd2xREjLVEifR5dN2fo3Hf3XzgyHY3r
```

⇒ 服务端**每次请求重新生成随机会话密钥**，再用客户端公钥 RSA 包裹。
（RSA 是确定性加密，若会话密钥固定则 P0 必然相同 —— 实测不同，故确认逐请求随机。）

### 3.3 `device_fp` 的来源（本次新发现）

```bash
adb shell "su -c 'cat /data/data/com.tudou.tool/shared_prefs/GUID.xml'"
```
```xml
<string name="uuid">16613a70-7628-4a15-bc72-3d018bcd67e1</string>
```

**去掉横线 = `16613a7076284a15bc723d018bcd67e1` = 我们的 `device_fp`** ✓

⇒ 服务端能从 `authentication` 头（其明文串 `S` 含 `device_fp`）拿到该设备的标识，
因此**可以按 device_fp 索引该设备注册的公钥**。这是"服务端如何知道客户端公钥"的答案。

### 3.4 设备上**没有**持久化的 RSA 私钥（已穷尽排查）

| 排查项 | 结果 |
|---|---|
| `/data/data/com.tudou.tool/` 全部文件 | 仅 `shared_prefs/{FlutterSharedPreferences,GUID}.xml`、`files/{INSTALLATION, libCachedImageData.db, libapp.so, libcore.so, libcore2.so, profileInstalled, themes/}` |
| `INSTALLATION` (32B) | `c37fac6cf6564ef89cbb568d2be5c15e`（16 字节十六进制，非 RSA 密钥） |
| `libCachedImageData.db` | 仅 `android_metadata` + `cacheObject` 两张表（图片缓存） |
| 近 2 天修改的非缓存文件 | 无 |
| `libcore.so` / `libapp.so` / blutter `pp.txt` / `objs.txt` | 搜 PKCS#1/PKCS#8 DER 特征（`308204bd0201000282010100`、`0282010100` 等）**全部未命中** |

⇒ 私钥**只在 App 进程内存中**（运行时生成），设备上无落盘副本。

---

## 四、已排除的路径（**勿重复**）

| 路径 | 结论 |
|---|---|
| 用已知通道密钥解 P0 | 不成立（MON/SIG 密钥与 RSA 无关） |
| 内存暴力搜 AES 会话 key | 已试：吞吐 ~110 KB/s，全量 1.4 GB 需 ~3.5h，锚点邻域 16 MB 0 命中 |
| 找内嵌 PEM/DER 私钥 | 已穷尽（见 §3.4），未命中 |
| 假设 P0 会话密钥固定 | 已证伪（§3.2 P0 逐请求变化） |
| 靠 Postman/Apipost 脚本直接解密 | 不可行 —— 缺私钥，任何 JS 沙箱都解不出 |

---

## 五、建议的下一步（按性价比排序）

### 方案 A（最推荐）：从 App 进程内存中定位并导出 RSA 私钥

**思路**：App 正在运行（`emulator-5554`，pid 2225），私钥必在其内存中。
Dart 侧用 pointycastle，`RSAPrivateKey` 以 BigInt 形式持有 `n, d, p, q, dP, dQ, qInv`。

**可行的识别判据（关键）**：
拿一份真实响应 `(P0, P1)`，对内存中候选的 `(n, d)` 做验证：

```python
m = pow(int.from_bytes(P0_bytes, "big"), d, n)     # RSA 解密
# m 应为 会话密钥||IV（长度是 16/32/48 的倍数，且不是全随机 —— 可用 AES 试解 P1 验证）
aes = AES.new(m[:32], AES.MODE_CBC, m[32:48])
pt = unpad(aes.decrypt(P1_bytes), 16)              # 应为可读 JSON（含中文）
```

**只要能解出合法 JSON，就找到了正确的私钥** —— 这个判据极强，误报率接近 0。

**可执行的起步动作**：
```bash
ADB="C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"
export MSYS_NO_PATHCONV=1
"$ADB" devices
"$ADB" shell "su -c 'ps -A -o PID,NAME | grep tudou'"
# dump 进程内存（按可读区间，注意体积）
"$ADB" shell "su -c 'cat /proc/<PID>/maps'" > research/captures/maps_now.txt
# 逐区间 dd，或直接用 gdb/lldb 附加
```
> 参考已有工具：`research/toolchain/run_rd.py`、`run_dump.py`、`v13.py`（都是按 `/proc/<pid>/maps` 逐区间读的现成实现）。

**注意**：`libcore.so` 是 ARM64、经 Houdini 翻译运行，**frida 看不到 ARM64 模块**
（`Process.enumerateModules()` 321 项全是 x86_64 host 库）。
但**读 `/proc/<pid>/mem` 不受影响**（那是内核视角），所以本方案可行。

### 方案 B：把 App 当解密 oracle（用 mitm 代理喂它我们的响应）

1. 起 mitm 代理（`research/deliverables/decrypt_v5/` 内有现成思路；
   旧脚本 `out/v5/mitm_proxy.py` 已归档到 `research/archive/legacy-scripts/`）
2. 规则：把 App 请求的 `/app/config` 响应**替换成我们在 Apipost 拿到的 P0.P1**
3. App 解密后，用 `research/deliverables/decrypt_v5/mem_plaintext.py` 从内存取明文

**前提**：服务端确实用"当前 App 实例注册的公钥"包裹 —— §3.3 支持这一点（同 device_fp）。
**代价**：只能解"我们已抓到的那些响应"，不能任意解。

### 方案 C：反推私钥派生算法

若私钥是由 `device_fp` / `INSTALLATION` **确定性派生**（而非随机生成），
则可在 `libapp.so`（Dart AOT）里找到派生逻辑并复现。

**排查入口**：
- blutter 产物：`research/artifacts/blutter_out/pp.txt`（对象池）、`objs.txt`、`asm/`
- 搜关键字：`RSAPrivateKey` / `generateKeyPair` / `RSASSA` / `pointycastle` / `seed` / `fromSeed`
- 交叉验证：用两个不同 device_fp 实例跑出的 `(P0, P1)` 判断密钥是否随 device_fp 变化

**若方案 A 已成功，方案 C 可跳过。**

### 方案 D：接受现状，走内存明文提取

不改协议，直接在 App 运行态用 `mem_plaintext.py` 抓明文（已验证可行）。
适合"只要数据"，不适合"要离线/批量解"。

---

## 六、环境与坑（重要）

| 项 | 说明 |
|---|---|
| 设备 | `emulator-5554`（雷电14 / Android 14 / x86_64 + Houdini），adb 有 root（`su -c`） |
| App 进程名 | **`com.tudou.tool`**（frida 里显示为中文「囧次元」），pid 每次重启变化 |
| adb 路径 | `C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe` |
| adb 版本告警 | 每次会打印 `adb server version (41) doesn't match this client (39)`，**无害** |
| Python | 一律用项目 venv：`./.venv/Scripts/python.exe`（含 unicorn / pycryptodome / frida） |
| 项目根 | `C:/Users/haige/Desktop/instruct/囧次元` |
| 服务器 | `http://43.145.33.254:27990`（明文 HTTP） |
| 服务端语义 | **错误也返回 HTTP 200**，业务码在 body；加密体 = 成功，明文 JSON = 失败 |
| 路径约定 | 研究区脚本一律 `import paths as _P`（`research/toolchain/paths.py`），禁止硬编码相对路径 |
| 结构校验 | `node scripts/validate-structure.mjs`；改文档后必须跑 |
| 注意 | `tools/` 被 adb/frida 进程锁定，**不要尝试移动** |

---

## 七、文件与脚本索引

### 核心交付（`research/deliverables/`）
| 文件 | 说明 |
|---|---|
| `authgen.py` | `authentication` 离线生成器（`--selftest` / `--test-server`） |
| `authgen_server.py` | 本地取签服务：`GET /auth`、`GET /health`、`POST /store`（密文归档）、`POST /classify` |
| `verify_server.py` / `verify_corpus*.py` | 服务端与语料验证 |
| `probe_matrix2.py` | 22 端点能力矩阵 |
| `decrypt_v5/mem_plaintext.py` | **App 运行态内存明文提取**（方案 D 用） |

### 工具链（`research/toolchain/`）
| 文件 | 说明 |
|---|---|
| `paths.py` | 统一路径解析（**必用**） |
| `emu_v11.py` / `emu_v14.py` / `v13.py` | libcore.so 的 Unicorn 模拟器 |
| `mcp_client.py` | MCP Streamable-HTTP JSON-RPC 客户端（直调 Apipost MCP） |
| `pull_apipost*.py` | 拉取 Apipost 库 |
| `run_dump.py` / `run_rd.py` / `dump_all.py` | **按 /proc/pid/maps 读设备内存**（方案 A 可直接复用） |
| `probe_D.py` | 受控实验主入口（`A1HEX`/`KEYHEX`/`IVHEX`/`TAG`） |
| `sm4.py` / `brute_E.py` / `try_custom_aes.py` | 密码学排除性验证 |

### 数据（`research/`）
| 路径 | 说明 |
|---|---|
| `artifacts/libcore.so`、`libcore_dev_img.bin`、`regions_min/`（28.6 MB） | authgen 运行必需 |
| `artifacts/blutter_out/` | Dart 对象池 / asm / objs（方案 C 用） |
| `captures/proxy_capture.jsonl` | 真机抓包（含真实响应） |
| `captures/apipost_responses.jsonl` | Apipost 后执行脚本归档的密文（自动累积） |
| `corpus/O_corpus.json` | 语料（ts ↔ auth 密文） |
| `reports/VERIFICATION.txt` | 全部验证记录（含负结果清单） |
| `reports/apipost_id_mapping*.json` | Apipost 三轮更新的 ID 映射 |

### 文档（`docs/`）
| 文件 | 说明 |
|---|---|
| `algorithm-auth.md` | `authentication` 算法原理与判定依据 |
| `reverse-journal-auth.md` | 逆向全过程（14 阶段，含被证伪的假设） |
| `api/apipost-library.md` | Apipost 库分析与三轮更新记录 |
| `api/apipost-testing.md` | 在 Apipost 里手动调试的完整步骤 |
| `architecture.md` / `structure.md` | 架构与目录职责 |

---

## 八、快速上手（新会话第一屏照抄）

```bash
cd C:/Users/haige/Desktop/instruct/囧次元

# 1) 确认环境
./.venv/Scripts/python.exe research/deliverables/authgen.py --selftest     # 期望 PASS
curl -s http://127.0.0.1:8791/health                                        # 取签服务（可能需重启）

# 2) 若服务未起
./.venv/Scripts/python.exe research/deliverables/authgen_server.py --warmup &

# 3) 取一份真实响应样本（含 P0/P1）
./.venv/Scripts/python.exe - <<'EOF'
import sys, json, urllib.request, random, http.client
sys.path.insert(0, "research/toolchain")
r = json.load(urllib.request.urlopen("http://127.0.0.1:8791/auth", timeout=60))
c = http.client.HTTPConnection("43.145.33.254", 27990, timeout=15)
c.request("GET", "/app/config", headers={
  "x-version":"2020-09-17","user-agent":"Dart/3.6 (dart:io)","appid":"4150439554430529",
  "ts":str(r["ts"]),"accept-encoding":"identity","authentication":r["authentication"],
  "tcs":"2","content-type":"application/json; charset=utf-8",
  "nonce":"%08d"%random.randint(0,99999999)})
d = c.getresponse().read()
open("research/captures/one_response.txt","wb").write(d)
p0,_,p1 = d.decode().partition(".")
print("P0 b64=%d  P1 b64=%d" % (len(p0), len(p1)))
EOF

# 4) 进入方案 A：dump App 内存
ADB="C:/Users/haige/.trae-cn/extensions/hyb1996.auto-js-pro-ext-9.0.9/tools/adb.exe"
export MSYS_NO_PATHCONV=1
"$ADB" shell "su -c 'ps -A -o PID,NAME | grep tudou'"
"$ADB" shell "su -c 'cat /proc/<PID>/maps'" > research/captures/maps_now.txt
```

---

## 九、成功判据

拿到候选 `(n, d)` 后：

```python
m  = pow(int.from_bytes(P0, "big"), d, n).to_bytes(256, "big")
# 1) m 应"看起来像"密钥材料：长度是 16 的倍数、熵高但长度短（常见 32 或 48 字节）
# 2) 用 m 做 AES-CBC 解 P1 → 应得到可读 JSON（含中文、code=200）
```

**两条同时成立 ⇒ 私钥正确，任务完成。**
完成后请把私钥与解密脚本落到 `research/deliverables/decrypt_response.py`，
并更新 `docs/api/apipost-testing.md`（把"离线不可解"改成"可解"）。

---

## 十、给新会话的建议开场白

> 读 `research/reports/handoff/HANDOFF_DECRYPT_RESPONSE.md`，
> 按 §五 方案 A 执行：从 `emulator-5554` 上 `com.tudou.tool` 进程内存里导出客户端 RSA 私钥，
> 用 §九 的判据验证。先跑 §八 的快速上手命令。
