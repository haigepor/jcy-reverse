# 囧次元响应体解密 · 现状总结与下一步分析路线

> 2026-10-01 · 目标：`com.tudou.tool`（LDPlayer emulator-5554）响应体
> `<P0_b64>.<P1_b64>` 离线解密（P0=RSA-2048 包裹会话密钥，P1=AES-CBC 业务 JSON），
> 最终达成"接口正常请求 + 响应实时解密"。

---

## 一、核心结论（全部为本轮实证，非推测）

### 1.1 已打通的链路

| 环节 | 状态 | 证据 |
|---|---|---|
| 响应体格式 | ✅ `<P0_b64>.<P1_b64>`，P0 恒 256B RSA-2048 PKCS1v15，P1 恒 16 倍数 AES-CBC | MITM 全量捕获 |
| 自定义 base64 | ✅ 字母表 `5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj` | P0/P1/auth 通用，反复验证 |
| 客户端 RSA 私钥 | ✅ `research/captures/rsa_scan/priv_from_go.pem` 有效 | 活体 10+ 条新鲜响应全部解出 K16 |
| K16（会话密钥材料） | ✅ 恒 16 字节 ASCII（`[A-Za-z0-9]`），每请求随机 | RSA PKCS1 unpad 长度=16 |
| K16 内存配对 | ✅ K16 在活体 dump `605_737e737e6289d000` 区命中（`H78BQEEYWV74BGQR`、`URTASDHHCRED52RM`），后随全零缓冲 | pair_hunt2.py 紧耦合配对 |
| native call 输入协议 | ✅ `std_b64( AES-CBC(qPwClBj7j7ZQraSm, p3JdVQl3q7WQJIgG, JSON) )` | Unicorn EVP_DecryptInit_ex hook：key/iv 即通道常量 |
| native 输入处理流程 | ✅ b64dec → AES dec → `JSON.parse` → action dispatch → handler | Unicorn upd-ret 解密输出 + parse_error 行为比对 |
| MITM 管线 | ✅ cap_proxy(PC:27990→43.145.33.254:27990) + `adb reverse`，`bodies_now.jsonl` 实时 | 活体 19+ 条 |
| 请求触发 | ✅ force-stop + 重启 SplashActivity 必产生新请求（tap 不可靠） | pair_hunt2 一轮 12 条 |
| frida 环境 | ✅ frida-server 17.8.2（设备）= frida-py 17.8.2（PC venv），须 adb forward tcp:27042，按 PID attach（进程名被隐藏） | run_frida.py |

### 1.2 libcore 关键符号（dynsym 实证，基址待定位）

```
EVP_DecryptInit_ex        0x387db4    aes_v8_set_encrypt_key  0x3851e0
EVP_DecryptUpdate         0x3877d0    aes_v8_set_decrypt_key  0x385400
EVP_DecryptFinal_ex       0x387be4    aes_v8_cbc_encrypt      0x385540
RSA_private_decrypt       0x43e324    AES_set_encrypt_key     0x3842ac
AES_set_decrypt_key       0x3845e0    (native 入口 call=0x307a38, init=0x2fdc24)
```

### 1.3 Dart 侧关键事实（blutter 实证）

- `apiDecrypt@0xbd7a68`：构造 `{"action":"api_decrypt","payload":{"data":<响应体原样>,"path":<路径>}}`，data **原样透传**。
- `g_http_client` 响应处理：utf8 解码后首字节 `== '{'` 走明文分支，否则调 `apiDecrypt`。
- `__call@0x5afa54`：Dart→native 通道加密用 qPwC/p3Jd；`dartCallback@0x5daf34`：native→Dart 回调同通道。
- `_loaderCall@0x77e014`：**另一套**密钥 `kFGTbLlOzFHQCIKp / F3q22XoM8l6T2Ydc`（loader 通道，未在本任务范围）。
- `getRandomString` 字母表：`AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890`。

### 1.4 唯一缺口

**P1 的 AES key/iv 派生公式：K16 → (key, iv)。**
其余全部打通。RSA 解 P0 已由本地私钥完成；只要派生公式确定，解密端即可离线交付。

---

## 二、本轮已排除的路线（防止回头路）

1. **9 种 K16 朴素派生 × 3 种 IV 方案**（direct/reverse/md5 族/md5hex16/sha1_16/sha256_16/salt 族 × IV=p1[:16]/zero/key）：本地对真实配对样本全部不命中。
2. **P1 前 16B 是 IV 的结构假设**（IV||ciphertext）：解出非 JSON，排除。
3. **AES key schedule 扫描**（加密型 + 解密型 EqDC 双检测器，`scan_aes_sched2.py`）：emu 内存 throw 停机瞬间、活体全量 dump、旧 dump 全部 0 命中——EVP_CIPHER_CTX_free zeroize 清掉了调度，此路概率极低。
4. **native 输入用自定义字母表**：错。Unicorn 证实 native 按 **std** 表 b64 解码输入（喂 cus 串被硬解成乱字节 `7ea92f10...`，与本地复算完全一致）。
5. **输入协议双层 b64**（AES 明文是 b64 文本）：错。upd-ret 铁证 native 解出的 JSON 直接 parse（"eyJh..." 被当 JSON 报 `invalid literal 'e'`）。
6. **tap 触发请求**：不可靠（焦点/页面状态影响）；**force-stop 重启**可靠。
7. **toybox dd 转 16 进制 skip**：32 位有符号溢出；必须用 busybox dd + `iflag=skip_bytes` 或 Python 预算十进制。

---

## 三、当前卡点（Unicorn 路线的精确死因）

Unicorn（`emu_keyhook.py` / `EmuKey`）已能完整走通：init → call → 输入层 AES(qPwC/p3Jd) 解密 → 外层 JSON parse → action dispatch。卡在 handler 内部：

1. **handler 对 `payload.data` 做 `JSON.parse`**（0x328b84），data="P0.P1" 密文串必然抛 `parse_error`。
2. 该异常在真机上**本应被 catch 后走密文解密分支**——但 Unicorn 的 C++ 异常 unwinding 不工作：
   - 根因：`dl_iterate_phdr` 落到空 RET 桩返回 0，libunwind 拿不到 phdr 信息。
   - 已尝试补真桩（构造 dl_phdr_info + 嵌套 `uc.emu_start` 调回调）：**嵌套 emu_start 污染外层执行状态**（PC 被带到 until 地址），Unicorn python 绑定不支持 hook 内嵌套。
3. 若把 data 硬编码成合法 JSON（嵌套 `{"data":body,"path":path}`），dispatch 过了但 handler 深处撞**空函数指针调用**（`0x30cce0: ldr x8,[sp,#8]; blr x8`，PC=0 crash）——handler 依赖某个未注册的基础设施回调，模拟环境缺这层。

**结论：Unicorn 路线走到 handler 内部"差一步"，但修复成本（异常机制仿真 + 回调体系补全）高；转真机 hook 是正确选择。**

---

## 四、下一步路线图（按优先级）

### 路线 1（主攻，成本最低）：Frida 特征码扫描 + 函数序言 hook —— **就绪未跑**

libcore.so 被**自定义加载器匿名映射**（frida enumerateModules 321 个模块中无 libcore/libapp/libloader；dlopen 变体 hook 也未捕获其加载）。因此放弃符号定位，改用**内存特征码**：

- `hunt_key2.js`（已写好）：本地 libcore.so 提取 6 个函数的 20B 序言特征 → 扫全部 r-x 匿名段 → `base = 命中地址 - 函数偏移` → 按偏移 hook：
  - `aes_v8_set_decrypt_key / set_encrypt_key`（onEnter 直接读 `args[0]` = **key 明文**）
  - `EVP_DecryptInit_ex`（`args[3]`=key、`args[4]`=iv）
  - `RSA_private_decrypt`（onLeave 读 `args[2]` 解密输出 = K16，顺带复核密钥形态）
  - `aes_v8_cbc_encrypt`（onLeave 读输出 = **P1 明文首块**，双保险）
- `run_frida.py` 刚改为 **attach 模式**（app 运行中 libcore 已映射；spawn 时还没加载，之前 0 命中的原因）——**未执行，这是第一个待跑动作**：
  ```
  ./.venv/Scripts/python.exe -u research/toolchain/run_frida.py
  # > research/captures/rsa_scan/frida_hunt2.log 后 grep SET_KEY|EVP_INIT|RSA_DEC|CBC_DEC
  ```
- 失败回退：
  - r-x 扫不到特征 → 放宽扫 `r--`/`rw-` 段；或加长特征（40B）；或特征被壳改写 → 改扫**解密调度特征**（EqDC 中间轮含 InvMixColumns，运行时才出现）。
  - hook 挂上了但 SET_KEY 不出 → 说明 handler 没走到（data 协议问题），转路线 4。

### 路线 2：hook EVP 层反推（路线 1 的加密型增强）

若 `aes_v8_*` 入口因 OpenSSL armcap 探测选了其他实现（vpaes/C 版）而不触发：
- hook `EVP_DecryptUpdate`（0x3877d0）入口，x0=EVP_CIPHER_CTX：解析 `cipher_data` 指针 → AES_KEY 结构（rounds@0x0, rd_key@0x8）→ 拿到**解密调度**（EqDC）→ `scan_aes_sched2.expand_dec` 反推 16B key。
- CBC 模式必经 `aes_v8_cbc_encrypt` 或等价函数，onEnter 的 `args[4]`=ivec 直接拿 IV。

### 路线 3：真机轮询抓调度（无 hook 备选）

解密瞬间解密调度必在内存（zeroize 在 free 之后）。Frida setInterval 轮询扫 rw- 匿名段跑 EqDC 检测（`scan_aes_sched2.expand_dec` 的 W4 校验），命中即得 key。窗口竞争激烈，成功率低于 hook，仅当 1/2 都失效。

### 路线 4：native 派生逻辑静态还原（兜底，成本最高）

从 Unicorn 已知断点出发：
- `0x30cce0` 空指针调用所在函数 = handler 核心区（0x30cxxx）。反汇编该函数（`dasm.py`），找 `parse(data)` 之后对 `data` 的处理：split('.') → 自定义 b64 解 P0 → `RSA_private_decrypt` → K16 → **派生函数** → EVP。
- 派生函数识别特征：输入 16B、输出 16B/32B；留意对 K16 的变换（哈希/查表/与 device_id 等字符串拼接）。libcore dynsym 里可先确认是否有 EVP_md5/SHA256_Init 等被 handler 调用（PLT 触发记录）。
- Unicorn 打桩跳过空回调（`0x30cce0` 强制 PC+8）已试：不 crash 但返回 x0=0——该回调参与语义，不可硬跳。

### 路线 5：Unicorn unwind 修复（最后手段）

Python 侧手工模拟 unwinding：`__cxa_throw` hook 捕获 (PC, LR)，解析 libcore `.eh_frame`/`.gcc_except_table` 定位 landing pad，直接 set PC 伪造 catch。工程量大，仅当以上全灭。

---

## 五、派生公式确定后的交付动作（一次性清单）

1. **写 `research/deliverables/decrypt_response.py`**：自定义 b64 → RSA(priv_from_go.pem) → K16 → 派生 → AES-CBC → JSON；输入 `<P0>.<P1>` 字符串/文件/bodies_now.jsonl 全量。
2. **实时链路**：cap_proxy 管线已在跑，解密端接上即"请求正常 + 响应实时解密"闭环；必要时把解密器挂到 proxy 落盘钩子。
3. **文档更新**：`docs/crypto/http-body.md`（"离线不可解"→派生公式+可解）、`docs/api/apipost-testing.md`、Apipost 云库 Banner 接口描述（create_target 更新）。
4. `node scripts/validate-structure.mjs` 结构校验。
5. 可选：cyberchef recipe（From Base64 自定义字母表 + AES Decrypt）。
6. 清理：设备 iptables REDIRECT 规则、frida-server 进程、后台扫描任务。

---

## 六、可直接复用的工具清单

| 文件 | 用途 |
|---|---|
| `research/toolchain/run_frida.py` | Frida 驱动（attach 模式，已适配按 PID + forward 27042） |
| `research/toolchain/hunt_key2.js` | 特征码扫描 + 6 函数 hook（**下一个待跑**） |
| `research/toolchain/hunt_key.js` | 符号版 hook（libcore 匿名映射后已无用，留档） |
| `research/toolchain/pair_hunt2.py` | 紧耦合配对：重启触发→设备转储→grep K16→只拉命中文件→派生测试 |
| `research/toolchain/emu_keyhook.py` | Unicorn 全 hook 基座（EVP/AES/RSA/throw/upd-ret），含通道加密输入构造 |
| `research/toolchain/emu_apidecrypt.py` / `emu_schedscan.py` | throw 异常消息读取 / throw 瞬间调度扫描 |
| `research/toolchain/scan_aes_sched2.py` | 加密+解密(EqDC) 双型 AES 调度检测 |
| `research/toolchain/cap_proxy.py` | MITM 代理（PC 127.0.0.1:27990 → 43.145.33.254:27990） |
| `research/toolchain/dump_mem.py` | 进程全量内存转储（busybox dd，十进制 skip） |
| `research/captures/rsa_scan/bodies_now.jsonl` | 活体抓包（实时增长） |
| `research/captures/rsa_scan/priv_from_go.pem` | 客户端 RSA-2048 私钥（已验证） |

## 七、环境速查

- adb 全部命令带 `ANDROID_ADB_SERVER_PORT=5039`（双版本互杀）+ `MSYS_NO_PATHCONV=1`
- frida：`adb forward tcp:27042 tcp:27042`；server 已在 `/data/local/tmp/frida-server`（root 后台跑）
- 触发请求：`am force-stop com.tudou.tool` + `am start -n com.tudou.tool/app.video.guoguo.SplashActivity`
- 27990 端口曾出现双进程抢占（旧 cap_proxy 残留）——重连前 `netstat -ano | findstr 27990` 核对单监听
