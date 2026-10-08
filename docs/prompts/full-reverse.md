# 囧次元完整逆向分析 · V5 执行提示词

> **用法**：把「一」到「十二」整段内容复制给新对话的 AI 助手即可直接执行。
> 本版在 V4 基础上，纳入了 2026-09-29 实测完成的 **Magisk 面具环境落地**、
> **5 个逆向模块安装与配置**、以及一条**颠覆 V4 结论的关键发现**（第四节）。

---

## 一、任务与最终验收标准

### 1.1 任务
对 `com.tudou.tool`（囧次元）在**雷电模拟器 14** 上开展完整逆向分析：

1. 先盘点并评估现有工具与文件，明确**已具备能力**与**存在缺口**；
2. 对应用进行**网络抓包**，系统性梳理**全部接口**的请求与响应结构；
3. **逐一还原**其加密与解密逻辑；
4. 工具不足时，通过**网络搜索 + GitHub 深度检索**，查找、安装并配置所需工具；
5. 必要时**安装并配置 LSPosed 模块**辅助处理；
6. 最终**打通所有接口**，能正常发起请求，成功获取**视频列表**与**视频播放地址**。

### 1.2 验收标准（必须逐条给出可复现证据）
| # | 验收项 | 通过判据 |
|---|---|---|
| A1 | 接口清单完整 | 所有端点列出方法/URL/参数/头/请求体/响应体结构，来源可追 |
| A2 | 三通道加解密可复现 | 监控 / 信令 / HTTP body 三通道各有独立解密脚本 + 真实密文样本可解出明文 |
| A3 | 视频列表打通 | 用自写客户端发起真实请求，返回 `code` 成功且含视频条目 |
| A4 | 播放地址打通 | 同上，拿到可播放的 m3u8/mp4 直链 |
| A5 | 每步可验证 | 每步都有命令 + 真实输出；未执行的写「未执行」，禁止推测当结论 |
| A6 | 环境配置就绪 | 第六节「配置与启用清单」逐项打勾完成 |

### 1.3 执行纪律
- 每一步**先说明将运行的命令 → 实际运行 → 如实回报真实输出**。
- **禁止**伪造 hash / HTTP 响应 / 偏移 / patch 结果 / 验证结论。
- 遇到失败**立即停下报告**，不要静默重试或跳过。
- 每完成一个阶段，向 `research/reports/VERIFICATION.txt` 追加审计链条目（沿用现有 `[F*]` 格式，当前至 `[F10]`）。

---

## 二、目标与环境基线（已实测，直接用，勿重复踩）

### 2.1 目标 App
| 项 | 值 |
|---|---|
| 包名 | `com.tudou.tool` |
| 名称 | 囧次元 |
| versionName / Code | 1.5.8.0 / 88 |
| minSdk / targetSdk | 24 / 35 |
| 技术栈 | Flutter 3.27.x + Dart 3.6.0（AOT） |
| **primaryCpuAbi** | **`arm64-v8a`（只有 arm64 原生库，无 x86_64）** |
| 原生库 | `libapp.so` 12.3MB / `libflutter.so` 10.8MB / `libcore.so` 6.8MB / `libloader.so` 6.2MB 等 |
| 原始样本 | `assets/assets/apk/base.apk`（43MB，只读，未动） |
| 工作区 | `C:\Users\haige\Desktop\instruct\囧次元` |

### 2.2 雷电模拟器 14
| 项 | 值 |
|---|---|
| 安装目录 | `C:\leidian\LDPlayer14` |
| 命令行工具 | `ldconsole.exe`、`adb.exe` |
| 版本 | `dnplayer v14.0.29.0` |
| 实例 | index `0` → 设备名 `emulator-5554`，540×960 @240dpi |
| Android | **14 / API 34** |
| ABI | **x86_64 + libhoudini ARM 转译** |
| 机型伪装 | `25102RKBEC` / REDMI（`ro.product.model`） |
| 配置文件 | `C:\leidian\LDPlayer14\vms\config\leidian0.config` |
| 共享目录 | 宿主 `C:\Users\haige\Documents\leidian14\Pictures` ↔ 设备 `/sdcard/Pictures` |

### 2.3 Magisk 面具环境（**本轮已完整落地，V4 里"待尝试"的部分已解决**）
| 组件 | 版本 / 位置 | 状态 |
|---|---|---|
| Kitsune Mask（面具主体） | v27.2-kitsune-4 (27002)，**Magisk Delta System Mode 装入 /system** | ✅ 已生效 |
| MagiskSU | `/system/bin/su`（雷电自带 su 已删除） | ✅ `uid=0 context=u:r:magisk:s0` |
| Zygisk Next | 1.5.0 (843-5217106) | ✅ `zygiskd64` 常驻 |
| LSPosed | v2.1.0 (7769) | ✅ `lspd` 常驻 |
| FlutterTap | v1.0.0（Zygisk，Flutter 流量重定向 + TLS 绕过） | ✅ 已加载 |
| Zygisk-Assistant | v2.1.4（Root 隐藏，替代装不上的 Shamiko） | ✅ 已加载 |
| HMA-OSS Zygisk | oss-168（隐藏应用列表） | ✅ 已加载 |
| frida-server | 17.8.2，`/data/local/tmp/frida-server` | ✅ 已部署 |

**Magisk 关键命令**（Kitsune 支持，全程可绕开 GUI）：
```bash
adb shell "su -c 'magisk -v'"                                   # v27.2-kitsune-4:MAGISK:R
adb shell "su -c 'magisk --install-module /data/local/tmp/x.zip'"
adb shell "su -c \"magisk --sqlite 'SELECT * FROM settings'\""
```

### 2.4 网络与代理
| 项 | 值 |
|---|---|
| 可用 HTTP 代理 | **`127.0.0.1:7897`**（GitHub 直连会被 reset，`13643` 已关闭） |
| GitHub Release 镜像 | `https://gh-proxy.com/<原始URL>` |
| 目标 API 主机 | `http://43.145.33.254:27990`（**明文 HTTP**，非 HTTPS） |

---

## 三、第一阶段：资产盘点与能力/缺口评估（**必须先做，产出评估表**）

### 3.1 盘点清单
```bash
cd "C:/Users/haige/Desktop/instruct/囧次元"
ls -la; ls research/ | head -60; ls research/deliverables/client/; ls tools/; ls docs/ docs/setup/
cat research/reports/VERIFICATION.txt | tail -60
cat research/reports/handoff/HANDOFF_PROMPT_V4.md
```

### 3.2 已有产物（已知存在，核对即可）
| 类别 | 路径 | 说明 |
|---|---|---|
| 分析主文档 | `research/reports/API_ANALYSIS.md` | 静态+动态分析主文档 |
| 审计链 | `research/reports/VERIFICATION.txt` | `[F1]`~`[F10]` 证据链 |
| 离线客户端 | `research/deliverables/client/gg_client.py` | 监控/信令双通道解密，**已验证** |
| frida 脚本族 | `research/deliverables/client/gg_*.js` | 纯 native hook 脚本（真机七轮） |
| blutter 产物 | `research/artifacts/blutter_out/` | `pp.txt` 对象池 2.6MB、`objs.txt`、`asm/`、IDA 脚本、frida 模板 |
| reFlutter 产物 | `reflutter_work/` | `dump.dart`、组合包 APK |
| 抓包数据 | `research/ggcap.pcap`、`research/auth_samples.json`(88条)、`research/auth_full_rows.json`(28条)、`research/resp_bodies.tsv` | |
| native 库 | `research/nativelibs/libcore.so`、`libapp.so` | |
| RSA 密钥 | `research/RSA_PUBLIC_KEY.pem` + `research/auth_rt7_log.jsonl` 内 `bn_n/bn_e/bn_d/bn_p/bn_q` | **libcore 内嵌密钥对已 dump** |
| 工具 | `tools/jadx`、`tools/apktool.jar`、`tools/blutter`、`tools/platform-tools`、`tools/PCAPdroid_v2.0.2.apk`、`tools/uber-apk-signer.jar` | |
| 环境模块包 | `tools/re-env/modules/`（gitignored） | FlutterTap / TrustMe / SSLUnpinner / Zygisk-Assistant / HMA-OSS |
| 环境脚本 | `scripts/re-env/start_re_env.bat`、`verify_env.py` | 一键拉起 + 验收 |
| 环境文档 | `docs/setup/ldplayer-magisk-env.md`、`docs/setup/re-modules.md` | 搭建全过程 |

### 3.3 已确认的加密结论（**勿再推翻重来**）
| 通道 | 载体 | 算法 | key | iv |
|---|---|---|---|---|
| 监控 | `libcore` C2 | AES-128-CBC PKCS7 | `qPwClBj7j7ZQraSm` | `p3JdVQl3q7WQJIgG` |
| 信令 | `libloader` IPC | AES-128-CBC PKCS7 | `kFGTbLlOzFHQCIKp` | `F3q22XoM8l6T2Ydc` |
| HTTP body | `apiEncrypt`/`apiDecrypt` | 随机会话 key AES-CBC + **RSA-2048 包裹** | 每请求随机 | 每请求随机 |

- 响应体 = `P0b64.P1b64`：**P0 恒 256B（RSA-2048）**，**P1 恒 16 倍数（AES）**。
- FFI 响应帧可离线解：`[16B IV][qPwC-CBC(JSON帧)]`。
- 部分端点（`/app/messagebox/give_me`、`/app/danmu`）返回明文 JSON。
- **架构要点**：Dart 层的 `clearKey`/`apiEncrypt`/`apiDecrypt` 是**诱饵循环**（`getRandomString` 假 key）；
  真实数据走 `_rawCall`(明文 JSON) → `libcore!call`(qPwC 加密) → `dartCallback` 异步回调。

### 3.4 接口结论（已还原部分）
- 请求形态：`GET http://43.145.33.254:27990/app/video/list?channel=N&sort=weight&limit=6&page=1`，无 body
- 必需头：`authentication`(112B b64) / `ts`(毫秒) / `nonce`(8位) / `appid=4150439554430529` / `tcs=2` / `x-version=2020-09-17`
- UA：`Dart/3.6 (dart:io)`
- 重放实测三拒：无 auth → `30000 authentication is empty`；旧 ts+旧 auth → `403502`；旧 auth+新 ts → `403501`
  ⇒ **服务器把 authentication 与 ts 绑定校验**
- `authentication` 结构 = **15B 恒定前缀** `e8cb1f120ef5a42c59e22a4d00279e` + **1B 代次**(0x9c–0x9f) + **96B 密文**
- `authentication = f(ts)` 精确确定性函数（与 nonce/URI 无关）

### 3.5 能力/缺口矩阵（**本阶段要产出的核心表，请据此填实**）
| 能力 | 现状 | 缺口 |
|---|---|---|
| 静态 Dart 还原 | ✅ blutter `pp.txt` + `asm/` 齐备 | — |
| 静态 native 还原 | ✅ `libcore.so` 有 11579 个导出，OpenSSL 完整 | 反汇编 `call@0x307a38` 未做完 |
| 抓包 | ✅ 已有 pcap + 样本；PCAPdroid 可补抓 | 需确认抓包覆盖全端点 |
| 监控/信令解密 | ✅ `gg_client.py` 已验证 | — |
| HTTP body 解密 | ⚠️ RSA 私钥已 dump，**pcap 内 P0→会话key→P1 未跑通** | **必补** |
| **authentication 生成** | ❌ **96B 算法未破**（全滑窗 AES 暴力 0 命中） | **核心缺口** |
| 动态 hook（模拟器） | ⚠️ frida spawn 工作流通，但见第四节崩溃问题 | **必须先解决** |
| LSPosed 模块 | ✅ 已装并启用 | 因 App 崩溃未实测生效 |

---

## 四、⚠️ 必读：一条颠覆 V4 结论的关键发现

### 4.1 现象
V4 记录「x86_64 + houdini **可跑 App**」。**本轮实测推翻该结论**：

```bash
adb shell "su -c 'dumpsys package com.tudou.tool | grep primaryCpuAbi'"
#   primaryCpuAbi=arm64-v8a

adb shell "su -c 'head -30 /data/tombstones/tombstone_01'"
```
```
Cmdline: com.tudou.tool
pid: 9372, tid: 9471, name: DartWorker  >>> com.tudou.tool <<<
signal 11 (SIGSEGV), code 128 (SI_KERNEL), fault addr 0x0
backtrace:
  #00 pc 00000000003aa43c  /system/vendor/lib64/libhoudini.so
  #01 pc 0000000000313e06  /system/vendor/lib64/libhoudini.so
  #02 pc 0000000000310ff2  /system/vendor/lib64/libhoudini.so
  #03 pc 000000000030e5ce  /system/vendor/lib64/libhoudini.so
```

`crash_copyx86/content.txt` 有同源记录。**结论**：App 只有 arm64 原生库，雷电靠 libhoudini 转译，
**Dart AOT 代码在转译层 SIGSEGV**，进程起不来。

> 注：`frida` 环境本身完全正常——`spawn` 成功、枚举到 304 个模块、11 个线程。
> 崩溃发生在 Dart 虚拟机启动之后。

### 4.2 处置策略（**开工第一件事就是重新验证并择路**）
| 路线 | 做法 | 适用 |
|---|---|---|
| **R1（推荐）** | 换 **arm64 原生环境**：真机 / arm64 系统镜像模拟器（MuMu 等）/ 云真机 | 需要稳定动态 hook 时 |
| **R2** | 继续在雷电上**只做静态 + 离线解密**，动态部分用 `unidbg` 在 PC 侧模拟执行 `libcore.so` | 不依赖 App 跑起来 |
| **R3** | 再试一次雷电：先冷启动、清理 tombstones，观察是否**偶发崩溃**（若是偶发，可用 spawn 抢在崩溃前 hook） | 低成本试错 |

**要求**：先跑 3 次冷启动复现实验，如实记录崩溃率，再决定主攻路线，**不要默认沿用 V4 的"可跑"假设**。

---

## 五、执行阶段（每阶段含验收，按序推进）

### P0 · 环境健康检查与修复
```bash
cd /c/leidian/LDPlayer14
./ldconsole.exe runninglist
./adb.exe devices                                   # 期望 emulator-5554  device
./adb.exe shell "su -c 'magisk -v'"
./adb.exe shell "su -c 'ps -A -o PID,NAME | grep -E \"zygiskd64|lspd|frida-server\"'"
```
修复动作见第七、八节。**frida-server 不自启**，每次重启模拟器后必须重跑启动命令。

### P1 · 网络抓包（补齐全端点覆盖）
```bash
# 方案 A（推荐，免 root，应用层明文 HTTP 无需 MITM）
adb install -r "tools/PCAPdroid_v2.0.2.apk"          # 用宿主机路径
# 方案 B：FlutterTap（已装）——把目标 App 流量转发到 PC 侧代理
#   打开 com.eduardolopes.fluttertap → 勾选 com.tudou.tool → 填 PC IP:端口
# 方案 C：复用已有 research/ggcap.pcap，确认其端点覆盖度
```
产出：`research/ggcap_v5.pcap` + 端点覆盖清单（哪些端点已抓、哪些缺）。

### P2 · 接口全量梳理
对每个端点产出：方法 / URL / query / 头 / 请求体（密文+明文）/ 响应体（密文+明文）/ 状态码 / 业务码。
**已知端点**（以 `docs/api/endpoints.md` 为底，补齐并交叉验证）：
```
/app/video/list        /app/video/play       /app/video/device-base
/app/messagebox/give_me (明文)   /app/danmu (明文)   ...
```
产出：`research/reports/API_MATRIX_V5.md`（一表打尽）。

### P3 · 加解密逐一还原
1. **监控通道**：用 `qPwC`/`p3Jd` 解一条真实密文，与 `gg_client.py` 结果比对。
2. **信令通道**：用 `kFGT`/`F3q2` 同上。
3. **HTTP body（必补）**：
   - 从 `research/auth_rt7_log.jsonl` 取 RSA 私钥（`bn_n/bn_d/bn_p/bn_q`，`e=010001`）
   - 对 pcap 里的响应体按 `'.'` 切分 → `RSA_private_decrypt(P0)` → 16 字节 ASCII 会话 key
   - 用该 key AES-CBC 解 P1 → 业务 JSON
   - 目标端点：`/app/video/list`、`/app/video/play`、`/app/video/device-base`
4. **authentication 96B（核心缺口）**：
   - 反汇编 `libcore!call@0x307a38`（真机 vaddr），定位真正参与签名的路径
   - 交叉验证 `libapp` 侧 `apiEncrypt@0x7eee0c`
   - 已知 `auth=f(ts)`，可用「固定 ts 反复取 auth」构造确定性样本做差分

产出：`research/deliverables/decrypt_v5/*.py`，每个通道一个可独立运行的脚本 + 真实样本断言。

### P4 · 端到端打通（**最终验收**）
```bash
# 目标：不发散，直接跑通两条链路
python research/deliverables/decrypt_v5/run_list.py    # → 视频列表（code 成功 + 条目）
python research/deliverables/decrypt_v5/run_play.py    # → 播放地址（可播直链）
```
要求：脚本自包含（只依赖 `requests` + `pycryptodome`），能独立重跑出结果。

### P5 · 工具/模块按需补充
仅当 P1–P4 遇到明确缺口时才做，且必须：
1. 先 GitHub 检索（用 2.4 节代理），**检查是否含 `zygisk/x86_64.so`**（雷电是 x86_64，arm64-only 模块装了不加载）；
2. 下载 → 校验体积/结构 → 安装 → **配置启用**（见第六节）→ 重启 → 从日志确认加载；
3. 记录到 `docs/setup/re-modules.md`。

---

## 六、必须执行的「配置与启用清单」（用户明确要求）

> 这一节是**必做项**，不是可选建议。每项完成后打勾并附验证命令输出。

### C1 雷电模拟器侧
```bash
# 关模拟器 → 改配置 → 重启
cd /c/leidian/LDPlayer14
cp vms/config/leidian0.config "vms/config/leidian0.config.bak.$(date +%Y%m%d_%H%M%S)"
```
`vms/config/leidian0.config` 必须为：
| 键 | 值 | 作用 |
|---|---|---|
| `basicSettings.rootMode` | `true` | 开启 ROOT |
| `basicSettings.standaloneSysVmdk` | **`true`** | **system 分区可写入**（`false`=共享只读，装不了面具） |
```bash
./ldconsole.exe reboot --index 0
adb shell "su -c 'mount -o remount,rw /; touch /system/.t && echo WRITE_OK && rm -f /system/.t'"
```

### C2 Magisk 面具侧（**最容易漏，漏了 adb 就没 root**）
| 配置 | 路径 | 值 |
|---|---|---|
| **超级用户访问权限** | 面具 App → 设置 → 超级用户 | **应用和 ADB**（默认「仅应用」会让 `adb shell su` 一律 Permission denied） |
| 内置 Zygisk | 面具 App → 设置 → Zygisk | **关闭**（否则 Zygisk Next 报 `Please disable built-in zygisk of magisk`） |

命令行等价操作：
```bash
# 查设置
adb shell "su -c \"magisk --sqlite 'SELECT * FROM settings'\""
# 若之前有 DENY 记录：面具 App → 超级用户 → 点 [SharedUID] Shell → 撤销
```

### C3 Zygisk Next / LSPosed 模块启用
```bash
# 确认 Zygisk Next 已加载全部模块（决定性证据）
adb shell "su -c 'grep -a zygisk /data/adb/lspd/log/verbose_*.log | tail -20'"
# 期望：loaded 64bit zygisk module zygisk_lsposed / fluttertap / zygisk-assistant / hma_oss_zygisk
adb shell "su -c 'cat /data/adb/zygisksu/modules_info'"
```

**LSPosed 模块启用（无需点 GUI，设备自带 sqlite3）**：
```bash
DB=/data/adb/lspd/config/modules_config.db
adb shell "su -c \"sqlite3 -header $DB 'SELECT * FROM modules; SELECT * FROM modules_state; SELECT * FROM scope'\""

# 启用 + 绑定作用域到目标 App
adb shell "su -c \"sqlite3 $DB \\\"
  INSERT OR REPLACE INTO modules_state(module_pkg_name,user_id,enabled,scope_request_blocked)
    VALUES('hk.kirk.trustme',0,1,0);
  INSERT OR REPLACE INTO scope(module_pkg_name,app_pkg_name,user_id)
    VALUES('hk.kirk.trustme','com.tudou.tool',0);
  INSERT OR REPLACE INTO modules_state(module_pkg_name,user_id,enabled,scope_request_blocked)
    VALUES('li.power.app.sslunpinner',0,1,0);
  INSERT OR REPLACE INTO scope(module_pkg_name,app_pkg_name,user_id)
    VALUES('li.power.app.sslunpinner','com.tudou.tool',0);
\\\"\""
# 改完需重启（或重启 zygote）让 LSPosed 重新读取
```
库结构：`modules` / `modules_state` / `scope` / `module_configs` / `app_configs` / `lspd_configs`。

### C4 FlutterTap 配置（**装了不配等于没装**）
1. 打开 `com.eduardolopes.fluttertap`
2. 勾选目标应用 `com.tudou.tool`
3. 填 PC 侧代理 `IP:端口`（如 `192.168.x.x:8080`）
4. 安装日志已提示：`No target apps are selected by default.` —— 必须手动选

### C5 frida-server 启动与转发（每次重启模拟器都要重做）
```bash
adb shell "su -c 'pkill -f frida-server; nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'"
adb forward tcp:27042 tcp:27042
adb shell "su -c 'ps -A -o PID,NAME | grep frida-server'"
# PC 侧验证（用系统 Python，已装 frida 17.8.2）
python -c "import frida;d=frida.get_device_manager().add_remote_device('127.0.0.1:27042');print(len(d.enumerate_processes()),'procs')"
```
也可直接跑 `scripts/re-env/start_re_env.bat`。

### C6 代理配置
```bash
# git / curl 走代理
export http_proxy=http://127.0.0.1:7897 https_proxy=http://127.0.0.1:7897
git -c http.proxy=http://127.0.0.1:7897 -c https.proxy=http://127.0.0.1:7897 push origin main
```

---

## 七、命令速查（全部实测）

```bash
# ── 模拟器生命周期 ──
cd /c/leidian/LDPlayer14
./ldconsole.exe list2 / runninglist
./ldconsole.exe launch --index 0
./ldconsole.exe reboot --index 0     # 原地重启（推荐，保留窗口）
./ldconsole.exe quit   --index 0

# ── adb（Git Bash 下务必带 MSYS_NO_PATHCONV=1）──
export MSYS_NO_PATHCONV=1
./adb.exe devices
./adb.exe push "<宿主机绝对路径>" /data/local/tmp/<文件名>   # 见第八节坑 1
./adb.exe install -r "<宿主机绝对路径>.apk"                  # 见第八节坑 2
./adb.exe shell "su -c '...'"

# ── Magisk ──
adb shell "su -c 'magisk -v'"
adb shell "su -c 'magisk --install-module /data/local/tmp/x.zip'"
adb shell "su -c \"magisk --sqlite 'SELECT * FROM settings'\""
adb shell "su -c 'ls /data/adb/modules/'"

# ── 诊断 ──
adb shell "su -c 'cat /data/tombstones/tombstone_01 | head -30'"
adb shell "su -c 'cat /data/adb/zygisksu/modules_info'"
adb shell "su -c 'grep -a zygisk /data/adb/lspd/log/verbose_*.log | tail'"
```

---

## 八、已知坑清单（**务必遵守，都是实测踩出来的**）

| # | 坑 | 症状 | 处理 |
|---|---|---|---|
| 1 | **adb push 到「目录形式」目标不落盘** | 报 `1 file pushed` 但设备上找不到文件 | 逐文件写**完整目标文件名**：`adb push x.zip /data/local/tmp/x.zip` |
| 2 | `adb install` 参数语义 | 传设备路径报 `failed to stat` | 必须传**宿主机路径** |
| 3 | **`adb kill-server` 后 guest adbd 不回连** | 永久 `offline`，shell 全挂 | `ldconsole reboot --index 0` 才能恢复；平时别随手 kill-server |
| 4 | Git Bash 路径转换 | `/sdcard/x` 被转成 `C:/.../sdcard/x` | `export MSYS_NO_PATHCONV=1` |
| 5 | `su -c` 引号被吃 | `su: invalid option -- o` | 整体再包一层：`adb shell "su -c '...'"` |
| 6 | VM 偶发卡顿致 adb offline | `VBox.log`: `Giving up catch-up attempt ... 60 002 396 959 ns lag` | 降低并发操作密度，稍等自愈 |
| 7 | 手改 `leidian.vbox` 无效 | 每次启动被 `dnplycore.dll` 重写 | 改 `vms/config/leidian0.config` |
| 8 | **frida attach 运行中的目标必超时** | `TimedOutError: unexpectedly timed out while waiting for stop` | **一律用 spawn**，不用 attach |
| 9 | frida 17 无内置 Java bridge | `Java is not defined` | 项目 hook 脚本全纯 native，不受影响；确需 Java 层用 frida-tools CLI |
| 10 | 目标进程名显示为 `囧次元`（中文） | 按包名 grep 搜不到 | 用 `enumerate_applications()` 按 `com.tudou.tool` 定位 |
| 11 | frida-server 不自启 | 重启模拟器后连接失败 | 重跑 C5 节命令 |
| 12 | 同机跑雷电 9 + 14 抢端口 | adb 串到错误实例 | 停掉多余实例 |
| 13 | libcore 内字符串全混淆 | `qPwC`/`kFGT`/前缀 15B 均搜不到 | 别指望字符串定位，走反汇编 |
| 14 | 地址体系易混 | blutter addr ≠ dump offset | `blutter_addr = 0x4b6b40 + dump_offset`；运行时 = `base + blutter_addr` |

---

## 九、证据与复现要求

1. **每个结论必须有可复现证据**：命令 + 原始输出（或产物文件路径）。
2. 区分「观测」「假设」「已验证结论」三层，**禁止把假设写成结论**。
3. 新增证据追加到 `research/reports/VERIFICATION.txt`，沿用 `[F*]` 编号。
4. 关键脚本放 `research/`（hook/探针）或 `research/deliverables/decrypt_v5/`（解密器），**不得留 stub**。
5. 文档同步两处：`docs/`（docsify 站）与 `research/reports/API_ANALYSIS.md`。

---

## 十、交付物

| # | 交付物 | 路径 |
|---|---|---|
| 1 | 能力/缺口评估表 | `research/reports/ASSESSMENT_V5.md` |
| 2 | 接口全量矩阵 | `research/reports/API_MATRIX_V5.md` |
| 3 | 三通道解密脚本（各可独立运行） | `research/deliverables/decrypt_v5/` |
| 4 | 端到端跑通脚本（列表 + 播放地址） | `research/deliverables/decrypt_v5/run_list.py`、`run_play.py` |
| 5 | 抓包文件与端点覆盖清单 | `research/ggcap_v5.pcap` |
| 6 | 审计链追加 | `research/reports/VERIFICATION.txt` |
| 7 | 环境与模块文档更新 | `docs/setup/*.md` |

---

## 十一、环境选型参考（勿重复论证）

| 需求 | 结论 |
|---|---|
| 抓包 | **PCAPdroid**（免 root，VPN 本地抓包导出 pcap）最契合——本 API 是**明文 HTTP**，无需 MITM CA |
| 为什么不用 Charles/HttpCanary/mitmproxy | P0.P1 是**应用层加密**，与 TLS 无关；Flutter 自带 BoringSSL 不信系统证书，常规代理抓 HTTPS 无效 |
| 解密主力 | **frida hook libcore**（真机已打通七轮，纯 native）；模拟器走 spawn |
| Root 隐藏 | Zygisk-Assistant > Shamiko（Shamiko 要求 Magisk >27005，本机 27002 装不上） |
| LSPosed/JustTrustMe 类 | 对 **Flutter native 加密无增益**，仅在需要 Java 层 hook 时使用 |
| 模拟器定位 | x86_64 + houdini 可抓包、frida spawn 可用；**但 App 本身会崩（第四节）** |

---

## 十二、风格与纪律（用户既定规则）

- 每一步**以命令输出为准**，不推测；未执行写「未执行」并给出下一条可复现命令。
- 遇到失败**立即报告**，不静默结束、不静默重试。
- 交付文件完整无 stub；**不伪造** hash / 响应 / 偏移 / patch 结果。
- 变更范围限定在本次任务模块内，保留无关用户文件。
- 长任务保持简短进度播报：`当前进度：N%｜已完成：…｜下一步：…`。

---

### 起步动作（第一句话就从这里开始，不要重复询问环境状态）

1. 执行 **P0 环境健康检查**（第五节）；
2. 执行 **3.1 资产盘点**，产出 3.5 能力/缺口矩阵到 `research/reports/ASSESSMENT_V5.md`；
3. 执行 **第四节 4.2 的 3 次冷启动复现实验**，确定主攻路线（R1/R2/R3）并说明理由；
4. 再进入 P1 抓包。
