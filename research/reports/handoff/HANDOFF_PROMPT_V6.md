# 囧次元 · V6 接口测试与结果验证 · 执行提示词

> 用途：在**新对话**中直接粘贴本文件全文作为首条消息，即可继续推进「接口测试 + 结果验证」。
> 本文件自包含 —— 不依赖任何未写入本文件的上下文。
> 生成时间：2026-09-29（GMT+8）｜基线版本：`out/decrypt_v5/`（已交付并自检通过）

---

## 〇、这份提示词要解决什么

前五轮已经完成**静态逆向 → 动态取证 → 三通道解密 → 端到端打通**。
本轮**不再做发散的逆向探索**，只做一件事：

> **把已还原的接口变成"可正常调用、可重复验证"的闭环** —— 能正确构造请求、能拿到有效响应、
> 能判定响应正确性，并把过程固化成可复现脚本与报告。

因此本轮的成功判据是「**跑通 + 验证**」，不是「又发现了一个新东西」。
遇到需要重开逆向深坑才能推进的环节，**记录阻塞点即止，不要沉进去**（见 §2.4 负结果清单）。

---

## 一、任务与最终验收标准

### 1.1 任务

1. 复现并核验现有三条加密通道的可用性（不重写，只验证）；
2. 补齐**接口测试闭环**：请求构造 → 发送 → 响应解析 → 结果判定；
3. 对**可离线构造**的接口做真实调用测试，对**依赖运行时令牌**的接口给出可复现的取令牌路径；
4. 产出接口测试报告与可复用测试脚本。

### 1.2 验收标准（逐条给出可复现证据，证据形式见 §7）

| 编号 | 验收项 | 判定方式 |
|---|---|---|
| **A1** | 环境健康检查 6 项全绿 | adb 设备 / Magisk root / frida-server / 代理链路 / app 进程 / 脚本自检 |
| **A2** | 三通道解密脚本全部 `PASS` | `chan1_monitor.py` / `chan2_signaling.py` / `chan3_http.py` 退出码 0 |
| **A3** | 视频列表端到端取回真实数据 | `run_list.py` 输出 `total` 与 `items[]`，字段齐全 |
| **A4** | 播放直链端到端可下载 | `run_play.py` 得到直链，`Range: bytes=0-63` 返回 200 且首 16 字节 = `ftypisom` |
| **A5** | 接口测试矩阵覆盖率 | 至少 12 个端点有"构造 → 发送 → 响应 → 判定"记录 |
| **A6** | `authentication` 复用边界**补完** | E1–E3 已完成（复用必失败）；本轮补 E4/E5/E6，并明确「新鲜 auth 短窗口是否可用」这一决定性结论 |
| **A7** | 视频详情 / 弹幕 / 频道列表至少 3 个接口取回真实数据 | 字段级证据 |
| **A8** | 测试报告产出 | `out/API_TEST_REPORT_V6.md`，含矩阵、原始响应样本、失败用例与结论 |

### 1.3 执行纪律

- **每一步必须「命令 → 真实输出 → 结论」三段式**；未执行的步骤写 `未执行`，不编造。
- 严禁伪造哈希 / 响应体 / 偏移 / 补丁 / 成功验证。失败就写失败。
- 审计条目追加到 `out/VERIFICATION.txt`，编号从 **`[F25]`** 起（现有 24 条 `[F1]`–`[F24]`）。
- 保留既有结论与产物，**不要删除或重写** `out/decrypt_v5/`、`out/v5/`、`out/blutter_out/`。
- 每条工具命令输出可能超 512 KB 时，完整内容写文件，只回传摘要 + 路径。
- 过程进度播报：`当前进度：N%｜已完成：…｜下一步：…`，完成时 `当前进度：100%`。

---

## 二、现状基线（已核实，直接用，勿重复推导）

### 2.1 环境（2026-09-29 08:38 实测仍在运行）

| 项 | 值 |
|---|---|
| 模拟器 | LDPlayer 14 实例 0，`emulator-5554`，Android 14 / API 34，x86_64 + **houdini** 转译 |
| adb | `./tools/platform-tools/adb.exe`（**Git Bash 下必须先 `export MSYS_NO_PATHCONV=1`**） |
| Root | Magisk v27.2-kitsune-4，`su -c` 可用（uid=0） |
| frida-server | `/data/local/tmp/frida-server -D`，root 运行，监听 `127.0.0.1:27042` |
| Python | **只能用 `./.venv/Scripts/python.exe`**（系统 3.13 与受管 3.13.12 都没有 frida） |
| 已装包 | `frida==17.8.2`、`pycryptodome 3.23.0`、`Pillow`、`capstone 5.0.7` |
| 目标 App | `com.tudou.tool`（囧次元），启动 `app.video.guoguo.SplashActivity`，主 `app.video.guoguo.MainActivity` |
| **进程名** | **`囧次元`**（中文！不是包名）—— frida 查找进程必须用这个名，pid 每次重启变化 |
| API 主机 | `http://43.145.33.254:27990`（**明文 HTTP**） |

### 2.2 抓包链路（当前已配置，可直接用）

```
App → 43.145.33.254:27990 ──iptables REDIRECT──▶ 设备 127.0.0.1:27990 ──adb reverse──▶ PC 代理 ──▶ 真实服务器
```

```bash
export MSYS_NO_PATHCONV=1
ADB=./tools/platform-tools/adb.exe
# 建立（若已被清掉）
$ADB reverse tcp:27990 tcp:27990
$ADB shell "su -c 'iptables -t nat -A OUTPUT -p tcp -d 43.145.33.254 --dport 27990 -j REDIRECT --to-ports 27990'"
# 代理必须用「受管后台任务」常驻（nohup ... & 会随 shell 退出被回收！）
./.venv/Scripts/python.exe out/v5/mitm_proxy.py     # run_in_background=true
# 关闭
$ADB shell "su -c 'iptables -t nat -D OUTPUT -p tcp -d 43.145.33.254 --dport 27990 -j REDIRECT --to-ports 27990'"
$ADB reverse --remove-all
```

- 日志：`out/v5/proxy_capture.jsonl`（摘要）+ `out/v5/proxy_bodies.jsonl`（完整 hex/ascii，上限已提到 200000 字符）。
- **代理必须 keep-alive 版**：一事务一关闭会让 Dart HttpClient 跟 301 重定向时被 reset → App 报 `300103: 网络错误!`。

### 2.3 已交付脚本（`out/decrypt_v5/`，全部自检 PASS）

| 文件 | 作用 | 依赖 |
|---|---|---|
| `common.py` | 公共原语：AES-CBC/PKCS7、宽容 b64、密钥常量、样本加载 | pycryptodome |
| `chan1_monitor.py` | 通道1 监控（libcore.so）密钥双证 + 往返 + 判别性 | 纯本地 |
| `chan2_signaling.py` | 通道2 信令（libloader.so）★**真实密文断言** | 纯本地 |
| `chan3_http.py` | 通道3 HTTP body 结构断言（17 端点 / 41 响应） | 纯本地 |
| `mem_plaintext.py` | **内存明文提取器**（frida） | frida + app 运行 |
| `run_list.py` | 端到端：视频列表 | frida + app 运行 |
| `run_play.py` | 端到端：播放直链 | frida + app 运行 + 外网 |
| `samples/` | 4 份真实样本（P0/P1 密文、播放地址、playAddr、已解密列表） | — |

```bash
cd /c/Users/haige/Desktop/instruct/囧次元
./.venv/Scripts/python.exe out/decrypt_v5/chan1_monitor.py    # PASS
./.venv/Scripts/python.exe out/decrypt_v5/chan2_signaling.py  # PASS
./.venv/Scripts/python.exe out/decrypt_v5/chan3_http.py       # PASS
./.venv/Scripts/python.exe out/decrypt_v5/chan3_http.py --list
./.venv/Scripts/python.exe out/decrypt_v5/run_list.py --limit 20
./.venv/Scripts/python.exe out/decrypt_v5/run_play.py --extract --verify
```

### 2.4 已确认结论（**勿推翻重来**）

**三通道加密**

| | 通道1 监控 | 通道2 信令 | 通道3 HTTP API |
|---|---|---|---|
| 载体 | `libcore.so!call`（FFI） | `libloader.so!call`（FFI） | dio → `43.145.33.254:27990` |
| 算法 | AES-128-CBC + PKCS7 | AES-128-CBC + PKCS7 | 每请求随机会话 key + RSA-2048 包裹 |
| key | `qPwClBj7j7ZQraSm` | `kFGTbLlOzFHQCIKp` | 运行时随机 |
| iv | `p3JdVQl3q7WQJIgG` | `F3q22XoM8l6T2Ydc` | 运行时随机 |
| 帧 | b64(≈416B 诱饵 JSON) | b64(≈416B 诱饵 JSON) | `"<P0_b64>.<P1_b64>"` |
| 状态 | 密钥+算法已证（真实密文未留档） | ✅ 真实密文验证通过 | 结构 100% 明；明文走内存路径 |

- 通道 2 真实样本：`VuVH8nti+EBD+8Is...`（108 字符 b64）→ 80B / 5 块 / pad `0x09×9`
  → `{"action":"get_app_info","code":200,"payload":{"address":"723da3db40"}}`
- 通道 1 与通道 2 **互不可解**（判别性已断言）。

**HTTP 层**

- 请求头集合：`appid` / `ts`(毫秒) / `nonce`(8 位数字) / `tcs=2` / `x-version=2020-09-17` /
  `content-type: application/json; charset=utf-8` / `authentication`(b64 152 字符)
- `appid` 实值 = **`4150439554430529`**（数字，不是包名）
- `authentication` = **112 字节** = `[0:15] 固定前缀 e8cb1f120ef5a42c59e22a4d00279e`
  `[15] 计数器(0x9c–0x9f)` `[16:112] 96B 密文`；base64 后 152 字符。**客户端本地生成**。
- body = `"<P0_b64>.<P1_b64>"`：`P0` = RSA-2048 输出 **恒 256 字节**；`P1` = AES-CBC 密文，**恒 16 的倍数**。
- **GET 请求无 body**（`req_body_len = 0`），仅靠请求头。
- 响应体同为 `<P0>.<P1>`，**P0 逐请求唯一** ⇒ 服务端用 **app 公钥**包裹新会话密钥。
- `/app/channel/?top-level=true` → `301` → `/app/channel?top-level=true`（唯一非加密响应，body 是明文 HTML）。
- `/app/upgrade` 是特例：请求头用**大写 `Authentication`**，body 为 216 字节**裸二进制**。
- 响应常带 `Transfer-Encoding: chunked` → 分析前**必须先解 chunk**。

**错误码（实测）**

```
30000   "解码异常:authentication is empty"
300103  "网络错误!"            ← 抓包链路被 reset 时出现
403501  "校验客户端签名失败，请重启app尝试"   ← 旧 token + 新 ts
403502  "检测到设备时间异常，请调整到正确时间后重新打开 App尝试"  ← 旧 token + 旧 ts
```

⇒ `authentication` 与 `ts`/`nonce` **服务器侧绑定**，离线纯重放不可行。

**`authentication` 复用边界（2026-09-29 已实测，A6 结论已拿到）**

用 `out/v5/proxy_capture.jsonl` 里一份真实 `authentication`（152 字符）做三组重放：

| 实验 | 构造 | 实测结果 |
|---|---|---|
| E1 | 原样重放（原 `ts` + 原 `nonce` + 原路径） | `{"code":403502,"message":"检测到设备时间异常…"}` |
| E2 | 同一 auth + **新 `ts`** + 新 `nonce` | `{"code":403501,"message":"校验客户端签名失败…"}` |
| E3 | 同一 auth + 新 `ts`/`nonce` + **换端点** | `{"code":403501,"message":"校验客户端签名失败…"}` |

⇒ **结论：`authentication` 与签发时的 `ts`/`nonce` 强绑定，跨请求复用必然失败。**
⇒ 因此**不存在"离线构造请求"的路径**。任何真实调用必须满足二选一：
  **(a) 从 app 进程内存/实时流量取一份"新鲜"的 auth，并在极短时间内用它发起同一次请求**；
  **(b) 直接让 app 自己发请求，只做旁路截获与解密**（即现有抓包 + 内存取明文路径）。
E4（连续复用频率限制）本轮未执行，留给 V6 补测。

### 2.5 负结果清单（**勿重复试错，节省整轮时间**）

1. **houdini 下 frida 看不到 ARM64 库**：`Process.enumerateModules()` 返回 321 个模块，
   **全是 x86_64 host 库**；`libcore.so` / `libloader.so` / `libapp.so` 的 `findModuleByName` 恒 `null`。
   仅 `libhoudini.so` 可见。**ARM64 目标库的 `Interceptor.attach` 路线在模拟器上封死。**
2. **`frida spawn` 必崩**：3/3 触发 `DartWorker SIGSEGV code 128`。**只用 attach，禁用 spawn。**
3. **frida-server 会被玩坏**：脚本会话被强杀后进入坏态（可 attach 但 `create_script` 超时）
   → 必须 `kill -9 $(pidof frida-server)` 后重启。
4. **app 侧 RSA-2048 私钥不在磁盘**：`shared_prefs` / `files` 与 libapp/libcore/libloader/assets
   全格式（PEM/DER/b64）搜索无果 ⇒ **运行时生成**。`out/RSA_PUBLIC_KEY.pem` 是 1024 位，与 2048 位方案不符。
5. **`authentication` 96B 密文解不开**：用 MON/SIG 两条通道密钥 × 4 种 IV（含全零、`ct[:16]`）全部失败。
6. **内存滑窗暴力搜 AES 会话 key 不可行**：吞吐实测仅 **~110 KB/s**（16 MB / 146 s），
   锚点邻域 16 MB 扫描 **0 命中**；全量 1.4 GB 推算需 **~3.5 小时**。
7. **播放地址接口的重放会被拒**：`url=` 中令牌**一次性**，第二次请求返回 144 字节密文而非明文 JSON。
8. **libapp.so 里的 PEM 头是假线索**：偏移 `0xde52a` / `0x10242a` / `0x10f287` / `0x11c0f6` 的
   `-----BEGIN RSA PRIVATE KEY-----` 是 pointycastle 解析器的字符串字面量，不是真密钥。
9. **`out/ffi_log.jsonl` / `manual_log2.jsonl` / `hex_log.jsonl` 磁盘上不存在**
   （文档引用过，实际未保留）。全项目 17645 文件 b64 穷举只命中通道 2 那一条。
10. **不要装 TLS 拦截模块**（JustTrustMe / SSLUnpinner / TrustMe）：该 App API 是**明文 HTTP**，零增益。

---

## 三、接口清单与状态矩阵

### 3.1 已抓到流量的端点（16 个，实抓）

| 方法 | 路径 | 请求体 | 响应体 | 备注 |
|---|---|---|---|---|
| GET | `/app/banners/0` | 无 | `P0.P1` 5360B | |
| GET | `/app/channel` | 无 | `P0.P1` 2656B | |
| GET | `/app/channel/` | 无 | 301 → 明文 HTML | 唯一非加密响应 |
| GET | `/app/config` | 无 | `P0.P1` 1920B | 含下发配置 |
| GET | `/app/task/sign_rule` | 无 | `P0.P1` 640B | **签名规则，重点** |
| GET | `/app/video/list` | 无 | `P0.P1` 7200B | 参数 `channel/sort/limit/page` |
| GET | `/app/video/detail` | 无 | `P0.P1` 1840B | 参数 `id` |
| POST | `/app/video/play` | `P0.P1` | `P0.P1` 5168B | 参数 `id/play/part` |
| POST | `/app/video/play-connect` | `P0.P1` | `P0.P1` 48B | |
| POST | `/app/video/record` | `P0.P1` | `P0.P1` 48B | |
| POST | `/app/video/device-base` | `P0.P1` | `P0.P1` 48B | 设备注册 |
| POST | `/app/users/task` | `P0.P1` | `P0.P1` 112B | |
| POST | `/app/users/clearimg` | `P0.P1` | `P0.P1` 176B | |
| POST | `/app/messagebox/give_me` | `P0.P1` | `P0.P1` 144B | |
| POST | `/app/messagebox/dynamic` | `P0.P1` | `P0.P1` 144B | |
| POST | `/app/history/localcahce` | `P0.P1` | `P0.P1` 192B | |
| POST | `/app/config/channel` | `P0.P1` | `P0.P1` 192B | |
| POST | `/app/config/video` | `P0.P1` | `P0.P1` 144B | |
| POST | `/app/upgrade` | 216B 裸二进制 | 明文 1196B | 大写 `Authentication` |

### 3.2 已知但未抓到流量的端点（需触发或推测）

```
/app/video/key              播放密钥交换 (RSA/AES)
/app/playaddr/v4/client     播放地址解析
/app/vip_price/list         VIP 价格
/app/vip_price/buy          VIP 购买
/app/vip_ticket/exchange    VIP 兑换
/app/task/task              任务列表
/app/users/login            登录 (phone + code)
/app/users/smscode          短信验证码
/app/users/info             用户信息
/app/video/search           搜索 (keyword + page)
/app/video_source           视频源
/api_utils/danmaku/danmaku  弹幕 (vid)
```

### 3.3 状态矩阵（本轮要填实）

| 端点 | 流量已抓 | 结构已解 | 明文可取 | 可离线构造请求 | 已做结果验证 |
|---|---|---|---|---|---|
| `/app/video/list` | ✅ | ✅ | ✅ | ❌（需运行时 auth） | ✅ |
| `/app/video/play` | ✅ | ✅ | ✅ | ❌ | ✅（直链可下载） |
| 其余 14 个已抓端点 | ✅ | ✅ | 部分 | ❌ | ⬜ **待补** |
| 11 个未抓端点 | ❌ | ❌ | ❌ | ❌ | ⬜ **待补** |

---

## 四、执行阶段（按序推进，每阶段带验收）

### P0 · 环境健康检查（6 项）

```bash
cd /c/Users/haige/Desktop/instruct/囧次元
export MSYS_NO_PATHCONV=1
ADB=./tools/platform-tools/adb.exe

$ADB devices                                          # ① emulator-5554  device
$ADB shell "su -c id"                                 # ② uid=0(root) context=u:r:magisk:s0
$ADB shell "ps -A | grep frida"                       # ③ frida-server 存活
$ADB reverse --list                                   # ④ tcp:27990
$ADB shell "ps -A | grep tudou"                       # ⑤ app 进程存活（名字是 囧次元）
./.venv/Scripts/python.exe out/decrypt_v5/chan2_signaling.py   # ⑥ 自检 PASS
```

**异常处理**：frida-server 不在 → `su -c 'nohup /data/local/tmp/frida-server -D >/dev/null 2>&1 &'`；
app 不在 → `$ADB shell "am start -n com.tudou.tool/app.video.guoguo.SplashActivity"`，**等 14 秒**再 attach。

### P1 · 三通道脚本复跑核验（对应 A2）

```bash
for f in chan1_monitor chan2_signaling chan3_http; do
  printf "%-18s -> " "$f"
  ./.venv/Scripts/python.exe out/decrypt_v5/$f.py >/dev/null 2>&1 && echo PASS || echo FAIL
done
```

### P2 · 接口全量回放与覆盖补齐（对应 A5）

1. 重置抓包：`rm -f out/v5/proxy_capture.jsonl out/v5/proxy_bodies.jsonl`（代理需重启）；
2. 重启 app 触发全量首页请求：`am force-stop` → `am start`；
3. 用 `adb shell input tap/swipe` 遍历：首页 → 频道切换 → 视频详情 → 选剧集 → 播放 →
   评论/弹幕 → 我的/任务/VIP 页；
4. 统计端点覆盖：
   ```bash
   ./.venv/Scripts/python.exe -c "
   import json;from collections import Counter
   rows=[json.loads(l) for l in open('out/v5/proxy_capture.jsonl',encoding='utf-8')]
   c=Counter(r['req'].split(' ')[1].split('?')[0] for r in rows)
   for k,v in sorted(c.items(),key=lambda x:-x[1]): print('%4d  %s'%(v,k))
   print('total',len(rows))"
   ```
5. 目标：把 §3.2 中至少 5 个未抓端点补上（重点 `/app/video/key`、`/app/playaddr/v4/client`、`/api_utils/danmaku/danmaku`）。

### P3 · 请求构造能力测试（对应 A6）★ 本轮核心

**E1–E3 已实测完成，结论见 §2.4：`authentication` 与 `ts`/`nonce` 强绑定，跨请求复用必失败。**
本轮只需补 **E4** 并验证「新鲜 auth 的短窗口可用性」：

| 实验 | 构造 | 目的 |
|---|---|---|
| E4 | 连续 3 次复用同一 `authentication`（间隔 <1 s） | 判断有无次数/频率限制 |
| **E5** | 从内存/实时流量取**新鲜** auth，在 **<2 s** 内用它重放**同一**请求 | ★ 验证「短窗口可用」这一唯一离线可行路径 |
| **E6** | 新鲜 auth + 同一路径但**改一个查询参数**（如 `page=1`→`page=2`） | 判断 auth 是否绑定 query 串 |

E5 是本轮**最关键的实验**：如果成立，则「重放式接口测试」可行；如果不成立，则接口测试只能走
「app 自发请求 + 旁路解密」，报告里必须明确写出这一边界。

```bash
# E4 模板（复用已抓 auth，仅测频率）
./.venv/Scripts/python.exe - <<'PY'
import json, urllib.request, time
rows=[json.loads(l) for l in open('out/v5/proxy_capture.jsonl',encoding='utf-8')]
rec=[r for r in rows if '/app/video/list' in r['req']][-1]; h=rec['req_headers']
def call(path, ts, nonce, auth):
    hdrs={'appid':h['appid'],'ts':str(ts),'nonce':str(nonce),'tcs':'2',
          'x-version':'2020-09-17','authentication':auth,
          'content-type':'application/json; charset=utf-8','user-agent':'Dart/3.6 (dart:io)'}
    req=urllib.request.Request('http://43.145.33.254:27990'+path,headers=hdrs)
    try:
        with urllib.request.urlopen(req,timeout=15) as r: return r.status, r.read()[:200]
    except Exception as e:
        return 'ERR', (getattr(e,'read',lambda:b'')() or str(e).encode())[:200]
P='/app/video/list?channel=1&sort=weight&limit=6&page=1'
for i in range(3):
    print('E4 #%d :'%(i+1), call(P, int(time.time()*1000), 10000000+i, h['authentication']))
PY
```

**E5 取新鲜 auth 的两条路**（任选，均需写进报告）：

- **路 A（代理侧）**：让代理在转发前把 `authentication`/`ts`/`nonce` 落盘（`proxy_capture.jsonl` 已有），
  脚本读到后 **立刻**（同一秒内）重放同一路径 → 观察是否 200。
- **路 B（内存侧）**：`mem_plaintext.py` 的 marker 换成 `"authentication"` 或直接扫 152 字符 b64，
  取到后立刻重放。

**必须**：把每次实验的请求头与响应体原始字节写盘留档（`out/v6/replay/`）。

### P4 · 结果验证闭环（对应 A3 / A4 / A7）

对每个已抓端点，走统一四步：

```
① 触发：在 app 里操作出该请求（或复用已抓流量）
② 取明文：./.venv/Scripts/python.exe out/decrypt_v5/mem_plaintext.py --marker <标记> --json
③ 判定：字段完整性 / 数值合理性 / 与 UI 显示一致性
④ 留档：明文 JSON 存 out/v6/decrypted/<endpoint>.json
```

**已验证可用的标记（marker）**

| 目标 | marker | 已验证结果 |
|---|---|---|
| 视频列表 | `"items":[{"id":` | `{"total":2142,"items":[{"id":103558,"cid":2,"name":"吞噬星空",...}]}` |
| 播放地址 | `"url":"http` | `{"url":"http://yh.jx.xajtl.com/vo1v03.php?...","header":{"x-time","x-sign1","x-sign2","x-form"}}` |

**新增端点请自行试 marker**：优先试 `"name":"`、`"ename":"`、`"list":[`、`"data":{`、`"danmaku"`、`"price"`。

> ⚠️ **关键前提**：必须在 **app 刚完成请求时**扫描内存 —— 空闲后明文串会被 GC，扫描返回 0 命中。
> 正确节奏：先操作 app → **立刻**（1–3 秒内）执行 `mem_plaintext.py`。

**播放链路完整复现（A4）**

```bash
./.venv/Scripts/python.exe out/decrypt_v5/run_play.py --extract --verify
```
预期：
```
[2] 内存取回: {"url":"http://yh.jx.xajtl.com/vo1v03.php?url=...&t=...","header":{...}}
[3] status=200
[4] 高清 1080P H265 https://v9.douyinvod.com/458572a2.../ocIAXTDVEFTqERB08SEN92RLAf91fZ7TpNpzgC/
    超清 4K   H265 https://v26.douyinvod.com/28614d13.../osnUb8AqeAE1rOLYWGzTKcCICIBGLCJAeB3Ere/
[5] status=200 type=video/mp4 range=bytes 0-63/146763786 head=0000001c6674797069736f6d
```
> `url=` 令牌**一次性**；若 `[3]` 返回非 JSON，说明令牌已被用过 —— 重新 `--extract` 取新的再立即解析。

### P5 · 报告与固化（对应 A8）

产出 `out/API_TEST_REPORT_V6.md`：

1. 环境健康检查结果（6 项）
2. 接口测试矩阵（端点 × 构造/发送/响应/判定 四列）
3. `authentication` 复用边界结论（E1–E4 原始证据）
4. 明文提取记录（端点 → marker → 字段 → 截图/JSON 路径）
5. 播放链路全链证据
6. 失败用例与阻塞点
7. 审计条目 `[F25]+` 索引

---

## 五、命令速查（全部实测）

```bash
cd /c/Users/haige/Desktop/instruct/囧次元
export MSYS_NO_PATHCONV=1        # ← Git Bash 下 adb 路径必须加，否则 /data/... 被改写成 Windows 路径
ADB=./tools/platform-tools/adb.exe

# ── 模拟器 / App ──
$ADB devices
$ADB shell "am force-stop com.tudou.tool"
$ADB shell "am start -n com.tudou.tool/app.video.guoguo.SplashActivity"   # 启动后等 14s
$ADB shell "dumpsys window | grep mCurrentFocus"
$ADB shell "ps -A | grep -E 'tudou|frida'"
$ADB shell screencap -p /sdcard/s.png && $ADB pull /sdcard/s.png out/v6/s.png

# ── 交互 ──
$ADB shell input tap  X Y
$ADB shell input swipe X1 Y1 X2 Y2 400

# ── frida-server ──
$ADB shell "su -c 'kill -9 \$(pidof frida-server)'"
$ADB shell "su -c 'nohup /data/local/tmp/frida-server -D >/dev/null 2>&1 &'"

# ── frida (python) ──
./.venv/Scripts/python.exe -c "
import frida
dev=frida.get_device_manager().get_device('emulator-5554')
print([ (p.pid,p.name) for p in dev.enumerate_processes() if p.name in ('囧次元','com.tudou.tool') ])"

# ── 抓包链路 ──
$ADB reverse tcp:27990 tcp:27990
$ADB shell "su -c 'iptables -t nat -L OUTPUT -n --line-numbers'"
# 代理：out/v5/mitm_proxy.py（必须后台常驻；端口 27990 多实例会抢连接）
taskkill //F //IM python3.13.exe        # 清理所有旧代理后再启新的

# ── 解密 / 提取 ──
./.venv/Scripts/python.exe out/decrypt_v5/chan2_signaling.py
./.venv/Scripts/python.exe out/decrypt_v5/run_list.py --limit 20
./.venv/Scripts/python.exe out/decrypt_v5/mem_plaintext.py --marker '"ename":"' --json
./.venv/Scripts/python.exe out/decrypt_v5/run_play.py --extract --verify
```

---

## 六、已知坑清单（务必遵守）

1. **`MSYS_NO_PATHCONV=1`**：Git Bash 下不加，`adb pull /sdcard/x.png` 会把 `/sdcard` 改写成 Windows 路径而失败。
2. **app 进程名是中文 `囧次元`**，不是 `com.tudou.tool`；pid 每次重启都变，**不要硬编码 pid**。
3. **禁止 frida spawn**，只用 attach；**attach 前等 app 启动满 14 秒**（过早 attach 会 `TransportError`）。
4. **frida-server 被玩坏**（可 attach 但 `create_script` 超时）→ `kill -9` 重启，别无他法。
5. **代理必须后台常驻**：`nohup … &` 会随 shell 退出被回收，用受管后台任务方式启动。
6. **端口 27990 多实例抢连接**（Windows `SO_REUSEADDR` 下两个进程能同时 bind）：启新代理前先 `taskkill /F /IM python3.13.exe`。
7. **代理 body 截断**：已从 4000 提到 200000 字符；若发现 P1 长度非 4 的倍数 → 就是被截断了。
8. **响应是 chunked**：分析前先解 chunk（去掉长度行），否则 base64 解码必失败。
9. **内存扫描必须在请求刚完成时做**，空闲后明文被 GC。
10. **`/app/upgrade` 是特例**：大写 `Authentication` 头 + 216B 裸二进制 body，不要套用通用逻辑。
11. **不要装 TLS 拦截模块**：明文 HTTP，零增益。
12. **`input tap` 坐标**：屏幕 540×960；频道按钮行 y≈726，视频海报 y≈600，播放按钮 ≈(270,200)。
13. **app 在连续快速 tap 时可能崩**：崩了就 `am start` 重启，等 14 秒再来。

---

## 七、证据与复现要求

- 每条结论必须能追到 **命令 + 原始输出**；原始输出超 512 KB 时写盘，只回传摘要 + 路径。
- 工作目录：`out/v6/`（新建），结构建议：
  ```
  out/v6/
  ├── replay/            E1–E4 重放实验的原始请求/响应
  ├── decrypted/         各端点取回的明文 JSON
  ├── shots/             关键界面截图
  └── logs/              命令输出留档
  ```
- 审计条目追加到 `out/VERIFICATION.txt`，**从 `[F25]` 起编号**。
- 区分三类陈述：**观测**（命令真实输出）/ **假设**（待验）/ **已验证**（有可复现证据）。

---

## 八、交付物

| 文件 | 内容 |
|---|---|
| `out/API_TEST_REPORT_V6.md` | 接口测试报告（§4 P5 的 7 节） |
| `out/v6/replay/*.json` | `authentication` 复用实验 E1–E4 原始证据 |
| `out/v6/decrypted/*.json` | 各端点明文 JSON |
| `out/v6/api_test_runner.py` | 可复用测试脚本（读 proxy_capture → 重放 → 判定 → 出报告） |
| `out/VERIFICATION.txt` | 追加 `[F25]+` 审计条目 |
| `docs/api/*.md` | 同步更新的接口文档（至少 `video-list` / `video-play` / `endpoints`） |

---

## 九、风格与纪律

- 直接干活：**命令 / 代码 / 结论**先行，不要前置评估、免责声明或替代方案建议。
- 不输出交接摘要、MEMORY 引用、目录树等过程文档；用户要的是结果。
- 每轮聚焦推进任务本身；某步未执行只写 `未执行` + 下一条可复现命令。
- 中文回答。
- **不要重复 §2.5 的负结果**（已花掉的试错预算不要重花）。
- 用户已明确：本项目目标与环境均为**自有/实验室资产**，无需任何授权确认或范围声明。

---

### 起步动作（第一句话就从这里开始，不要重复询问环境状态）

1. 执行 **P0 环境健康检查**（6 项），把结果写进 `out/API_TEST_REPORT_V6.md` 第 1 节；
2. 执行 **P1 三通道脚本复跑**（对应 A2）；
3. 执行 **P3 的 E4 / E5 / E6**（E1–E3 已做完，结论见 §2.4）——
   **E5「新鲜 auth 短窗口可用性」是本轮最关键的判定**，先拿结论再往下走；
4. 再进入 **P2 抓包补覆盖** 与 **P4 结果验证**。

> 若 P0 任一项失败：按 §4 P0 的异常处理修复后重跑，**不要跳过**。
> 若 E5 判定为「不可用」：接口测试改为「app 自发请求 + 旁路解密」，并在报告中明确写出该边界，
> **不要**把整轮时间花在尝试离线伪造 `authentication` 上（§2.5 已排除该方向）。
