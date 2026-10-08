# 囧次元逆向 · V13 交接提示词（新对话直接粘贴）

## 任务总目标
对 com.tudou.tool（囧次元）HTTP 协议做最后闭环，并按优先级推进：
1. **【最高】攻下响应体离线解密**（E 的逆函数）—— 目前唯一硬缺口；
2. 用 App 侧通路把「视频列表 → 播放地址 → 播放测试」跑完并出结论；
3. 把 apipost 接口按 V12/V13 协议更新到可测状态。

## 已完成（勿重复验证）

### 请求方向：完全打通 ✅
```
请求体 = CUSTOM_B64(P0) . CUSTOM_B64(P1)
  P0 = RSA-2048-PKCS1v1.5(server_pub, K16)      K16 = 客户端 16 字节随机
  P1 = CBC-E( key = K16 , iv = reverse(K16) , PKCS7(params) )
  E  = libcore 自研分组密码（与 authentication 头同一算法，**不是 AES**）
  密文长度 = ceil((len(params)+1)/16)*16
```
- 服务端判据（HTTP 恒 200，看 body）：`{"code":800131,"message":"通讯失败"}` = P1 解不开；
  返回 `<P0_b64>.<P1_b64>` 形态 = 请求被接受 ✅
- 6/6 POST 端点实测被接受：device-base / record / config-video / config-channel / users-task / messagebox-dynamic

### authentication 头：完全破解 ✅
`authentication = CUSTOM_B64( E( CUSTOM_B64( S ) ) )`，
`S = "3.0.0.8-{ts}-Android-1.5.8.0-{device_fp}-default"`，
auth 专用 key `ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv` / iv `WonrnVkxeIxDcFbv`。
只与 ts 强绑定（不绑 path/query），时效约 2 分钟。

### E 加密预言机（可复用，任意 key/iv + 任意明文）✅
复用 Unicorn 的 auth 编码管线 `0x304eb0`：
`fix_long_string(0x688130,key)` / `(0x688148,iv)` 注密钥，A1 阶段 hook 覆写明文缓冲。
回归自检：pt=104B 时输出首块 == `CT0 23754ae9d0cbe749f5441e769b45143e`。
**约束：明文长度必须是 4 的倍数**（b64 长度约束，forge 侧用空格补齐）。

## 未完成（本轮重点，含已排除项）

### 响应 P1 离线解密 —— 缺 E 的逆
已排除（**禁止重试**）：
- **不是 AES**：对伪造响应做全候选（K16/K16×2/md5/sha16/K16resp/authK × rev/K16/zero/authIV/revresp × CBC/ECB）→ 0 命中
- **E 无同帧镜像函数**：全 .text 扫描，`sub sp,sp,#0x180` 只有 E(0x2d6f78) 一处
- **E 管线无模式位**：x3/x4 传 0/1/2/0x10/0x100，输出逐字节不变
- **E 非对合**：`E(E(x)) != x`
- **emu 的 api_decrypt 走不到业务层**：envelope 能解出 `{"action":"api_decrypt","payload":{...}}`，
  但 E 的序言在加密/解密两次 TRACE_CIPHER 运行中都从未出现；
  `--enc quoted`(默认) 才能过 app 的 json::parse，`--enc plain` 报 `parse_error.101 invalid literal 'u'`
- 函数级差分（`TRACE_CIPHER=1`，只记 `sub sp,sp,#imm` 序言）找到**仅解密执行**的
  `0x2ce598` / `0x2e6364`，但入参 x0 指向 `417/411` 长度的字符串结构 → 是 JSON/payload 辅助函数

**当前最强假设**：响应 P1 的解密实现在 **Dart 侧(libapp.so)**，不在 libcore ——
这能解释 libcore 的 E 只被 `0x303df0`（业务 P1 加密）与 `0x3050f8`（auth 头）调用、且 emu(libcore-only) 永远到不了解密。
→ 建议下一步查 `research/artifacts/blutter_out/`（blutter 反编译的 Dart 侧）。

### 视频播放：App 内系统性失败 ❌（本轮新结论）
- `/app/video/list` 明文内存提取正常：`{"total":206,"items":[...]}`
- 播放请求链路已发出且被接受：`/app/video/record` → `/app/video/play-connect` → `/app/video/play?id=..&play=mp4&part=第1集`（HTTP 200，7250B 加密体）
- **App 内点播放恒报「播放错误，可点击播放页下方反馈按钮上传错误报告！」**
  - 换视频（我家弟弟们给你添麻烦了 / 桃源暗鬼）→ 同样失败
  - 「换源」里只有一条线路（线路3）→ 同样失败
  - **撤掉抓包重定向（iptables -F + adb reverse --remove-all）后仍失败** → 不是我们的代理导致
- App **从未向解析接口发请求**（`yh.jx.xajtl.com` = 116.196.151.128，已单独重定向到通用代理，无任何请求）
- 播放响应明文不在内存 → 疑似 App 侧拿不到/解不开 play 响应的 `source`
- **App 的播放解析是 Lua 脚本**（内存里已 dump 到 `research/captures/live/lua_play.txt`）：
  ```lua
  local timestamp = utils.timestamp()
  local modified_source = source .. "&t=" .. timestamp
  for i = 1, #parsers do
    local get_header = { ["x-time"]=timestamp, ["x-form"]=config.platform,
                         ["x-sign1"]=sign(config.version,timestamp),
                         ["x-sign2"]=sign(source,timestamp) }
    local jsonData = safe_http_get(parsers[i] .. modified_source, { header = get_header })
    local obj = parse_response(jsonData)
    if obj and obj.code == 200 then
      for _, item in ipairs(obj.data.playAddr) do
        -- 直链 = item.m3u8FileDomain .. item.addr
  ```
  parsers 列表（内存里只有一条）：`["http://yh.jx.xajtl.com/vo1v03.php?url="]`

## 环境与工具（照抄，勿重新摸索）

### 设备/运行时
- adb：`C:/leidian/LDPlayer14/adb.exe`；Git Bash 需 `export PATH="/c/leidian/LDPlayer14:$PATH"`
- **所有 adb/HTTP 命令必须前缀 `MSYS_NO_PATHCONV=1`**（否则 `/app/...` 被改写成 `C:/...`）
- 设备 `emulator-5554`；`adb kill-server` 后注册会丢 → `adb connect 127.0.0.1:5555` 补回
- App 进程名 `com.tudou.tool`，launcher = `com.tudou.tool/app.video.guoguo.SplashActivity`，屏幕 540x960
- frida-server 在 `/data/local/tmp/frida-server`（root）；frida 客户端只在项目 `.venv`（17.8.2）
- **frida 在 App 启动早期 attach 会触发 DartWorker SIGSEGV(code 128)** → 必须等 MainActivity 稳定再挂
- **禁止 frida spawn**

### 本地服务（已在跑，127.0.0.1:8791）
`research/deliverables/authgen_server.py`
```
GET /auth                          -> {ts, authentication}
GET /forge?params=&path=           -> {ts, authentication, body(P0.P1), k16}
GET /unwrap?body=P0.P1             -> {k16resp, p1_hex}      解响应 P0（离线可解）
GET /relay?path=&params=&method=   -> 伪造+直发真实服务端+原样返回（apipost 一键测试）
```
**坑**：`e_enc` 会覆写共享 Unicorn 会话的 key 槽 → `make_auth` 前必须
`fix_long_string(0x688130, AES_KEY)` / `(0x688148, AES_IV)` 复位，否则 auth 失效（服务端 30000）。

### 抓包链路
```
adb reverse tcp:27990 tcp:27990
adb shell su -c "iptables -t nat -A OUTPUT -p tcp -d 43.145.33.254 --dport 27990 -j REDIRECT --to-ports 27990"
./.venv/Scripts/python.exe research/captures/rsa_scan/mitm_proxy_live.py      # 按固定上游转发
./.venv/Scripts/python.exe research/captures/rsa_scan/mitm_proxy_generic.py   # 按 Host 转发(27991, 用于解析接口等第三方域)
```
坑（都已修，勿重踩）：
- 宿主机**旧代理残留占 27990**（Windows SO_REUSEADDR 允许双绑）→ 新代理收不到连接、抓包恒空；
  先 `netstat -ano | grep :27990` 找 LISTENING 清掉旧的
- 响应 chunked 未解码 → body 混入 `2805\r\n`；代理已内置 dechunk
- 宿主机 `HTTP_PROXY/HTTPS_PROXY=127.0.0.1:4816`（沙箱出口）劫持 urllib → `gaierror`；
  发 HTTP 一律用 `http.client` 直连

### App 内存取明文（目前唯一能读响应明文的途径）
```
./.venv/Scripts/python.exe research/deliverables/decrypt_v5/mem_plaintext.py --marker '{"total":' --json
```
必须**在 App 刚完成请求时**扫（空闲后字符串被 GC）。

## 关键文件
- 伪造/预言机：`research/captures/rsa_scan/{e_oracle,forge_v6,forge_v7}.py`
- 内存猎取：`research/captures/rsa_scan/{live_hunt,live_hunt_loop}.py`
- 抓包：`research/captures/rsa_scan/{mitm_proxy_live,mitm_proxy_generic}.py`
- 本地服务：`research/deliverables/authgen_server.py`
- emu：`research/toolchain/emu_unwind.py`（`TRACE_CIPHER=1` 开启函数级执行追踪）
- 密码探针：`research/captures/rsa_scan/{cipher_probe,dec_mode_probe}.py`
- Lua 播放脚本：`research/captures/live/lua_play.txt`
- 文档：`docs/crypto/http-body.md`（V12 收官章节）、`research/reports/VERIFICATION.txt`（[H1]-[H9]）

## 建议执行顺序（新对话）
1. 起环境：设备在线 → frida-server → 本地 8791 服务（`--warmup`）→ 需要抓包再加 reverse+iptables
2. **攻 E⁻¹**：查 `research/artifacts/blutter_out/` 的 Dart 侧实现，找 `api_decrypt` 的解密路径；
   若确认在 Dart，则用 blutter 输出 + Unicorn 复现 D(key,iv,ct)
3. 拿到 D 后：在 `authgen_server.py` 加 `GET /decrypt?body=&k16=` → 真正离线解密响应
4. 用 `/relay` 跑 `/app/video/play`，解出 `source` → 按 Lua 逻辑请求解析接口 → 取直链 → 验证流可播
5. 顺带查清 App 内「播放错误」的根因（是 source 拿不到，还是环境/登录限制）

## 纪律
- 执行台账：不重复已成功的读取/命令；**负结果不再重试**（见上面"已排除"清单）
- 命令输出 >512KB 落盘，只回传摘要+路径
- 进度播报：`当前进度：N%｜已完成：…｜下一步：…`
- 未执行的步骤明确写"未执行"，禁止虚构结果
- `api.zxcbug.com` 是本工具的中转资产，严禁任何探测/攻击
